package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
	"github.com/Ollie33-a/v3c5c4n/internal/utils"
)

// SubnetScanner performs subnet-wide scanning
type SubnetScanner struct {
	config    *models.ScanConfig
	logger    *utils.Logger
	rateLimiter *utils.RateLimiter
}

// HostDiscovery represents discovered host information
type HostDiscovery struct {
	IP              string
	Hostname        string
	IsAlive         bool
	OpenPorts       []models.PortResult
	OSDetection     OSFingerprint
	DiscoveredAt    time.Time
	ScanDuration    time.Duration
}

// SubnetResult contains all hosts in a subnet
type SubnetResult struct {
	Subnet          string
	TotalHosts      int
	HostsScanned    int
	AliveHosts      int
	DownHosts       int
	DiscoveredHosts []HostDiscovery
	ScanDuration    time.Duration
	StartTime       time.Time
	EndTime         time.Time
}

// NewSubnetScanner creates a new subnet scanner
func NewSubnetScanner(config *models.ScanConfig, logger *utils.Logger) *SubnetScanner {
	return &SubnetScanner{
		config:      config,
		logger:      logger,
		rateLimiter: utils.NewRateLimiter(config.RateLimit),
	}
}

// ScanSubnet scans an entire subnet
func (ss *SubnetScanner) ScanSubnet() (*SubnetResult, error) {
	result := &SubnetResult{
		Subnet:          ss.config.Target,
		DiscoveredHosts: make([]HostDiscovery, 0),
		StartTime:       time.Now(),
	}

	// Parse CIDR notation
	ips, err := parseSubnet(ss.config.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	result.TotalHosts = len(ips)
	ss.logger.Info("Scanning subnet %s (%d hosts)", ss.config.Target, len(ips))
	ss.logger.Info("Using %d threads with rate limit: %d packets/sec", ss.config.ThreadCount, ss.config.RateLimit)

	// Stage 1: Host Discovery (Ping Sweep)
	ss.logger.Info("\n[Stage 1/2] Performing host discovery...")
	aliveHosts := ss.discoverHosts(ips)

	ss.logger.Success("Found %d alive hosts out of %d", len(aliveHosts), len(ips))

	// Stage 2: Port Scanning on Alive Hosts
	ss.logger.Info("\n[Stage 2/2] Scanning ports on alive hosts...")
	result.AliveHosts = len(aliveHosts)
	result.DownHosts = len(ips) - len(aliveHosts)

	// Scan each alive host
	hostResults := make(chan HostDiscovery, len(aliveHosts))
	var wg sync.WaitGroup

	// Create worker pool
	numWorkers := ss.config.ThreadCount / 2
	if numWorkers < 1 {
		numWorkers = 1
	}

	hostQueue := make(chan string, len(aliveHosts))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go ss.hostWorker(hostQueue, hostResults, &wg)
	}

	// Send hosts to scan
	go func() {
		for _, ip := range aliveHosts {
			hostQueue <- ip
		}
		close(hostQueue)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(hostResults)
	}()

	for hostResult := range hostResults {
		result.HostsScanned++
		if len(hostResult.OpenPorts) > 0 {
			result.DiscoveredHosts = append(result.DiscoveredHosts, hostResult)
		}
	}

	result.EndTime = time.Now()
	result.ScanDuration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// discoverHosts performs ping sweep to find alive hosts
func (ss *SubnetScanner) discoverHosts(ips []string) []string {
	aliveHosts := make([]string, 0)
	aliveHostsMux := sync.Mutex{}

	hostQueue := make(chan string, len(ips))
	var wg sync.WaitGroup

	// Worker pool for host discovery
	numWorkers := ss.config.ThreadCount
	if numWorkers > 32 {
		numWorkers = 32 // Cap at 32 for discovery
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hostQueue {
				if ss.isHostAlive(ip) {
					aliveHostsMux.Lock()
					aliveHosts = append(aliveHosts, ip)
					aliveHostsMux.Unlock()
					ss.logger.Success("Host alive: %s", ip)
				}
			}
		}()
	}

	// Send IPs to check
	for _, ip := range ips {
		hostQueue <- ip
	}
	close(hostQueue)

	wg.Wait()
	return aliveHosts
}

// isHostAlive checks if a host is alive using multiple methods
func (ss *SubnetScanner) isHostAlive(ip string) bool {
	// Method 1: TCP port check on common ports
	commonPorts := []int{22, 80, 443, 445, 3389}
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Method 2: Fallback - try generic connection
	address := fmt.Sprintf("%s:443", ip)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// hostWorker scans individual hosts
func (ss *SubnetScanner) hostWorker(hostQueue chan string, results chan HostDiscovery, wg *sync.WaitGroup) {
	defer wg.Done()

	ns := NewNetworkScanner(ss.config, ss.logger)

	for ip := range hostQueue {
		ss.logger.Info("Scanning host %s...", ip)

		// Create temp config for this host
		tempConfig := *ss.config
		tempConfig.Target = ip

		ns.config = &tempConfig
		scanResult, err := ns.Scan()

		if err != nil {
			ss.logger.Warn("Failed to scan %s: %v", ip, err)
			continue
		}

		hostDiscovery := HostDiscovery{
			IP:           ip,
			IsAlive:      len(scanResult.OpenPorts) > 0,
			OpenPorts:    scanResult.OpenPorts,
			DiscoveredAt: time.Now(),
			ScanDuration: scanResult.ScanDuration,
		}

		// Perform OS detection
		hostDiscovery.OSDetection = DetectOS(scanResult.OpenPorts)

		// Try to get hostname
		hostDiscovery.Hostname = getHostname(ip)

		results <- hostDiscovery
	}
}

// parseSubnet parses CIDR notation and returns all IPs
func parseSubnet(subnet string) ([]string, error) {
	// Check if it's CIDR notation
	if strings.Contains(subnet, "/") {
		ip, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}

		var ips []string
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			ipStr := ip.String()
			// Skip network and broadcast addresses
			if ipStr != ipNet.IP.String() && ipStr != getBroadcast(ipNet).String() {
				ips = append(ips, ipStr)
			}
		}
		return ips, nil
	}

	// Single IP
	if net.ParseIP(subnet) != nil {
		return []string{subnet}, nil
	}

	return nil, fmt.Errorf("invalid subnet specification")
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getBroadcast gets broadcast address for a subnet
func getBroadcast(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)
	for i := 0; i < len(ipNet.Mask); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}
	return broadcast
}

// getHostname attempts to get hostname for IP
func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}