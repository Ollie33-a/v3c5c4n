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
	Vulnerabilities []PortVulnerability
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

// ScanSubnet scans an entire subnet with detailed host information
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
	ss.logger.Info("════════════════════════════════════════════════════════════════")
	ss.logger.Info("SUBNET SCAN INITIATED")
	ss.logger.Info("════════════════════════════════════════════════════════════════")
	ss.logger.Info("Scanning subnet %s (%d hosts)", ss.config.Target, len(ips))
	ss.logger.Info("Using %d threads with rate limit: %d packets/sec", ss.config.ThreadCount, ss.config.RateLimit)
	ss.logger.Info("Port range: %d-%d", ss.config.Ports[0], ss.config.Ports[len(ss.config.Ports)-1])
	ss.logger.Info("════════════════════════════════════════════════════════════════\n")

	// Stage 1: Host Discovery (Ping Sweep)
	ss.logger.Info("[Stage 1/2] Performing host discovery on %d IPs...", len(ips))
	aliveHosts := ss.discoverHosts(ips)
	ss.logger.Success("Found %d alive hosts out of %d total hosts\n", len(aliveHosts), len(ips))

	result.AliveHosts = len(aliveHosts)
	result.DownHosts = len(ips) - len(aliveHosts)

	// Stage 2: Sequential Port Scanning on Alive Hosts
	ss.logger.Info("[Stage 2/2] Detailed scanning of alive hosts (sequential)...")
	ss.logger.Info("Scanning each host individually with full port details\n")

	for i, ip := range aliveHosts {
		ss.logger.Info("════════════════════════════════════════════════════════════════")
		ss.logger.Info("[Host %d/%d] Scanning %s", i+1, len(aliveHosts), ip)
		ss.logger.Info("════════════════════════════════════════════════════════════════")

		hostDiscovery := ss.scanHost(ip)
		
		if hostDiscovery.IsAlive && len(hostDiscovery.OpenPorts) > 0 {
			result.HostsScanned++
			result.DiscoveredHosts = append(result.DiscoveredHosts, hostDiscovery)
			
			// Print detailed report for this host immediately
			ss.printHostReport(hostDiscovery, i+1, len(aliveHosts))
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
	if numWorkers > 64 {
		numWorkers = 64 // Cap at 64 for discovery
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hostQueue {
				if ss.isHostAlive(ip) {
					aliveHostsMux.Lock()
					aliveHosts = append(aliveHosts, ip)
					ss.logger.Success("Host alive: %s", ip)
					aliveHostsMux.Unlock()
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
	commonPorts := []int{22, 80, 443, 445, 3389, 139}
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Method 2: Extended port check
	extendedPorts := []int{25, 53, 67, 111, 135, 139, 161, 179, 389, 443, 512, 513, 514, 993, 995, 1433, 1521, 3306, 5432}
	for _, port := range extendedPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// scanHost performs detailed scan on a single host
func (ss *SubnetScanner) scanHost(ip string) HostDiscovery {
	hostDiscovery := HostDiscovery{
		IP:              ip,
		IsAlive:         true,
		OpenPorts:       make([]models.PortResult, 0),
		DiscoveredAt:    time.Now(),
		Vulnerabilities: make([]PortVulnerability, 0),
	}

	// Create config for this host
	hostConfig := *ss.config
	hostConfig.Target = ip

	// Scan the host
	ns := NewNetworkScanner(&hostConfig, ss.logger)
	scanResult, err := ns.Scan()

	if err != nil || len(scanResult.OpenPorts) == 0 {
		hostDiscovery.IsAlive = false
		return hostDiscovery
	}

	hostDiscovery.OpenPorts = scanResult.OpenPorts
	hostDiscovery.ScanDuration = scanResult.ScanDuration

	// Perform OS detection
	hostDiscovery.OSDetection = DetectOS(scanResult.OpenPorts)

	// Get hostname
	hostDiscovery.Hostname = getHostname(ip)

	// Perform vulnerability scan on open ports
	vulnScanner := NewVulnerabilityScanner(ss.logger, ip)
	for _, port := range scanResult.OpenPorts {
		vulns := vulnScanner.ScanPort(port.Port, port.Service)
		hostDiscovery.Vulnerabilities = append(hostDiscovery.Vulnerabilities, vulns...)
	}

	return hostDiscovery
}

// printHostReport prints detailed report for a single host
func (ss *SubnetScanner) printHostReport(host HostDiscovery, hostNum int, totalHosts int) {
	ss.logger.Info("")
	ss.logger.Info("───────────────────────────────────────────────────────────────")
	ss.logger.Info("HOST DETAILS: %s", host.IP)
	ss.logger.Info("───────────────────────────────────────────────────────────────")

	// Hostname
	if host.Hostname != "" {
		ss.logger.Info("Hostname: %s", host.Hostname)
	} else {
		ss.logger.Info("Hostname: Not resolved")
	}

	// OS Detection
	ss.logger.Info("")
	ss.logger.Info("OS DETECTION:")
	ss.logger.Info("  Detected: %s", host.OSDetection.DetectedOS)
	ss.logger.Info("  Confidence: %.0f%%", host.OSDetection.Confidence*100)
	ss.logger.Info("  Version: %s", host.OSDetection.ProbableVersion)
	ss.logger.Info("  Family: %s", host.OSDetection.GetOSFamily())

	if len(host.OSDetection.Indicators) > 0 {
		ss.logger.Info("  Indicators:")
		for _, indicator := range host.OSDetection.Indicators {
			ss.logger.Info("    • %s", indicator)
		}
	}

	// Open Ports and Services
	ss.logger.Info("")
	ss.logger.Info("OPEN PORTS & SERVICES: (%d ports)", len(host.OpenPorts))
	ss.logger.Info("───────────────────────────────────────────────────────────────")

	if len(host.OpenPorts) == 0 {
		ss.logger.Warn("No open ports found")
	} else {
		for _, port := range host.OpenPorts {
			ss.logger.Success("Port %d/%s - %s (Confidence: %.0f%%)", 
				port.Port, port.Protocol, port.Service, port.Confidence*100)

			// Show banner if available
			if port.Banner != "" {
				banner := strings.TrimSpace(port.Banner)
				if len(banner) > 100 {
					banner = banner[:100] + "..."
				}
				ss.logger.Info("  Banner: %s", banner)
			}

			// Show CVEs if available
			if len(port.CVEs) > 0 {
				ss.logger.Error("  CVEs Found:")
				for _, cve := range port.CVEs {
					ss.logger.Error("    [%s] %s (CVSS: %.1f)", cve.CVEID, cve.Title, cve.Score)
				}
			}
		}
	}

	// Vulnerabilities
	if len(host.Vulnerabilities) > 0 {
		ss.logger.Info("")
		ss.logger.Info("DETECTED VULNERABILITIES: (%d)", len(host.Vulnerabilities))
		ss.logger.Info("───────────────────────────────────────────────────────────────")

		criticalCount := 0
		highCount := 0
		mediumCount := 0

		for _, vuln := range host.Vulnerabilities {
			switch vuln.Severity {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			case "medium":
				mediumCount++
			}
		}

		ss.logger.Info("Critical: %d | High: %d | Medium: %d", criticalCount, highCount, mediumCount)

		for _, vuln := range host.Vulnerabilities {
			switch vuln.Severity {
			case "critical":
				ss.logger.Error("[CRITICAL] Port %d - %s (CVSS: %.1f)", vuln.Port, vuln.Title, vuln.CVSS)
			case "high":
				ss.logger.Error("[HIGH] Port %d - %s (CVSS: %.1f)", vuln.Port, vuln.Title, vuln.CVSS)
			case "medium":
				ss.logger.Warn("[MEDIUM] Port %d - %s (CVSS: %.1f)", vuln.Port, vuln.Title, vuln.CVSS)
			case "low":
				ss.logger.Info("[LOW] Port %d - %s (CVSS: %.1f)", vuln.Port, vuln.Title, vuln.CVSS)
			}

			ss.logger.Info("  Description: %s", vuln.Description)
			if len(vuln.CVEs) > 0 {
				ss.logger.Error("  CVEs: %v", vuln.CVEs)
			}
			ss.logger.Info("  Remediation: %s", vuln.Remediation)
			ss.logger.Info("  Confidence: %.0f%%\n", vuln.ConfidenceScore*100)
		}
	} else {
		ss.logger.Info("")
		ss.logger.Success("No vulnerabilities detected on this host")
	}

	// Scan Stats
	ss.logger.Info("")
	ss.logger.Info("SCAN STATISTICS:")
	ss.logger.Info("  Duration: %s", host.ScanDuration)
	ss.logger.Info("  Discovered: %s", host.DiscoveredAt.Format(time.RFC3339))

	ss.logger.Info("")
	ss.logger.Info("───────────────────────────────────────────────────────────────")
	ss.logger.Info("Progress: [%d/%d hosts scanned]", hostNum, totalHosts)
	ss.logger.Info("───────────────────────────────────────────────────────────────\n")
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