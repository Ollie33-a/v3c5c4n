package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
	"github.com/Ollie33-a/v3c5c4n/internal/utils"
)

// NetworkScanner performs network port scanning
type NetworkScanner struct {
	config        *models.ScanConfig
	logger        *utils.Logger
	rateLimiter   *utils.RateLimiter
	evasionEngine *EvasionEngine
	state         *models.ScanState
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(config *models.ScanConfig, logger *utils.Logger) *NetworkScanner {
	return &NetworkScanner{
		config:        config,
		logger:        logger,
		rateLimiter:   utils.NewRateLimiter(config.RateLimit),
		evasionEngine: NewEvasionEngine(),
		state: &models.ScanState{
			StartTime:  time.Now(),
			IsScanning: true,
			TotalPorts: config.EndPort - config.StartPort + 1,
		},
	}
}

// Scan performs the network scan
func (ns *NetworkScanner) Scan() (*models.HostResult, error) {
	if err := utils.ValidateConfig(ns.config); err != nil {
		return nil, err
	}

	result := &models.HostResult{
		Target:        ns.config.Target,
		Timestamp:     time.Now(),
		TotalPorts:    ns.config.EndPort - ns.config.StartPort + 1,
		OpenPorts:     make([]models.PortResult, 0),
		ClosedPorts:   make([]models.PortResult, 0),
		FilteredPorts: make([]models.PortResult, 0),
	}

	ns.logger.Info("Starting scan on %s (%d-%d ports)", ns.config.Target, ns.config.StartPort, ns.config.EndPort)
	ns.logger.Debug("Using %d threads with rate limit: %d packets/sec", ns.config.ThreadCount, ns.config.RateLimit)

	startTime := time.Now()

	// TCP Scan
	tcpResults := ns.scanTCP()
	result.OpenPorts = append(result.OpenPorts, tcpResults.Open...)
	result.ClosedPorts = append(result.ClosedPorts, tcpResults.Closed...)
	result.FilteredPorts = append(result.FilteredPorts, tcpResults.Filtered...)

	// UDP Scan (if enabled)
	if ns.config.IncludeUDP {
		ns.logger.Info("Starting UDP scan...")
		udpResults := ns.scanUDP()
		result.OpenPorts = append(result.OpenPorts, udpResults.Open...)
		result.ClosedPorts = append(result.ClosedPorts, udpResults.Closed...)
		result.FilteredPorts = append(result.FilteredPorts, udpResults.Filtered...)
	}

	// Sort results
	sort.Slice(result.OpenPorts, func(i, j int) bool { return result.OpenPorts[i].Port < result.OpenPorts[j].Port })

	// Check for filtered ports
	if len(result.FilteredPorts) > 0 && !ns.config.ScanFiltered {
		ns.logger.Warn("Found %d filtered ports. These may be protected by firewall", len(result.FilteredPorts))
	}

	result.ScanDuration = time.Since(startTime)
	result.PacketsSent = ns.state.PacketsSent
	result.PacketsReceived = ns.state.PacketsReceived
	result.Success = true

	return result, nil
}

// scanTCP performs TCP port scanning
func (ns *NetworkScanner) scanTCP() *TCPScanResult {
	result := &TCPScanResult{
		Open:     make([]models.PortResult, 0),
		Closed:   make([]models.PortResult, 0),
		Filtered: make([]models.PortResult, 0),
	}

	ports := make(chan int, ns.config.ThreadCount)
	results := make(chan models.PortResult, ns.state.TotalPorts)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < ns.config.ThreadCount; i++ {
		wg.Add(1)
		go ns.tcpWorker(ports, results, &wg)
	}

	// Send ports to scan
	go func() {
		for port := ns.config.StartPort; port <= ns.config.EndPort; port++ {
			select {
			case ports <- port:
			case <-ns.config.Context.Done():
				close(ports)
				return
			}
		}
		close(ports)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for portResult := range results {
		switch portResult.State {
		case "open":
			result.Open = append(result.Open, portResult)
			ns.logger.Success("Port %d/%s open - %s", portResult.Port, portResult.Protocol, portResult.Service)
		case "closed":
			result.Closed = append(result.Closed, portResult)
		case "filtered", "open|filtered":
			result.Filtered = append(result.Filtered, portResult)
			ns.logger.Warn("Port %d/%s filtered", portResult.Port, portResult.Protocol)
		}
	}

	return result
}

// tcpWorker scans TCP ports
func (ns *NetworkScanner) tcpWorker(ports chan int, results chan models.PortResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for port := range ports {
		// Apply rate limiting
		if err := ns.rateLimiter.Wait(ns.config.Context); err != nil {
			return
		}

		// Apply evasion if enabled
		if ns.config.UseEvasion && len(ns.config.EvasionMethods) > 0 {
			ns.evasionEngine.ApplyEvasion(ns.config.EvasionMethods[0])
		}

		result := ns.scanTCPPort(port)
		ns.state.PacketsSent++

		if result.State != "closed" {
			ns.state.PacketsReceived++
		}

		select {
		case results <- result:
		case <-ns.config.Context.Done():
			return
		}
	}
}

// scanTCPPort scans a single TCP port
func (ns *NetworkScanner) scanTCPPort(port int) models.PortResult {
	result := models.PortResult{
		Port:       port,
		Protocol:   "tcp",
		State:      "closed",
		Service:    models.GetServiceName(port),
		ScannedAt:  time.Now(),
		Confidence: 0.0,
	}

	address := fmt.Sprintf("%s:%d", ns.config.Target, port)
	conn, err := net.DialTimeout("tcp", address, ns.config.Timeout)

	if err == nil {
		defer conn.Close()
		result.State = "open"
		result.Confidence = 0.99

		// Try to get banner
		result.Banner = ns.getBanner(conn)
	} else {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
			result.Confidence = 0.7
		} else {
			result.State = "closed"
			result.Confidence = 0.99
		}
	}

	return result
}

// scanUDP performs UDP port scanning
func (ns *NetworkScanner) scanUDP() *TCPScanResult {
	result := &TCPScanResult{
		Open:     make([]models.PortResult, 0),
		Closed:   make([]models.PortResult, 0),
		Filtered: make([]models.PortResult, 0),
	}

	// UDP scanning requires elevated privileges and is more complex
	// For now, we'll implement basic ICMP-based detection
	for port := ns.config.StartPort; port <= ns.config.EndPort; port++ {
		select {
		case <-ns.config.Context.Done():
			return result
		default:
		}

		portResult := ns.scanUDPPort(port)

		switch portResult.State {
		case "open":
			result.Open = append(result.Open, portResult)
			ns.logger.Success("Port %d/udp open - %s", portResult.Port, portResult.Service)
		case "filtered":
			result.Filtered = append(result.Filtered, portResult)
		}
	}

	return result
}

// scanUDPPort scans a single UDP port
func (ns *NetworkScanner) scanUDPPort(port int) models.PortResult {
	result := models.PortResult{
		Port:       port,
		Protocol:   "udp",
		State:      "closed",
		Service:    models.GetServiceName(port),
		ScannedAt:  time.Now(),
		Confidence: 0.6,
	}

	address := fmt.Sprintf("%s:%d", ns.config.Target, port)
	conn, err := net.DialTimeout("udp", address, ns.config.Timeout)

	if err == nil {
		defer conn.Close()

		// Send probe
		conn.SetDeadline(time.Now().Add(ns.config.Timeout))
		conn.Write([]byte{0x00, 0x01, 0x00, 0x00})

		buffer := make([]byte, 4096)
		_, err := conn.Read(buffer)

		if err == nil {
			result.State = "open"
			result.Confidence = 0.8
		} else {
			result.State = "filtered"
		}
	}

	return result
}

// getBanner retrieves service banner from open port
func (ns *NetworkScanner) getBanner(conn net.Conn) string {
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	if n, err := conn.Read(buffer); err == nil {
		return string(buffer[:n])
	}

	return ""
}

// TCPScanResult contains TCP scan results
type TCPScanResult struct {
	Open     []models.PortResult
	Closed   []models.PortResult
	Filtered []models.PortResult
}