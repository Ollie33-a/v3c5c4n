package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
)

// ParseTarget parses target specification (single IP, CIDR, or range)
func ParseTarget(target string) ([]string, error) {
	targets := []string{}

	// Check if it's CIDR notation
	if strings.Contains(target, "/") {
		ip, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR notation: %w", err)
		}
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); increment(ip) {
			if ip.String() != ipNet.IP.String() && ip.String() != broadcast(ipNet).String() {
				targets = append(targets, ip.String())
			}
		}
		return targets, nil
	}

	// Check if it's a range (e.g., 192.168.1.1-50)
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) == 2 {
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			if startIP != nil {
				endOctet, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					ipParts := strings.Split(startIP.String(), ".")
					if len(ipParts) == 4 {
						start, _ := strconv.Atoi(ipParts[3])
						for i := start; i <= endOctet && i <= 255; i++ {
							ipParts[3] = strconv.Itoa(i)
							targets = append(targets, strings.Join(ipParts, "."))
						}
						return targets, nil
					}
				}
			}
		}
	}

	// Single IP
	if net.ParseIP(target) != nil {
		targets = append(targets, target)
		return targets, nil
	}

	return nil, fmt.Errorf("invalid target specification: %s", target)
}

// ParsePortRange parses port range specification (handles comma-separated and ranges)
func ParsePortRange(portRange string) ([]int, error) {
	if portRange == "" {
		// Return all ports
		ports := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
		return ports, nil
	}

	portMap := make(map[int]bool)
	
	// Split by comma first (handles: 22,80,443)
	parts := strings.Split(portRange, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		
		// Check if it's a range (e.g., 1000-2000)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))

			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port numbers in range: %s", part)
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range must be between 1-65535 and start <= end")
			}

			for port := start; port <= end; port++ {
				portMap[port] = true
			}
		} else {
			// Single port (e.g., 22 or 80)
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be between 1-65535, got: %d", port)
			}

			portMap[port] = true
		}
	}

	// Convert map to sorted slice
	ports := make([]int, 0, len(portMap))
	for port := range portMap {
		ports = append(ports, port)
	}
	
	// Sort ports
	for i := 0; i < len(ports)-1; i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[i] > ports[j] {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}

	return ports, nil
}

// ValidateConfig validates scanner configuration
func ValidateConfig(config *models.ScanConfig) error {
	if config.Target == "" {
		return fmt.Errorf("target must be specified")
	}

	if len(config.Ports) == 0 {
		return fmt.Errorf("no valid ports to scan")
	}

	if config.Timeout < 100*1000000 { // 100ms
		return fmt.Errorf("timeout must be at least 100ms")
	}

	if config.RateLimit < 1 {
		config.RateLimit = 1000 // Default rate limit
	}

	if config.ThreadCount < 1 {
		config.ThreadCount = 64 // Default threads
	}

	return nil
}

// Helper functions
func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func broadcast(ipNet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipNet.IP))
	copy(broadcast, ipNet.IP)
	for i := 0; i < len(ipNet.Mask); i++ {
		broadcast[i] |= ^ipNet.Mask[i]
	}
	return broadcast
}