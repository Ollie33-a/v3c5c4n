package reporter

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/Ollie33-a/v3c5c4n/internal/models"
	"github.com/Ollie33-a/v3c5c4n/internal/scanner"
)

// TerminalReporter generates terminal output
type TerminalReporter struct{}

// NewTerminalReporter creates a new terminal reporter
func NewTerminalReporter() *TerminalReporter {
	return &TerminalReporter{}
}

// PrintNetworkReport prints network scan results to terminal
func (tr *TerminalReporter) PrintNetworkReport(result *models.HostResult) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n")
	color.New(color.FgCyan, color.Bold).Printf("NETWORK SCAN REPORT\n")
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n\n")

	color.New(color.FgWhite, color.Bold).Printf("Target: ")
	fmt.Printf("%s\n", result.Target)

	color.New(color.FgWhite, color.Bold).Printf("Scan Time: ")
	fmt.Printf("%s\n", result.Timestamp.Format(time.RFC3339))

	color.New(color.FgWhite, color.Bold).Printf("Duration: ")
	fmt.Printf("%s\n", result.ScanDuration)

	color.New(color.FgWhite, color.Bold).Printf("Total Ports Scanned: ")
	fmt.Printf("%d\n", result.TotalPorts)

	fmt.Println()
	color.New(color.FgGreen, color.Bold).Printf("OPEN PORTS (%d):\n", len(result.OpenPorts))
	color.New(color.FgGreen, color.Bold).Println("─────────────────────────────────────────────────────────────────")

	if len(result.OpenPorts) == 0 {
		fmt.Println("No open ports found")
	} else {
		fmt.Printf("%-10s %-15s %-30s %-15s\n", "Port", "Protocol", "Service", "Confidence")
		fmt.Println("─────────────────────────────────────────────────────────────────")
		for _, port := range result.OpenPorts {
			fmt.Printf("%-10d %-15s %-30s %-15.1f%%\n",
				port.Port, port.Protocol, port.Service, port.Confidence*100)

			// Print CVEs if found
			if len(port.CVEs) > 0 {
				color.New(color.FgRed, color.Bold).Printf("    CVEs Found:\n")
				for _, cve := range port.CVEs {
					color.New(color.FgRed).Printf("      [%s] %s (CVSS: %.1f)\n",
						cve.CVEID, cve.Title, cve.Score)
				}
			}
		}
	}

	fmt.Println()
	color.New(color.FgRed, color.Bold).Printf("CLOSED PORTS (%d):\n", len(result.ClosedPorts))
	fmt.Printf("Found %d closed ports\n", len(result.ClosedPorts))

	fmt.Println()
	color.New(color.FgYellow, color.Bold).Printf("FILTERED PORTS (%d):\n", len(result.FilteredPorts))
	if len(result.FilteredPorts) > 0 {
		color.New(color.FgYellow).Printf("Found %d filtered ports (may be protected by firewall)\n", len(result.FilteredPorts))
	}

	if len(result.OpenFilteredPorts) > 0 {
		fmt.Println()
		color.New(color.FgMagenta, color.Bold).Printf("OPEN|FILTERED PORTS (via evasion) (%d):\n", len(result.OpenFilteredPorts))
		for _, port := range result.OpenFilteredPorts {
			color.New(color.FgMagenta).Printf("Port %d/%s [%s evasion]\n", port.Port, port.Protocol, port.EvasionMethod)
		}
	}

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Printf("STATISTICS:\n")
	color.New(color.FgCyan, color.Bold).Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("Packets Sent:     %d\n", result.PacketsSent)
	fmt.Printf("Packets Received: %d\n", result.PacketsReceived)
	if result.PacketsSent > 0 {
		fmt.Printf("Success Rate:     %.2f%%\n", float64(result.PacketsReceived)/float64(result.PacketsSent)*100)
	}

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("════════════════════════════════════════════════════════════════")
}

// PrintWebReport prints web scan results to terminal
func (tr *TerminalReporter) PrintWebReport(result *models.WebScanResult) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n")
	color.New(color.FgCyan, color.Bold).Printf("WEB VULNERABILITY SCAN REPORT\n")
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n\n")

	color.New(color.FgWhite, color.Bold).Printf("Target URL: ")
	fmt.Printf("%s\n", result.URL)

	color.New(color.FgWhite, color.Bold).Printf("Scan Time: ")
	fmt.Printf("%s\n", result.Timestamp.Format(time.RFC3339))

	color.New(color.FgWhite, color.Bold).Printf("Duration: ")
	fmt.Printf("%s\n", result.ScanDuration)

	// Server Info
	fmt.Println()
	color.New(color.FgBlue, color.Bold).Printf("SERVER INFORMATION:\n")
	color.New(color.FgBlue, color.Bold).Println("─────────────────────────────────────────────────────────────────")
	if result.ServerInfo.Server != "" {
		fmt.Printf("Server: %s\n", result.ServerInfo.Server)
	}
	if result.ServerInfo.PoweredBy != "" {
		fmt.Printf("Powered By: %s\n", result.ServerInfo.PoweredBy)
	}

	// Vulnerabilities
	fmt.Println()
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	color.New(color.FgRed, color.Bold).Printf("VULNERABILITIES FOUND (%d):\n", len(result.Vulnerabilities))
	fmt.Printf("Critical: %d | High: %d | Medium: %d\n", criticalCount, highCount, mediumCount)
	color.New(color.FgRed, color.Bold).Println("─────────────────────────────────────────────────────────────────")

	if len(result.Vulnerabilities) == 0 {
		color.New(color.FgGreen).Println("No vulnerabilities found!")
	} else {
		for i, vuln := range result.Vulnerabilities {
			fmt.Printf("\n[%d] %s\n", i+1, vuln.Title)

			color.New(color.FgWhite).Printf("  Severity:   ")
			switch vuln.Severity {
			case "critical":
				color.New(color.FgRed, color.Bold).Println(vuln.Severity)
			case "high":
				color.New(color.FgRed).Println(vuln.Severity)
			case "medium":
				color.New(color.FgYellow).Println(vuln.Severity)
			default:
				fmt.Println(vuln.Severity)
			}

			fmt.Printf("  Confidence: %.1f%%\n", vuln.ConfidenceScore*100)
			fmt.Printf("  Endpoint:   %s\n", vuln.Endpoint)
			fmt.Printf("  Description: %s\n", vuln.Description)

			if len(vuln.CVE) > 0 {
				color.New(color.FgMagenta, color.Bold).Printf("  CVEs:       ")
				for j, cve := range vuln.CVE {
					if j > 0 {
						fmt.Printf(", ")
					}
					fmt.Printf("%s", cve)
				}
				fmt.Println()
			}
		}
	}

	// SSL Info
	if result.SslCertInfo.Subject != "" {
		fmt.Println()
		color.New(color.FgBlue, color.Bold).Printf("SSL/TLS INFORMATION:\n")
		color.New(color.FgBlue, color.Bold).Println("─────────────────────────────────────────────────────────────────")
		fmt.Printf("Subject:  %s\n", result.SslCertInfo.Subject)
		fmt.Printf("Issuer:   %s\n", result.SslCertInfo.Issuer)
		fmt.Printf("Valid:    %v - %v\n", result.SslCertInfo.NotBefore, result.SslCertInfo.NotAfter)

		if !result.SslCertInfo.IsValid {
			color.New(color.FgRed).Printf("Status:   INVALID\n")
			for _, issue := range result.SslCertInfo.IssuesFound {
				fmt.Printf("  - %s\n", issue)
			}
		} else {
			color.New(color.FgGreen).Printf("Status:   VALID\n")
		}
	}

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("════════════════════════════════════════════════════════════════")
}

// PrintSubnetReport prints subnet scan results summary
func (tr *TerminalReporter) PrintSubnetReport(result *scanner.SubnetResult) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n")
	color.New(color.FgCyan, color.Bold).Printf("SUBNET SCAN SUMMARY\n")
	color.New(color.FgCyan, color.Bold).Printf("════════════════════════════════════════════════════════════════\n\n")

	color.New(color.FgWhite, color.Bold).Printf("Subnet: ")
	fmt.Printf("%s\n", result.Subnet)

	color.New(color.FgWhite, color.Bold).Printf("Scan Start: ")
	fmt.Printf("%s\n", result.StartTime.Format(time.RFC3339))

	color.New(color.FgWhite, color.Bold).Printf("Total Duration: ")
	fmt.Printf("%s\n", result.ScanDuration)

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Printf("FINAL SUMMARY:\n")
	color.New(color.FgCyan, color.Bold).Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("Total Hosts in Subnet: %d\n", result.TotalHosts)
	color.New(color.FgGreen).Printf("Alive Hosts Found:    %d\n", result.AliveHosts)
	color.New(color.FgRed).Printf("Hosts Down:           %d\n", result.DownHosts)
	fmt.Printf("Hosts with Services:  %d\n", len(result.DiscoveredHosts))

	// Summary of hosts
	fmt.Println()
	color.New(color.FgGreen, color.Bold).Printf("HOSTS WITH OPEN PORTS:\n")
	color.New(color.FgGreen, color.Bold).Println("─────────────────────────────────────────────────────────────────")

	if len(result.DiscoveredHosts) == 0 {
		fmt.Println("No hosts with open ports found")
	} else {
		fmt.Printf("%-20s %-25s %-20s %s\n", "IP Address", "Hostname", "OS", "Open Ports")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────")
		
		for _, host := range result.DiscoveredHosts {
			hostname := host.Hostname
			if hostname == "" {
				hostname = "N/A"
			}
			
			osName := host.OSDetection.DetectedOS
			portCount := len(host.OpenPorts)
			
			fmt.Printf("%-20s %-25s %-20s %d\n", host.IP, hostname, osName, portCount)
		}
	}

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("════════════════════════════════════════════════════════════════")
	fmt.Println()
	color.New(color.FgYellow).Println("Note: Detailed reports for each host were displayed during the scan above.")
	fmt.Println()
}