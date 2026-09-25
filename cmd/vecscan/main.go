package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
	"github.com/Ollie33-a/v3c5c4n/internal/reporter"
	"github.com/Ollie33-a/v3c5c4n/internal/scanner"
	"github.com/Ollie33-a/v3c5c4n/internal/utils"
	"github.com/Ollie33-a/v3c5c4n/internal/web"
)

func main() {
	// Define flags
	var (
		scanType        = flag.String("type", "network", "Scan type: network or web")
		target          = flag.String("target", "", "Target to scan (IP, CIDR, or domain) - can specify multiple IPs separated by space")
		ports           = flag.String("ports", "1-65535", "Port range (e.g., 80,443 or 1000-2000)")
		timeout         = flag.Duration("timeout", 5*time.Second, "Connection timeout")
		rateLimit       = flag.Int("rate", 1000, "Packets per second")
		threads         = flag.Int("threads", 64, "Number of scanning threads")
		useEvasion      = flag.Bool("evasion", false, "Use firewall evasion techniques")
		evasionMethods  = flag.String("evasion-methods", "ack,fin,spoof", "Comma-separated evasion methods")
		includeUDP      = flag.Bool("include-udp", false, "Include UDP scanning")
		jsonOutput      = flag.String("json", "", "Output JSON report to file")
		verbose         = flag.Bool("verbose", false, "Enable verbose output")
		checkCVE        = flag.Bool("cve", false, "Check for CVE matches")
		deepScan        = flag.Bool("deep", false, "Enable deep scanning")
		vulnScan        = flag.Bool("vuln", false, "Perform vulnerability assessment")
	)

	flag.Parse()

	// Create logger
	logger := utils.NewLogger(*verbose)
	logger.Banner()

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Warn("Shutdown signal received. Cleaning up...")
		cancel()
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// Validate inputs
	if *target == "" {
		logger.Error("Target must be specified with -target flag")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Execute scan based on type
	switch *scanType {
	case "network":
		// Check if multiple targets (space-separated or comma-separated)
		targets := parseMultipleTargets(*target)
		
		if len(targets) > 1 {
			// Multiple targets
			scanMultipleNetworkTargets(ctx, logger, targets, ports, timeout, rateLimit, threads, useEvasion, evasionMethods, includeUDP, jsonOutput, verbose, vulnScan, deepScan)
		} else {
			// Single target
			scanNetwork(ctx, logger, &targets[0], ports, timeout, rateLimit, threads, useEvasion, evasionMethods, includeUDP, jsonOutput, verbose, vulnScan)
		}
	case "web":
		targets := parseMultipleTargets(*target)
		if len(targets) > 1 {
			scanMultipleWebTargets(ctx, logger, targets, jsonOutput, checkCVE, deepScan)
		} else {
			scanWeb(ctx, logger, &targets[0], jsonOutput, checkCVE, deepScan)
		}
	default:
		logger.Error("Invalid scan type: %s", *scanType)
		os.Exit(1)
	}
}

// parseMultipleTargets parses multiple targets separated by space or comma
func parseMultipleTargets(targetStr string) []string {
	// Replace commas with spaces for uniform parsing
	targetStr = strings.ReplaceAll(targetStr, ",", " ")
	
	// Split by spaces
	targets := strings.Fields(targetStr)
	
	if len(targets) == 0 {
		return []string{}
	}
	
	return targets
}

// scanMultipleNetworkTargets scans multiple network targets
func scanMultipleNetworkTargets(ctx context.Context, logger *utils.Logger, targets []string, ports *string, timeout *time.Duration, rateLimit *int, threads *int, useEvasion *bool, evasionMethods *string, includeUDP *bool, jsonOutput *string, verbose *bool, vulnScan *bool, deepScan *bool) {
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("MULTIPLE TARGET SCAN")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Total targets: %d", len(targets))
	logger.Info("Targets: %v", targets)
	logger.Info("════════════════════════════════════════════════════════════════\n")

	// Parse ports
	parsedPorts, err := utils.ParsePortRange(*ports)
	if err != nil {
		logger.Fatal("Invalid port specification: %v", err)
	}

	// Parse evasion methods
	var evasionList []string
	if *useEvasion {
		evasionList = strings.Split(*evasionMethods, ",")
		for i := range evasionList {
			evasionList[i] = strings.TrimSpace(evasionList[i])
		}
	}

	startTime := time.Now()
	var allReports []*models.HostResult

	// Scan each target
	for i, target := range targets {
		logger.Info("═════════════════════════════════════════════════════════════════")
		logger.Info("[%d/%d] Scanning target: %s", i+1, len(targets), target)
		logger.Info("═════════════════════════════════════════════════════════════════")

		// Check if target is subnet or single IP
		isSubnet := strings.Contains(target, "/")

		if isSubnet {
			// Subnet scan
			scanSubnetTarget(ctx, logger, &target, ports, timeout, rateLimit, threads, jsonOutput, verbose)
		} else {
			// Single host scan
			config := &models.ScanConfig{
				Target:         target,
				Ports:          parsedPorts,
				Timeout:        *timeout,
				RateLimit:      *rateLimit,
				ThreadCount:    *threads,
				UseEvasion:     *useEvasion,
				EvasionMethods: evasionList,
				IncludeUDP:     *includeUDP,
				JSONOutput:     *jsonOutput,
				Verbose:        *verbose,
				Context:        ctx,
				Cancel:         nil,
			}

			ns := scanner.NewNetworkScanner(config, logger)
			result, err := ns.Scan()

			if err != nil {
				logger.Error("Scan failed for %s: %v", target, err)
				continue
			}

			allReports = append(allReports, result)

			// Print OS Detection
			if len(result.OpenPorts) > 0 {
				logger.Info("\n═══════════════════════════════════════════════════════════════")
				logger.Info("OS DETECTION")
				logger.Info("═══════════════════════════════════════════════════════════════")

				osFingerprint := scanner.DetectOS(result.OpenPorts)
				logger.Info("Detected OS: %s", osFingerprint.DetectedOS)
				logger.Info("Confidence: %.0f%%", osFingerprint.Confidence*100)
				logger.Info("Probable Version: %s", osFingerprint.ProbableVersion)
				logger.Info("Indicators:")
				for _, indicator := range osFingerprint.Indicators {
					logger.Info("  • %s", indicator)
				}
				logger.Info("═══════════════════════════════════════════════════════════════")
			}

			// Print report
			tr := reporter.NewTerminalReporter()
			tr.PrintNetworkReport(result)

			// Vulnerability assessment
			if *vulnScan && len(result.OpenPorts) > 0 {
				ns.ScanVulnerabilities(result.OpenPorts)
			}

			// Export individual JSON
			if *jsonOutput != "" {
				jr := reporter.NewJSONReporter(*jsonOutput)
				if err := jr.WriteNetworkReport(result); err != nil {
					logger.Error("Failed to write JSON report: %v", err)
				} else {
					logger.Success("JSON report saved to %s", *jsonOutput)
				}
			}
		}

		logger.Info("\nProgress: [%d/%d targets scanned]", i+1, len(targets))
		logger.Info("\n")
	}

	// Print summary
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("SCAN SUMMARY")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Total targets scanned: %d", len(targets))
	logger.Info("Total scan duration: %v", time.Since(startTime))
	
	// Summary statistics
	totalOpenPorts := 0
	for _, report := range allReports {
		totalOpenPorts += len(report.OpenPorts)
	}
	
	logger.Success("Total open ports found: %d", totalOpenPorts)
	logger.Info("════════════════════════════════════════════════════════════════\n")
}

// scanMultipleWebTargets scans multiple web targets
func scanMultipleWebTargets(ctx context.Context, logger *utils.Logger, targets []string, jsonOutput *string, checkCVE *bool, deepScan *bool) {
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("MULTIPLE WEB TARGET SCAN")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Total targets: %d", len(targets))
	logger.Info("════════════════════════════════════════════════════════════════\n")

	startTime := time.Now()

	for i, target := range targets {
		logger.Info("═════════════════════════════════════════════════════════════════")
		logger.Info("[%d/%d] Scanning: %s", i+1, len(targets), target)
		logger.Info("═════════════════════════════════════════════════════════════════")

		// Ensure URL has scheme
		url := target
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}

		config := &models.WebScanConfig{
			URL:             url,
			Timeout:         10 * time.Second,
			IncludeDeepScan: *deepScan,
			CheckCVE:        *checkCVE,
			JSONOutput:      *jsonOutput,
			Context:         ctx,
			Cancel:          nil,
		}

		ws := web.NewWebScanner(config, logger)
		result, err := ws.Scan()

		if err != nil {
			logger.Error("Web scan failed for %s: %v", target, err)
			continue
		}

		// Print report
		tr := reporter.NewTerminalReporter()
		tr.PrintWebReport(result)

		// Export JSON
		if *jsonOutput != "" {
			jr := reporter.NewJSONReporter(*jsonOutput)
			if err := jr.WriteWebReport(result); err != nil {
				logger.Error("Failed to write JSON report: %v", err)
			} else {
				logger.Success("JSON report saved to %s", *jsonOutput)
			}
		}

		logger.Info("\nProgress: [%d/%d targets scanned]", i+1, len(targets))
		logger.Info("\n")
	}

	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("WEB SCAN SUMMARY")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Total targets scanned: %d", len(targets))
	logger.Info("Total scan duration: %v", time.Since(startTime))
	logger.Info("════════════════════════════════════════════════════════════════\n")
}

// scanSubnetTarget scans a subnet
func scanSubnetTarget(ctx context.Context, logger *utils.Logger, target *string, ports *string, timeout *time.Duration, rateLimit *int, threads *int, jsonOutput *string, verbose *bool) {
	parsedPorts, err := utils.ParsePortRange(*ports)
	if err != nil {
		logger.Fatal("Invalid port specification: %v", err)
	}

	config := &models.ScanConfig{
		Target:      *target,
		Ports:       parsedPorts,
		Timeout:     *timeout,
		RateLimit:   *rateLimit,
		ThreadCount: *threads,
		JSONOutput:  *jsonOutput,
		Verbose:     *verbose,
		Context:     ctx,
		Cancel:      nil,
	}

	ss := scanner.NewSubnetScanner(config, logger)
	result, err := ss.ScanSubnet()

	if err != nil {
		logger.Fatal("Subnet scan failed: %v", err)
	}

	tr := reporter.NewTerminalReporter()
	tr.PrintSubnetReport(result)

	if *jsonOutput != "" {
		jr := reporter.NewJSONReporter(*jsonOutput)
		if err := jr.WriteSubnetReport(result); err != nil {
			logger.Error("Failed to write JSON report: %v", err)
		} else {
			logger.Success("JSON report saved to %s", *jsonOutput)
		}
	}
}

// Single target functions remain the same
func scanNetwork(ctx context.Context, logger *utils.Logger, target *string, ports *string, timeout *time.Duration, rateLimit *int, threads *int, useEvasion *bool, evasionMethods *string, includeUDP *bool, jsonOutput *string, verbose *bool, vulnScan *bool) {
	isSubnet := strings.Contains(*target, "/") || strings.Count(*target, "-") > 0

	if isSubnet && strings.Contains(*target, "/") {
		scanSubnetTarget(ctx, logger, target, ports, timeout, rateLimit, threads, jsonOutput, verbose)
	} else {
		parsedPorts, err := utils.ParsePortRange(*ports)
		if err != nil {
			logger.Fatal("Invalid port specification: %v", err)
		}

		var evasionList []string
		if *useEvasion {
			evasionList = strings.Split(*evasionMethods, ",")
			for i := range evasionList {
				evasionList[i] = strings.TrimSpace(evasionList[i])
			}
		}

		config := &models.ScanConfig{
			Target:         *target,
			Ports:          parsedPorts,
			Timeout:        *timeout,
			RateLimit:      *rateLimit,
			ThreadCount:    *threads,
			UseEvasion:     *useEvasion,
			EvasionMethods: evasionList,
			IncludeUDP:     *includeUDP,
			JSONOutput:     *jsonOutput,
			Verbose:        *verbose,
			Context:        ctx,
			Cancel:         nil,
		}

		ns := scanner.NewNetworkScanner(config, logger)
		result, err := ns.Scan()

		if err != nil {
			logger.Fatal("Scan failed: %v", err)
		}

		if len(result.OpenPorts) > 0 {
			logger.Info("\n═══════════════════════════════════════════════════════════════")
			logger.Info("OS DETECTION")
			logger.Info("═══════════════════════════════════════════════════════════════")

			osFingerprint := scanner.DetectOS(result.OpenPorts)
			logger.Info("Detected OS: %s", osFingerprint.DetectedOS)
			logger.Info("Confidence: %.0f%%", osFingerprint.Confidence*100)
			logger.Info("Probable Version: %s", osFingerprint.ProbableVersion)
			logger.Info("Indicators:")
			for _, indicator := range osFingerprint.Indicators {
				logger.Info("  • %s", indicator)
			}
			logger.Info("═══════════════════════════════════════════════════════════════")
		}

		tr := reporter.NewTerminalReporter()
		tr.PrintNetworkReport(result)

		if *vulnScan && len(result.OpenPorts) > 0 {
			ns.ScanVulnerabilities(result.OpenPorts)
		}

		if *jsonOutput != "" {
			jr := reporter.NewJSONReporter(*jsonOutput)
			if err := jr.WriteNetworkReport(result); err != nil {
				logger.Error("Failed to write JSON report: %v", err)
			} else {
				logger.Success("JSON report saved to %s", *jsonOutput)
			}
		}
	}
}

func scanWeb(ctx context.Context, logger *utils.Logger, target *string, jsonOutput *string, checkCVE *bool, deepScan *bool) {
	url := *target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	config := &models.WebScanConfig{
		URL:             url,
		Timeout:         10 * time.Second,
		IncludeDeepScan: *deepScan,
		CheckCVE:        *checkCVE,
		JSONOutput:      *jsonOutput,
		Context:         ctx,
		Cancel:          nil,
	}

	ws := web.NewWebScanner(config, logger)
	result, err := ws.Scan()

	if err != nil {
		logger.Fatal("Web scan failed: %v", err)
	}

	tr := reporter.NewTerminalReporter()
	tr.PrintWebReport(result)

	if *jsonOutput != "" {
		jr := reporter.NewJSONReporter(*jsonOutput)
		if err := jr.WriteWebReport(result); err != nil {
			logger.Error("Failed to write JSON report: %v", err)
		} else {
			logger.Success("JSON report saved to %s", *jsonOutput)
		}
	}
}