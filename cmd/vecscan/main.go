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
        target          = flag.String("target", "", "Target to scan (IP, CIDR, or domain)")
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
        deepScan       = flag.Bool("deep", false, "Enable deep scanning")
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
        scanNetwork(ctx, logger, target, ports, timeout, rateLimit, threads, useEvasion, evasionMethods, includeUDP, jsonOutput, verbose, vulnScan)
    case "web":
        scanWeb(ctx, logger, target, jsonOutput, checkCVE, deepScan)
    default:
        logger.Error("Invalid scan type: %s", *scanType)
        os.Exit(1)
    }
}

func scanNetwork(ctx context.Context, logger *utils.Logger, target *string, ports *string, timeout *time.Duration, rateLimit *int, threads *int, useEvasion *bool, evasionMethods *string, includeUDP *bool, jsonOutput *string, verbose *bool, vulnScan *bool) {
    // Parse port range
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

    // Create scan configuration
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

    // Create and run scanner
    ns := scanner.NewNetworkScanner(config, logger)
    result, err := ns.Scan()

    if err != nil {
        logger.Fatal("Scan failed: %v", err)
    }

    // Print terminal report
    tr := reporter.NewTerminalReporter()
    tr.PrintNetworkReport(result)

    // Perform vulnerability assessment if requested
	if *vulnScan && len(result.OpenPorts) > 0 { // NEW
		ns.ScanVulnerabilities(result.OpenPorts)
	}

    // Write JSON report if requested
    if *jsonOutput != "" {
        jr := reporter.NewJSONReporter(*jsonOutput)
        if err := jr.WriteNetworkReport(result); err != nil {
            logger.Error("Failed to write JSON report: %v", err)
        } else {
            logger.Success("JSON report saved to %s", *jsonOutput)
        }
    }
}

func scanWeb(ctx context.Context, logger *utils.Logger, target *string, jsonOutput *string, checkCVE *bool, deepScan *bool) {
    // Ensure URL has scheme
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

    // Create and run web scanner
    ws := web.NewWebScanner(config, logger)
    result, err := ws.Scan()

    if err != nil {
        logger.Fatal("Web scan failed: %v", err)
    }

    // Print terminal report
    tr := reporter.NewTerminalReporter()
    tr.PrintWebReport(result)

    // Write JSON report if requested
    if *jsonOutput != "" {
        jr := reporter.NewJSONReporter(*jsonOutput)
        if err := jr.WriteWebReport(result); err != nil {
            logger.Error("Failed to write JSON report: %v", err)
        } else {
            logger.Success("JSON report saved to %s", *jsonOutput)
        }
    }
}