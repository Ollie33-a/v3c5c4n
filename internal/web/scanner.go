package web

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"

    "github.com/Ollie33-a/v3c5c4n/internal/models"
    "github.com/Ollie33-a/v3c5c4n/internal/utils"
)

// WebScanner performs web vulnerability scanning
type WebScanner struct {
    config *models.WebScanConfig
    logger *utils.Logger
    client *http.Client
}

// NewWebScanner creates a new web scanner
func NewWebScanner(config *models.WebScanConfig, logger *utils.Logger) *WebScanner {
    client := &http.Client{
        Timeout: config.Timeout,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }

    return &WebScanner{
        config: config,
        logger: logger,
        client: client,
    }
}

// Scan performs the web vulnerability scan
func (ws *WebScanner) Scan() (*models.WebScanResult, error) {
    if err := validateWebURL(ws.config.URL); err != nil {
        return nil, err
    }

    result := &models.WebScanResult{
        URL:              ws.config.URL,
        Timestamp:        time.Now(),
        Vulnerabilities: make([]models.WebVulnerability, 0),
    }

    ws.logger.Info("Starting web vulnerability scan on %s", ws.config.URL)
    startTime := time.Now()

    // Get server information
    serverInfo, err := ws.getServerInfo()
    if err != nil {
        ws.logger.Warn("Failed to get server info: %v", err)
    } else {
        result.ServerInfo = serverInfo
    }

    // Scan for vulnerabilities
    vulns := ws.scanVulnerabilities()
    result.Vulnerabilities = vulns

    // Check SSL/TLS
    sslInfo, err := ws.checkSSL()
    if err == nil {
        result.SslCertInfo = sslInfo
    }

    // Attempt CVE matching
    if ws.config.CheckCVE {
        ws.logger.Info("Matching vulnerabilities to CVEs...")
        for i, vuln := range result.Vulnerabilities {
            cves := matchToCVE(&vuln)
            result.Vulnerabilities[i].CVE = cves
        }
    }

    result.ScanDuration = time.Since(startTime)
    result.Success = true

    return result, nil
}

// getServerInfo retrieves server information
func (ws *WebScanner) getServerInfo() (models.ServerInfo, error) {
    info := models.ServerInfo{
        Headers: make(map[string]string),
    }

    req, err := http.NewRequestWithContext(ws.config.Context, "GET", ws.config.URL, nil)
    if err != nil {
        return info, err
    }

    resp, err := ws.client.Do(req)
    if err != nil {
        return info, err
    }
    defer resp.Body.Close()

    // Extract headers
    for key, values := range resp.Header {
        if len(values) > 0 {
            info.Headers[key] = values[0]
        }
    }

    info.Server = resp.Header.Get("Server")
    info.PoweredBy = resp.Header.Get("X-Powered-By")
    info.ContentType = resp.Header.Get("Content-Type")

    // Extract cookies
    for _, cookie := range resp.Cookies() {
        info.Cookies = append(info.Cookies, cookie.Name)
    }

    return info, nil
}

// scanVulnerabilities scans for common web vulnerabilities
func (ws *WebScanner) scanVulnerabilities() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    // SQL Injection tests
    sqlVulns := ws.testSQLInjection()
    vulns = append(vulns, sqlVulns...)

    // XSS tests
    xssVulns := ws.testXSS()
    vulns = append(vulns, xssVulns...)

    // CSRF tests
    csrfVulns := ws.testCSRF()
    vulns = append(vulns, csrfVulns...)

    // Security headers tests
    headerVulns := ws.testSecurityHeaders()
    vulns = append(vulns, headerVulns...)

    // Directory traversal tests
    dirVulns := ws.testDirectoryTraversal()
    vulns = append(vulns, dirVulns...)

    return vulns
}

// testSQLInjection tests for SQL injection vulnerabilities
func (ws *WebScanner) testSQLInjection() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    payloads := []string{
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "1' UNION SELECT NULL--",
    }

    for _, payload := range payloads {
        testURL := fmt.Sprintf("%s?id=%s", ws.config.URL, url.QueryEscape(payload))
        
        req, err := http.NewRequestWithContext(ws.config.Context, "GET", testURL, nil)
        if err != nil {
            continue
        }

        resp, err := ws.client.Do(req)
        if err != nil {
            continue
        }

        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        // Check for SQL error indicators
        bodyStr := string(body)
        if strings.Contains(bodyStr, "SQL") || strings.Contains(bodyStr, "database") {
            vulns = append(vulns, models.WebVulnerability{
                ID:              "SQL001",
                Title:           "Potential SQL Injection",
                Severity:        "high",
                Description:     fmt.Sprintf("Potential SQL injection vulnerability detected with payload: %s", payload),
                Endpoint:        testURL,
                Payload:         payload,
                ConfidenceScore: 0.7,
                DiscoveredAt:    time.Now(),
            })
        }
    }

    return vulns
}

// testXSS tests for XSS vulnerabilities
func (ws *WebScanner) testXSS() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    payloads := []string{
        "<script>alert('XSS')</script>",
        "<img src=x onerror=\"alert('XSS')\">",
        "<svg/onload=\"alert('XSS')\">",
    }

    for _, payload := range payloads {
        testURL := fmt.Sprintf("%s?search=%s", ws.config.URL, url.QueryEscape(payload))
        
        req, err := http.NewRequestWithContext(ws.config.Context, "GET", testURL, nil)
        if err != nil {
            continue
        }

        resp, err := ws.client.Do(req)
        if err != nil {
            continue
        }

        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        // Check if payload is reflected in response
        if strings.Contains(string(body), payload) {
            vulns = append(vulns, models.WebVulnerability{
                ID:              "XSS001",
                Title:           "Reflected XSS Vulnerability",
                Severity:        "high",
                Description:     "User input is reflected in response without proper encoding",
                Endpoint:        testURL,
                Payload:         payload,
                ConfidenceScore: 0.85,
                DiscoveredAt:    time.Now(),
            })
        }
    }

    return vulns
}

// testCSRF tests for CSRF vulnerabilities
func (ws *WebScanner) testCSRF() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    req, err := http.NewRequestWithContext(ws.config.Context, "GET", ws.config.URL, nil)
    if err != nil {
        return vulns
    }

    resp, err := ws.client.Do(req)
    if err != nil {
        return vulns
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    bodyStr := string(body)

    // Check for CSRF token
    hasCSRFToken := strings.Contains(bodyStr, "csrf") || strings.Contains(bodyStr, "_token")
    
    if !hasCSRFToken {
        vulns = append(vulns, models.WebVulnerability{
            ID:              "CSRF001",
            Title:           "Missing CSRF Protection",
            Severity:        "medium",
            Description:     "Forms appear to lack CSRF token protection",
            Endpoint:        ws.config.URL,
            ConfidenceScore: 0.6,
            DiscoveredAt:    time.Now(),
        })
    }

    return vulns
}

// testSecurityHeaders tests for missing security headers
func (ws *WebScanner) testSecurityHeaders() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    req, err := http.NewRequestWithContext(ws.config.Context, "GET", ws.config.URL, nil)
    if err != nil {
        return vulns
    }

    resp, err := ws.client.Do(req)
    if err != nil {
        return vulns
    }
    defer resp.Body.Close()

    requiredHeaders := map[string]string{
        "X-Content-Type-Options":    "Prevents MIME-type sniffing",
        "X-Frame-Options":           "Prevents clickjacking attacks",
        "Strict-Transport-Security": "Enforces HTTPS",
        "Content-Security-Policy":   "Mitigates XSS attacks",
    }

    for header, description := range requiredHeaders {
        if resp.Header.Get(header) == "" {
            vulns = append(vulns, models.WebVulnerability{
                ID:              fmt.Sprintf("HEADER_%s", strings.ToUpper(header)),
                Title:           fmt.Sprintf("Missing Security Header: %s", header),
                Severity:        "medium",
                Description:     description,
                Endpoint:        ws.config.URL,
                ConfidenceScore: 0.95,
                DiscoveredAt:    time.Now(),
            })
        }
    }

    return vulns
}

// testDirectoryTraversal tests for directory traversal vulnerabilities
func (ws *WebScanner) testDirectoryTraversal() []models.WebVulnerability {
    vulns := make([]models.WebVulnerability, 0)

    payloads := []string{
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
    }

    for _, payload := range payloads {
        testURL := fmt.Sprintf("%s?file=%s", ws.config.URL, url.QueryEscape(payload))
        
        req, err := http.NewRequestWithContext(ws.config.Context, "GET", testURL, nil)
        if err != nil {
            continue
        }

        resp, err := ws.client.Do(req)
        if err != nil {
            continue
        }

        // Check for successful access to sensitive files
        if resp.StatusCode == http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            resp.Body.Close()
            
            if strings.Contains(string(body), "root:") || strings.Contains(string(body), "Administrator") {
                vulns = append(vulns, models.WebVulnerability{
                    ID:              "LFI001",
                    Title:           "Local File Inclusion (LFI)",
                    Severity:        "critical",
                    Description:     "Server appears vulnerable to directory traversal/LFI attacks",
                    Endpoint:        testURL,
                    Payload:         payload,
                    ConfidenceScore: 0.9,
                    DiscoveredAt:    time.Now(),
                })
            }
        }
    }

    return vulns
}

// checkSSL checks SSL/TLS configuration
func (ws *WebScanner) checkSSL() (models.SslCertInfo, error) {
    info := models.SslCertInfo{
        IssuesFound: make([]string, 0),
    }

    u, err := url.Parse(ws.config.URL)
    if err != nil {
        return info, err
    }

    if u.Scheme != "https" {
        info.IsValid = false
        info.IssuesFound = append(info.IssuesFound, "Not using HTTPS")
        return info, nil
    }

    conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        return info, err
    }
    defer conn.Close()

    certs := conn.ConnectionState().PeerCertificates
    if len(certs) > 0 {
        cert := certs[0]
        info.Subject = cert.Subject.String()
        info.Issuer = cert.Issuer.String()
        info.NotBefore = cert.NotBefore
        info.NotAfter = cert.NotAfter
        info.IsValid = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)

        if !info.IsValid {
            info.IssuesFound = append(info.IssuesFound, "Certificate is expired or not yet valid")
        }

        if err := cert.VerifyHostname(u.Hostname()); err != nil {
            info.IssuesFound = append(info.IssuesFound, "Certificate hostname mismatch")
        }
    }

    return info, nil
}

// validateWebURL validates a web URL
func validateWebURL(urlStr string) error {
    u, err := url.Parse(urlStr)
    if err != nil {
        return err
    }

    if u.Scheme == "" {
        return fmt.Errorf("URL must include scheme (http/https)")
    }

    if u.Host == "" {
        return fmt.Errorf("URL must include host")
    }

    return nil
}