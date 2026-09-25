package models

import (
    "context"
    "sync"
    "time"
)

// ScanConfig holds the configuration for network scanning
type ScanConfig struct {
    Target              string
    StartPort           int
    EndPort             int
    Timeout             time.Duration
    RateLimit           int // packets per second
    ThreadCount         int
    UseEvasion          bool
    EvasionMethods      []string // "ack", "fin", "null", "xmas", "fragment", "spoof"
    JSONOutput          string
    Verbose             bool
    IncludeUDP          bool
    ScanFiltered        bool
    Context             context.Context
    Cancel              context.CancelFunc
}

// WebScanConfig holds web vulnerability scan configuration
type WebScanConfig struct {
    URL                 string
    Timeout             time.Duration
    IncludeDeepScan     bool
    CheckCVE            bool
    JSONOutput          string
    Context             context.Context
    Cancel              context.CancelFunc
}

// PortResult represents a single port scan result
type PortResult struct {
    Port            int
    Protocol        string // TCP or UDP
    State           string // open, closed, filtered, open|filtered
    Service         string
    Banner          string
    Confidence      float64 // 0.0 to 1.0
    EvasionMethod   string
    ScannedAt       time.Time
}

// HostResult represents complete scan results for a host
type HostResult struct {
    Target              string
    Timestamp           time.Time
    TotalPorts          int
    OpenPorts           []PortResult
    ClosedPorts         []PortResult
    FilteredPorts       []PortResult
    OpenFilteredPorts   []PortResult
    ScanDuration        time.Duration
    PacketsSent         int
    PacketsReceived     int
    Success             bool
    Error               string
}

// WebVulnerability represents a web vulnerability
type WebVulnerability struct {
    ID              string
    Title           string
    Severity        string // critical, high, medium, low
    Description     string
    CVE             []string
    Endpoint        string
    Payload         string
    Response        string
    Remediation     string
    DetectionMethod string
    ConfidenceScore float64
    DiscoveredAt    time.Time
}

// WebScanResult represents web scan results
type WebScanResult struct {
    URL              string
    Timestamp        time.Time
    Vulnerabilities  []WebVulnerability
    ServerInfo       ServerInfo
    SslCertInfo      SslCertInfo
    ScanDuration     time.Duration
    RequestsSent     int
    Success          bool
    Error            string
}

// ServerInfo contains server information
type ServerInfo struct {
    Server          string
    PoweredBy       string
    XPoweredBy      string
    ContentType     string
    Headers         map[string]string
    Cookies         []string
}

// SslCertInfo contains SSL/TLS certificate information
type SslCertInfo struct {
    Issuer          string
    Subject         string
    NotBefore       time.Time
    NotAfter        time.Time
    IsValid         bool
    IssuesFound     []string
}

// CVEMatch represents a CVE match result
type CVEMatch struct {
    CVEID           string
    Title           string
    Severity        string
    Score           float64
    Description     string
    PublishedDate   time.Time
    ReferencesFound int
}

// ScanState represents the current state of a scan
type ScanState struct {
    mu                  sync.RWMutex
    OpenPorts           int
    ClosedPorts         int
    FilteredPorts       int
    CurrentPort         int
    TotalPorts          int
    PacketsSent         int
    PacketsReceived     int
    StartTime           time.Time
    IsScanning          bool
}

// Progress callback function
type ProgressCallback func(state *ScanState)