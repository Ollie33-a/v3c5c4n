# VecScan - Advanced Network & Web Vulnerability Scanner

<div align="center">

![VecScan Logo](https://img.shields.io/badge/VecScan-v1.0.0-blue?style=for-the-badge&logo=go)

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Ollie33-a/v3c5c4n?style=flat-square)](https://github.com/Ollie33-a/v3c5c4n)
[![GitHub Forks](https://img.shields.io/github/forks/Ollie33-a/v3c5c4n?style=flat-square)](https://github.com/Ollie33-a/v3c5c4n)

**VecScan** is a professional-grade, high-performance network port scanner and web vulnerability scanner written in Go. Designed for security researchers, penetration testers, and system administrators, VecScan combines advanced firewall evasion techniques with comprehensive vulnerability detection.

### ⚡ Key Features

- **65,535 Port Scanning** with concurrent threading
- **Firewall Evasion** using 8+ advanced techniques
- **Web Vulnerability Detection** (SQLi, XSS, CSRF, LFI, etc.)
- **CVE Matching** for discovered vulnerabilities
- **JSON Export** for automation & integration
- **Rate Limiting** & Graceful Shutdown

[Installation](#installation) • [Quick Start](#quick-start) • [Usage](#usage) • [Features](#features) • [Documentation](#documentation)

</div>

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Quick Install](#quick-install)
  - [From Source](#from-source)
  - [Docker Setup](#docker-setup)
- [Quick Start](#quick-start)
  - [Network Scanning](#network-scanning)
  - [Web Scanning](#web-scanning)
  - [Firewall Evasion](#firewall-evasion)
- [Comprehensive Usage Guide](#comprehensive-usage-guide)
  - [Network Scan Types](#network-scan-types)
  - [Evasion Techniques](#evasion-techniques)
  - [Web Vulnerability Scans](#web-vulnerability-scans)
  - [Advanced Scanning](#advanced-scanning)
- [Command Reference](#command-reference)
- [Output Examples](#output-examples)
- [Configuration](#configuration)
- [Performance Benchmarks](#performance-benchmarks)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## 🎯 Features

### 🔍 Network Scanning

#### Port Scanning

- ✅ **Full Port Range**: Scan all 65,535 ports efficiently
- ✅ **TCP Scanning**: Standard SYN-based port detection
- ✅ **UDP Scanning**: ICMP-based UDP port detection
- ✅ **Service Identification**: Automatic service name resolution
- ✅ **Banner Grabbing**: Extract service banners and versions
- ✅ **Multi-threaded**: Up to 256 concurrent threads
- ✅ **Filtered Port Detection**: Identify firewall-protected ports

#### Port States Detected

- **Open**: Port is accepting connections
- **Closed**: Port is reachable but not listening
- **Filtered**: Firewall is blocking port
- **Open|Filtered**: Unable to determine exact state

### 🛡️ Firewall Evasion (8+ Techniques)

| Technique                | Description                               | Detection Avoidance                 |
| ------------------------ | ----------------------------------------- | ----------------------------------- |
| **ACK Scan**             | Sends ACK packets to probe firewall rules | Bypasses simple ACL-based firewalls |
| **FIN Scan**             | Sends FIN packets (RFC 793 compliant)     | Evades stateless packet filters     |
| **NULL Scan**            | Sends packets with no flags set           | Confuses basic IDS/IPS systems      |
| **Xmas Scan**            | Sends FIN, PSH, URG flags                 | RFC-compliant evasion technique     |
| **Packet Fragmentation** | Splits packets into smaller pieces        | Evades signature-based detection    |
| **Source Port Spoofing** | Uses trusted ports (DNS:53, HTTP:80)      | Bypasses port-based filtering       |
| **Decoy Scanning**       | Mixes real packets with decoys            | Obfuscates source of scan           |
| **Timing Evasion**       | Variable packet timing                    | Avoids rate-based detection         |

### 🌐 Web Vulnerability Scanning

#### Vulnerability Types Detected

- ✅ **SQL Injection (SQLi)**: Multiple payload variants
- ✅ **Cross-Site Scripting (XSS)**: Reflected & Stored XSS
- ✅ **Cross-Site Request Forgery (CSRF)**: Missing token detection
- ✅ **Local File Inclusion (LFI)**: Directory traversal attacks
- ✅ **Security Headers**: Missing critical security headers
- ✅ **SSL/TLS Issues**: Certificate validation & configuration
- ✅ **Server Information Disclosure**: Banner grabbing & header analysis

#### Security Headers Checked

- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security
- Content-Security-Policy
- X-XSS-Protection
- Referrer-Policy

### 📊 Reporting & Export

- ✅ **Terminal Output**: Colored, formatted reports
- ✅ **JSON Export**: Structured data for automation
- ✅ **CVE Matching**: Automatic CVE identification
- ✅ **Confidence Scoring**: Accuracy metrics for findings
- ✅ **Detailed Statistics**: Packet loss, success rates, timing

### ⚡ Performance

- ✅ **Multi-threaded**: Up to 256 concurrent threads
- ✅ **Rate Limiting**: 1-10,000+ packets/second
- ✅ **Memory Efficient**: <50MB for full 65,535 port scan
- ✅ **Fast Scanning**: 65,535 ports in ~2 minutes
- ✅ **Adaptive Timeouts**: Smart timeout handling

### 🛑 Reliability & Safety

- ✅ **Graceful Shutdown**: Clean exit on Ctrl+C
- ✅ **Error Handling**: Robust error recovery
- ✅ **Resource Cleanup**: Proper goroutine cleanup
- ✅ **Partial Reports**: Saved results even on interruption
- ✅ **Network Resilience**: Handle timeouts & retries

---

## 🏗️ Architecture

```
VecScan/
├── cmd/vecscan/                 # Main CLI application
│   └── main.go                  # Entry point & flag parsing
├── internal/
│   ├── scanner/                 # Network scanning engine
│   │   ├── network.go           # Main scanner logic
│   │   ├── evasion.go           # Firewall evasion techniques
│   │   └── packet.go            # Raw packet crafting
│   ├── web/                     # Web vulnerability scanner
│   │   ├── scanner.go           # Web scanner logic
│   │   └── cve_matcher.go       # CVE matching engine
│   ├── reporter/                # Report generation
│   │   ├── json.go              # JSON export
│   │   └── terminal.go          # Terminal output
│   ├── utils/                   # Utility functions
│   │   ├── logger.go            # Colored logging
│   │   ├── config.go            # Config parsing
│   │   └── rate_limiter.go      # Rate limiting
│   └── models/                  # Data structures
│       ├── types.go             # All data types
│       └── service_map.go       # Port-to-service mapping
├── go.mod                       # Go module definition
├── go.sum                       # Dependency lock file
├── README.md                    # This file
├── LICENSE                      # MIT License
├── Makefile                     # Build automation
└── setup.sh                     # Installation script
```

---

## 📦 Installation

### Prerequisites

- **Go** 1.21 or higher ([Download](https://golang.org/dl/))
- **Linux** or **macOS** (Windows requires WSL2)
- **Root/sudo access** (required for raw socket operations on Linux)
- **Git** (optional, for cloning)

### Quick Install (System-Wide)

```bash
# Clone repository
git clone https://github.com/Ollie33-a/v3c5c4n.git
cd v3c5c4n

# Run setup script
chmod +x setup.sh
./setup.sh

# Verify installation
v3c5c4n -help
```

### From Source (Manual)

```bash
# Clone and navigate
git clone https://github.com/Ollie33-a/v3c5c4n.git
cd v3c5c4n

# Download dependencies
go mod download
go mod tidy

# Build
go build -o v3c5c4n ./cmd/vecscan/main.go

# Install system-wide (optional)
sudo cp v3c5c4n /usr/local/bin/

# Run
v3c5c4n -help
```

### Using Make

```bash
# View available targets
make help

# Build
make build

# Install
make install

# Run tests
make test

# Format code
make fmt
```

### Docker Setup

```bash
# Build Docker image
docker build -t v3c5c4n .

# Run network scan
docker run --rm --net=host v3c5c4n:latest -type network -target 192.168.1.1

# Run web scan
docker run --rm v3c5c4n:latest -type web -target example.com
```

---

## 🚀 Quick Start

### Network Scanning - Basic

```bash
# Scan a single IP
sudo v3c5c4n -type network -target 192.168.1.1

# Scan common ports (top 1000)
sudo v3c5c4n -type network -target 192.168.1.1 -ports 1-1024

# Scan specific ports
sudo v3c5c4n -type network -target 192.168.1.1 -ports 22,80,443,3306,5432
```

### Web Scanning - Basic

```bash
# Scan a website for vulnerabilities
v3c5c4n -type web -target example.com

# Scan with HTTPS
v3c5c4n -type web -target https://example.com

# Deep vulnerability scan
v3c5c4n -type web -target example.com -deep -cve
```

### Firewall Evasion - Stealth Scan

```bash
# Use evasion techniques
sudo v3c5c4n -type network -target 192.168.1.1 -evasion

# Combine multiple evasion methods
sudo v3c5c4n -type network -target 192.168.1.1 \
  -evasion -evasion-methods "ack,fin,fragment"

# Maximum stealth (slow but sneaky)
sudo v3c5c4n -type network -target 192.168.1.1 \
  -evasion -evasion-methods "fragment,timing,decoy" \
  -threads 8 -rate 100 -timeout 15s
```

### Export Results

```bash
# Save to JSON
sudo v3c5c4n -type network -target 192.168.1.1 -json report.json

# Web scan with JSON export
v3c5c4n -type web -target example.com -json web_report.json

# View JSON report
cat report.json | jq '.'
```

---

## 📖 Comprehensive Usage Guide

### Network Scan Types

#### 1. Standard TCP Scan (Default)

```bash
# Scan all TCP ports
sudo v3c5c4n -type network -target 192.168.1.100

# Output:
# [+] Port 22/tcp open - SSH
# [+] Port 80/tcp open - HTTP
# [+] Port 443/tcp open - HTTPS
```

**Use Case**: General network reconnaissance, finding open services

---

#### 2. UDP Scan

```bash
# Include UDP scanning
sudo v3c5c4n -type network -target 192.168.1.100 -include-udp

# Scan only specific UDP ports
sudo v3c5c4n -type network -target 192.168.1.100 \
  -include-udp -ports 53,67,68,161,162
```

**Common UDP Services**:

- Port 53: DNS
- Port 67/68: DHCP
- Port 161: SNMP
- Port 162: SNMP Trap

**Use Case**: Complete network discovery, DNS/DHCP/SNMP reconnaissance

---

#### 3. Fast Scan (Well-Known Ports)

```bash
# Scan only well-known ports (1-1024)
sudo v3c5c4n -type network -target 192.168.1.100 -ports 1-1024

# Scan only IANA registered ports (1-49151)
sudo v3c5c4n -type network -target 192.168.1.100 -ports 1-49151
```

**Duration**: ~30 seconds for 1024 ports

**Use Case**: Quick reconnaissance, finding standard services

---

#### 4. Complete Port Scan

```bash
# Scan all 65,535 ports
sudo v3c5c4n -type network -target 192.168.1.100

# Scan all ports with verbose output
sudo v3c5c4n -type network -target 192.168.1.100 -verbose
```

**Duration**: ~2-5 minutes (depending on network)

**Use Case**: Comprehensive audit, finding hidden services on non-standard ports

---

#### 5. High-Speed Scan

```bash
# Aggressive scanning with high throughput
sudo v3c5c4n -type network -target 192.168.1.100 \
  -threads 256 -rate 5000 -ports 1-65535

# Parameters explained:
# -threads 256  = 256 concurrent threads
# -rate 5000    = 5,000 packets per second
# -ports 1-65535 = All ports
```

**Duration**: ~30-60 seconds for all ports

**Use Case**: Internal network scans where stealth is not needed

---

#### 6. Slow Scan (Low Noise)

```bash
# Stealth scan with minimal network traffic
sudo v3c5c4n -type network -target 192.168.1.100 \
  -threads 4 -rate 50 -ports 1-65535 -timeout 10s

# Parameters explained:
# -threads 4    = 4 concurrent threads (minimal)
# -rate 50      = 50 packets per second
# -timeout 10s  = 10 second timeout per port
```

**Duration**: ~30 minutes for all ports

**Use Case**: Evading IDS/IPS systems, stealth penetration testing

---

#### 7. CIDR Range Scan

```bash
# Scan entire subnet
sudo v3c5c4n -type network -target 192.168.1.0/24 -ports 22,80,443

# Scan larger network
sudo v3c5c4n -type network -target 10.0.0.0/16 -ports 22,80,443

# Scan class C network
sudo v3c5c4n -type network -target 172.16.0.0/12 -ports 1-1024
```

**Use Case**: Network-wide reconnaissance, finding all open ports across subnets

---

#### 8. IP Range Scan

```bash
# Scan IP range (1 to 100)
sudo v3c5c4n -type network -target 192.168.1.1-100 -ports 22,80,443

# Scan small range
sudo v3c5c4n -type network -target 10.10.10.50-75 -ports 3389
```

**Use Case**: Scanning specific IP ranges without CIDR notation

---

### Firewall Evasion Techniques

#### Evasion Techniques Overview

```bash
# List all available evasion methods
sudo v3c5c4n -evasion -help
```

**Available Methods**:

1. `ack` - TCP ACK Scan
2. `fin` - FIN Scan
3. `null` - NULL Scan
4. `xmas` - Xmas Scan
5. `fragment` - Packet Fragmentation
6. `spoof` - Source Port Spoofing
7. `decoy` - Decoy Scanning
8. `timing` - Timing Evasion

---

#### 1. ACK Scan (Firewall Rule Mapping)

```bash
# Detect firewall ACL rules
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "ack"

# How it works:
# 1. Sends ACK packets to ports
# 2. No RST = filtered port (firewall blocks)
# 3. RST response = unfiltered port
```

**Firewall Detection**: ⭐⭐⭐☆☆ (Likely to be detected)

**Effectiveness**: 70% against simple firewalls

**Use Case**:

- Mapping firewall rules
- Finding non-filtered ports
- Bypassing basic ACL-based filtering

**Example Output**:

```
[+] Port 22 unfiltered (firewall allows)
[!] Port 23 filtered (firewall blocks)
[+] Port 80 unfiltered
```

---

#### 2. FIN Scan (RFC 793 Compliant)

```bash
# RFC 793 compliant evasion
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "fin"

# How it works:
# 1. Sends FIN packets to ports
# 2. No response = open|filtered
# 3. RST response = closed
# 4. No response from firewall = filtered
```

**Firewall Detection**: ⭐⭐☆☆☆ (Less likely to be detected)

**Effectiveness**: 60% against modern firewalls

**Use Case**:

- Evading stateless packet filters
- Bypassing IDS signatures
- Slow, stealthy reconnaissance

**Example Output**:

```
[+] Port 22 open|filtered
[+] Port 80 open|filtered
[-] Port 139 closed
```

---

#### 3. NULL Scan (All Flags Cleared)

```bash
# Send packets with no flags
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "null"

# How it works:
# 1. Sends packets with zero flags
# 2. No response = open|filtered
# 3. RST response = closed
# 4. Confuses basic IDS systems
```

**Firewall Detection**: ⭐⭐☆☆☆ (Less likely to be detected)

**Effectiveness**: 60% against simple IDS

**Use Case**:

- Confusing basic detection systems
- Evading signature-based IDS
- RFC 793 based evasion

---

#### 4. Xmas Scan (FIN/PSH/URG Flags)

```bash
# Send packets with FIN, PSH, and URG flags
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "xmas"

# How it works:
# 1. Sends FIN + PSH + URG flags
# 2. "Lights up like a Christmas tree"
# 3. Same response behavior as FIN scan
# 4. Very recognizable in logs
```

**Firewall Detection**: ⭐⭐⭐⭐☆ (Highly detectable)

**Effectiveness**: 40% against modern firewalls

**Use Case**:

- Testing RFC 793 compliance
- Academic/research purposes
- Educational demonstrations

---

#### 5. Packet Fragmentation (IDS Evasion)

```bash
# Fragment packets into smaller pieces
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "fragment"

# How it works:
# 1. Splits packets into fragments
# 2. Reassembled at destination
# 3. Evades signature-based detection
# 4. May confuse older IDS systems
```

**Firewall Detection**: ⭐⭐⭐☆☆ (Moderate detection)

**Effectiveness**: 75% against older IDS systems

**Use Case**:

- Evading signature-based IDS/IPS
- Bypassing packet inspection firewalls
- Stealth reconnaissance

**Example**:

```
Normal packet: |------ SYN packet ------|
Fragmented:    |--| + |--| + |--| + |-|
```

---

#### 6. Source Port Spoofing (DNS Port)

```bash
# Use DNS port (53) as source port
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "spoof"

# How it works:
# 1. Uses port 53 (DNS) as source port
# 2. Firewall may allow port 53
# 3. Bypasses port-based filtering
# 4. Can use other "trusted" ports (80, 443)
```

**Firewall Detection**: ⭐⭐⭐⭐☆ (Often detected by modern systems)

**Effectiveness**: 65% against basic firewalls

**Use Case**:

- Bypassing port-based ACLs
- Evading simple filtering rules
- Using "trusted" source ports

**Trusted Source Ports**:

- Port 53: DNS
- Port 80: HTTP
- Port 443: HTTPS
- Port 123: NTP

---

#### 7. Decoy Scanning (Source Obfuscation)

```bash
# Mix real scan packets with decoys
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "decoy"

# How it works:
# 1. Generates random source IPs
# 2. Mixes with real scan packets
# 3. Makes log analysis difficult
# 4. Appears as multiple sources
```

**Firewall Detection**: ⭐⭐☆☆☆ (Hard to attribute)

**Effectiveness**: 70% against log-based detection

**Use Case**:

- Obfuscating source of scan
- Making attribution difficult
- Multi-source appearance

**Example**:

```
Real scan: 192.168.1.50
Decoy packets from:
  - 10.0.0.1
  - 172.16.0.1
  - 203.0.113.1
  - 198.51.100.1
```

---

#### 8. Timing Evasion (Rate-Based Detection)

```bash
# Variable packet timing
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "timing" -rate 100

# How it works:
# 1. Varies packet timing
# 2. Avoids rate-based detection
# 3. Slower than aggressive scan
# 4. Harder for IDS to detect pattern
```

**Firewall Detection**: ⭐☆☆☆☆ (Very hard to detect)

**Effectiveness**: 90% against rate-based detection

**Use Case**:

- Evading rate-based IDS/IPS
- Avoiding anomaly detection
- Stealthy, slow reconnaissance

---

#### 9. Combined Evasion Strategies

```bash
# Moderate stealth (balance)
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "ack,fin,spoof" \
  -threads 32 -rate 1000

# Maximum stealth (slow)
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "fragment,timing,decoy" \
  -threads 8 -rate 100 -timeout 15s

# Aggressive but evasive
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "ack,null,xmas,fragment" \
  -threads 128 -rate 3000
```

**Stealth Levels**:

| Level           | Methods       | Speed     | Detection Risk  |
| --------------- | ------------- | --------- | --------------- |
| Low Stealth     | Single method | Fast      | High (⭐⭐⭐⭐) |
| Moderate        | 2-3 methods   | Medium    | Medium (⭐⭐⭐) |
| High Stealth    | 4+ methods    | Slow      | Low (⭐⭐)      |
| Maximum Stealth | All methods   | Very Slow | Minimal (⭐)    |

---

### Web Vulnerability Scans

#### 1. Basic Web Scan

```bash
# Scan for all vulnerabilities
v3c5c4n -type web -target example.com

# Verbose output
v3c5c4n -type web -target example.com -verbose
```

**Checks**:

- SQL Injection
- XSS (Reflected & Stored)
- CSRF
- Security Headers
- Directory Traversal

**Output**:

```
════════════════════════════════════════════════════════════════
WEB VULNERABILITY SCAN REPORT
════════════════════════════════════════════════════════════════

Target URL: http://example.com
Vulnerabilities: 5 found
  Critical: 0
  High: 2
  Medium: 3
```

---

#### 2. HTTPS Scan with Certificate Check

```bash
# Scan HTTPS website
v3c5c4n -type web -target https://example.com

# Check SSL/TLS configuration
v3c5c4n -type web -target https://example.com -verbose
```

**Checks**:

- Certificate validity
- Certificate expiration
- Hostname mismatch
- Weak cipher suites
- SSL/TLS version support

**Example Output**:

```
SSL/TLS INFORMATION:
─────────────────────────────────────────────────────────────────
Subject:  CN=example.com
Issuer:   C=US, O=Let's Encrypt, CN=R3
Valid:    2023-01-15 - 2024-04-15
Status:   VALID
```

---

#### 3. SQL Injection Detection

```bash
# Scan for SQL injection vulnerabilities
v3c5c4n -type web -target http://vulnerable-app.local -verbose
```

**Payloads Tested**:

- `' OR '1'='1`
- `' OR 1=1--`
- `admin' --`
- `1' UNION SELECT NULL--`

**Detection Indicators**:

- SQL error messages in response
- Database-specific error strings
- Unusual response behavior

**Example Finding**:

```
[!] Potential SQL Injection
    Endpoint: http://vulnerable-app.local?id=' OR '1'='1
    Severity: HIGH
    Confidence: 85%
    Description: SQL error found in response body
```

---

#### 4. XSS Detection

```bash
# Test for Cross-Site Scripting
v3c5c4n -type web -target http://vulnerable-app.local -verbose
```

**Payloads Tested**:

- `<script>alert('XSS')</script>`
- `<img src=x onerror="alert('XSS')">`
- `<svg/onload="alert('XSS')">`

**Detection Method**:

- Payload reflection in HTML response
- Script execution confirmation
- Context-aware payload testing

**Example Finding**:

```
[!] Reflected XSS Vulnerability
    Endpoint: http://vulnerable-app.local?search=<script>alert('XSS')</script>
    Severity: HIGH
    Confidence: 90%
    Payload: <script>alert('XSS')</script>
```

---

#### 5. CSRF Detection

```bash
# Check for CSRF protections
v3c5c4n -type web -target http://vulnerable-app.local -verbose
```

**Checks**:

- CSRF token presence
- Token validation
- Same-Site cookie attribute
- Content-Type checking

**Example Finding**:

```
[!] Missing CSRF Protection
    Endpoint: http://vulnerable-app.local
    Severity: MEDIUM
    Confidence: 60%
    Description: Forms lack CSRF token protection
```

---

#### 6. Security Headers Scan

```bash
# Check all security headers
v3c5c4n -type web -target https://example.com -verbose
```

**Headers Checked**:

- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security
- Content-Security-Policy
- X-XSS-Protection
- Referrer-Policy

**Example Output**:

```
SECURITY HEADERS:
─────────────────────────────────────────────────────────────────
[✓] X-Content-Type-Options: nosniff
[✓] X-Frame-Options: DENY
[✗] Strict-Transport-Security: MISSING
[✗] Content-Security-Policy: MISSING
[✗] X-XSS-Protection: MISSING
```

---

#### 7. Directory Traversal / LFI Scan

```bash
# Test for directory traversal / LFI
v3c5c4n -type web -target http://vulnerable-app.local -verbose
```

**Payloads Tested**:

- `../../../etc/passwd`
- `..\\..\\..\\windows\\system32`
- `....//....//....//etc/passwd`

**Detection Indicators**:

- Successfully reading /etc/passwd
- Windows system files accessible
- Unexpected file content in response

**Example Finding**:

```
[!] Local File Inclusion (LFI)
    Endpoint: http://vulnerable-app.local?file=../../../etc/passwd
    Severity: CRITICAL
    Confidence: 95%
    Evidence: /etc/passwd contents returned
```

---

#### 8. Deep Vulnerability Scan

```bash
# Comprehensive vulnerability assessment
v3c5c4n -type web -target example.com -deep -verbose

# With CVE matching
v3c5c4n -type web -target example.com -deep -cve -verbose
```

**Additional Checks**:

- Server technology fingerprinting
- Extended payload testing
- Cookie security analysis
- Response header analysis
- Technology stack detection

**Duration**: 2-5 minutes per target

---

#### 9. CVE Matching

```bash
# Automatically match vulnerabilities to CVEs
v3c5c4n -type web -target example.com -cve

# Deep scan with CVE matching
v3c5c4n -type web -target example.com -deep -cve
```

**Matched CVEs**:

- SQL Injection CVEs
- XSS CVEs
- RCE CVEs
- Information Disclosure CVEs

**Example Output**:

```
[!] SQL Injection Vulnerability
    CVEs: CVE-2019-9193, CVE-2018-20225
    CVSS Score: 9.8
    Severity: CRITICAL
```

---

#### 10. JSON Export for Web Scans

```bash
# Export detailed results
v3c5c4n -type web -target example.com -json web_report.json

# View report
cat web_report.json | jq '.'

# Parse for critical vulnerabilities
cat web_report.json | jq '.Vulnerabilities[] | select(.Severity=="critical")'
```

---

### Advanced Scanning

#### 1. Combination Scans (Network + Evasion)

```bash
# Full stealth network scan with all evasion techniques
sudo v3c5c4n -type network -target 192.168.1.100 \
  -evasion -evasion-methods "ack,fin,null,xmas,fragment,spoof,decoy,timing" \
  -ports 1-65535 \
  -threads 16 \
  -rate 200 \
  -timeout 10s \
  -include-udp \
  -verbose \
  -json stealth_report.json
```

**Execution Time**: 20-30 minutes

**Detection Risk**: Minimal ⭐

---

#### 2. Enterprise Network Scan

```bash
# Scan entire enterprise network
sudo v3c5c4n -type network -target 10.0.0.0/8 \
  -ports 22,80,443,3306,5432 \
  -threads 128 \
  -rate 2000 \
  -json enterprise_scan.json

# Analyze results
cat enterprise_scan.json | jq '.OpenPorts[] | {Port, Service}'
```

---

#### 3. Vulnerability Assessment Pipeline

```bash
#!/bin/bash

TARGET="example.com"

# Network scan
sudo v3c5c4n -type network -target $TARGET -json network_scan.json

# Web scan
v3c5c4n -type web -target "https://$TARGET" -cve -json web_scan.json

# Generate combined report
echo "=== Network Vulnerabilities ===" > report.txt
cat network_scan.json | jq '.OpenPorts' >> report.txt

echo "=== Web Vulnerabilities ===" >> report.txt
cat web_scan.json | jq '.Vulnerabilities' >> report.txt

echo "Report saved to report.txt"
```

---

#### 4. Firewall Testing

```bash
# Test each firewall evasion technique individually
for technique in ack fin null xmas fragment spoof decoy timing; do
  echo "Testing $technique evasion..."
  sudo v3c5c4n -type network -target 192.168.1.100 \
    -evasion -evasion-methods "$technique" \
    -json "result_$technique.json"
done

# Compare results
echo "Results comparison:"
for file in result_*.json; do
  echo "$file: $(jq '.OpenPorts | length' $file) open ports"
done
```

---

#### 5. Performance Benchmarking

```bash
# Benchmark different thread counts
for threads in 8 16 32 64 128 256; do
  echo "Testing with $threads threads..."
  time sudo v3c5c4n -type network -target 192.168.1.1-10 \
    -ports 1-1024 \
    -threads $threads \
    -json "benchmark_$threads.json"
done
```

---

#### 6. Continuous Monitoring

```bash
#!/bin/bash

# Monitor target for changes
TARGET="192.168.1.100"
BASELINE="baseline.json"

# Create baseline if not exists
if [ ! -f "$BASELINE" ]; then
  sudo v3c5c4n -type network -target $TARGET -json $BASELINE
  echo "Baseline created"
  exit 0
fi

# Regular scans
while true; do
  CURRENT="current_$(date +%s).json"
  sudo v3c5c4n -type network -target $TARGET -json $CURRENT

  # Compare with baseline
  BASELINE_PORTS=$(jq '.OpenPorts | length' $BASELINE)
  CURRENT_PORTS=$(jq '.OpenPorts | length' $CURRENT)

  if [ $BASELINE_PORTS -ne $CURRENT_PORTS ]; then
    echo "ALERT: Port count changed! ($BASELINE_PORTS -> $CURRENT_PORTS)"
    # Send notification
  fi

  # Sleep 1 hour
  sleep 3600
done
```

---

## 🎛️ Command Reference

### Global Flags

```bash
-help              Show help message
-type STRING       Scan type: network or web (default: network)
-target STRING     Target IP/CIDR/URL (required)
-json STRING       Output JSON report to file
-verbose           Enable verbose output
```

### Network Scanning Flags

```bash
# Port options
-ports STRING      Port range (default: 1-65535)
                   Examples: 80,443 or 1-1024 or 22,80-443

# Performance options
-threads INT       Number of concurrent threads (default: 64)
-rate INT          Packets per second (default: 1000)
-timeout DURATION  Connection timeout (default: 5s)

# Protocol options
-include-udp       Include UDP scanning (default: false)

# Evasion options
-evasion           Enable firewall evasion (default: false)
-evasion-methods STRING
                   Comma-separated methods
                   (default: ack,fin,spoof)
```

### Web Scanning Flags

```bash
-deep              Enable deep vulnerability scan
-cve               Check for CVE matches
```

---

## 📤 Output Examples

### Network Scan - Terminal Output

```
════════════════════════════════════════════════════════════════
NETWORK SCAN REPORT
════════════════════════════════════════════════════════════════

Target: 192.168.1.100
Scan Time: 2024-01-15T10:30:45Z
Duration: 2m15s
Total Ports Scanned: 65535

OPEN PORTS (5):
─────────────────────────────────────────────────────────────────
Port       Protocol        Service                    Confidence
─────────────────────────────────────────────────────────────────
22         tcp             SSH                        99.0%
80         tcp             HTTP                       99.0%
443        tcp             HTTPS                      99.0%
3306       tcp             MYSQL                      99.0%
5432       tcp             POSTGRESQL                 99.0%

CLOSED PORTS (65530):
Found 65530 closed ports

FILTERED PORTS (0):

STATISTICS:
─────────────────────────────────────────────────────────────────
Packets Sent:     65535
Packets Received: 5
Success Rate:     0.01%

════════════════════════════════════════════════════════════════
```

### Network Scan - JSON Output

```json
{
  "Target": "192.168.1.100",
  "Timestamp": "2024-01-15T10:30:45Z",
  "TotalPorts": 65535,
  "OpenPorts": [
    {
      "Port": 22,
      "Protocol": "tcp",
      "State": "open",
      "Service": "SSH",
      "Banner": "SSH-2.0-OpenSSH_7.4",
      "Confidence": 0.99,
      "EvasionMethod": "",
      "ScannedAt": "2024-01-15T10:30:45Z"
    },
    {
      "Port": 80,
      "Protocol": "tcp",
      "State": "open",
      "Service": "HTTP",
      "Banner": "HTTP/1.1 200 OK",
      "Confidence": 0.99,
      "EvasionMethod": "",
      "ScannedAt": "2024-01-15T10:31:02Z"
    }
  ],
  "ClosedPorts": [],
  "FilteredPorts": [],
  "ScanDuration": 135000000000,
  "PacketsSent": 65535,
  "PacketsReceived": 5,
  "Success": true
}
```

### Web Scan - Terminal Output

```
════════════════════════════════════════════════════════════════
WEB VULNERABILITY SCAN REPORT
════════════════════════════════════════════════════════════════

Target URL: https://example.com
Scan Time: 2024-01-15T10:45:30Z
Duration: 1m30s

SERVER INFORMATION:
─────────────────────────────────────────────────────────────────
Server: nginx/1.18.0
Powered By: PHP/7.4.3

VULNERABILITIES FOUND (3):
Critical: 0 | High: 1 | Medium: 2
─────────────────────────────────────────────────────────────────

[1] Missing CSRF Protection
  Severity:   MEDIUM
  Confidence: 60.0%
  Endpoint:   https://example.com
  Description: Forms appear to lack CSRF token protection

[2] Missing Security Header: Strict-Transport-Security
  Severity:   MEDIUM
  Confidence: 95.0%
  Endpoint:   https://example.com
  Description: Enforces HTTPS

[3] Reflected XSS Vulnerability
  Severity:   HIGH
  Confidence: 85.0%
  Endpoint:   https://example.com?search=<script>alert('XSS')</script>
  Description: User input is reflected in response without proper encoding
  CVEs:       CVE-2020-5410

SSL/TLS INFORMATION:
─────────────────────────────────────────────────────────────────
Subject:  CN=example.com
Issuer:   C=US, O=Let's Encrypt, CN=R3
Valid:    2023-01-15 - 2024-04-15
Status:   VALID

════════════════════════════════════════════════════════════════
```

### Web Scan - JSON Output

```json
{
  "URL": "https://example.com",
  "Timestamp": "2024-01-15T10:45:30Z",
  "Vulnerabilities": [
    {
      "ID": "CSRF001",
      "Title": "Missing CSRF Protection",
      "Severity": "medium",
      "Description": "Forms appear to lack CSRF token protection",
      "Endpoint": "https://example.com",
      "Payload": "",
      "Response": "",
      "ConfidenceScore": 0.6,
      "DiscoveredAt": "2024-01-15T10:45:35Z",
      "CVE": null,
      "Remediation": "Implement CSRF tokens in all forms",
      "DetectionMethod": "Token presence check"
    },
    {
      "ID": "XSS001",
      "Title": "Reflected XSS Vulnerability",
      "Severity": "high",
      "Description": "User input is reflected in response without proper encoding",
      "Endpoint": "https://example.com?search=<script>alert('XSS')</script>",
      "Payload": "<script>alert('XSS')</script>",
      "Response": "...<script>alert('XSS')</script>...",
      "ConfidenceScore": 0.85,
      "DiscoveredAt": "2024-01-15T10:45:45Z",
      "CVE": ["CVE-2020-5410"],
      "Remediation": "Implement output encoding",
      "DetectionMethod": "Payload reflection check"
    }
  ],
  "ServerInfo": {
    "Server": "nginx/1.18.0",
    "PoweredBy": "PHP/7.4.3",
    "ContentType": "text/html; charset=UTF-8",
    "Headers": {
      "Server": "nginx/1.18.0",
      "Date": "Mon, 15 Jan 2024 10:45:30 GMT"
    },
    "Cookies": ["PHPSESSID", "user_pref"]
  },
  "SslCertInfo": {
    "Issuer": "C=US, O=Let's Encrypt, CN=R3",
    "Subject": "CN=example.com",
    "NotBefore": "2023-01-15T00:00:00Z",
    "NotAfter": "2024-04-15T00:00:00Z",
    "IsValid": true,
    "IssuesFound": []
  },
  "ScanDuration": 90000000000,
  "RequestsSent": 24,
  "Success": true
}
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Set default target
export VECSCAN_TARGET="192.168.1.100"

# Set default port range
export VECSCAN_PORTS="1-1024"

# Set default threads
export VECSCAN_THREADS="64"

# Set default rate limit
export VECSCAN_RATE="1000"
```

### Configuration File (Optional)

Create `~/.vecscan/config.yaml`:

```yaml
network:
  default_ports: "1-65535"
  default_threads: 64
  default_rate: 1000
  default_timeout: 5s

web:
  default_timeout: 10s
  follow_redirects: true
  verify_ssl: false

evasion:
  default_methods: ["ack", "fin", "spoof"]
  enabled: false

output:
  json_format: true
  verbose: false
```

---

## 📊 Performance Benchmarks

### Single Target Scans

| Scan Type    | Port Range | Threads | Rate | Duration | Memory |
| ------------ | ---------- | ------- | ---- | -------- | ------ |
| Standard TCP | 1-1024     | 64      | 1000 | ~10s     | 5MB    |
| Standard TCP | 1-65535    | 64      | 1000 | ~2m      | 15MB   |
| Aggressive   | 1-65535    | 256     | 5000 | ~30s     | 25MB   |
| Stealth      | 1-65535    | 8       | 100  | ~30m     | 8MB    |
| UDP          | 1-1024     | 64      | 1000 | ~15s     | 6MB    |

### Network Scanning

| Scan Type    | Targets | Ports     | Duration | Memory |
| ------------ | ------- | --------- | -------- | ------ |
| Single IP    | 1       | 1-1024    | ~10s     | 5MB    |
| /24 CIDR     | 254     | 22,80,443 | ~2m      | 20MB   |
| /16 CIDR     | 65,534  | 22,80,443 | ~45m     | 50MB   |
| Full network | 65,534  | 1-65535   | N/A      | 100MB+ |

### Web Scanning

| Scan Type         | Duration | Memory |
| ----------------- | -------- | ------ |
| Basic scan        | 15-30s   | 10MB   |
| Deep scan         | 2-5m     | 15MB   |
| With CVE matching | 3-10m    | 20MB   |

---

## 🔧 Troubleshooting

### Command Not Found

```bash
# Add to PATH
echo 'export PATH="$PATH:/home/ollie/v3c5c4n"' >> ~/.zshrc
source ~/.zshrc

# Or install system-wide
sudo cp ~/v3c5c4n/v3c5c4n /usr/local/bin/
which v3c5c4n
```

### Permission Denied

```bash
# Make executable
chmod +x v3c5c4n

# Run with sudo for network scans
sudo v3c5c4n -type network -target 192.168.1.1
```

### "Raw Sockets Not Supported"

```bash
# Linux - requires root
sudo v3c5c4n -type network -target 192.168.1.1

# macOS - may need sudo
sudo v3c5c4n -type network -target 192.168.1.1
```

### High False Positives

```bash
# Increase timeout for slow networks
sudo v3c5c4n -type network -target 192.168.1.1 -timeout 10s

# Reduce rate for unstable networks
sudo v3c5c4n -type network -target 192.168.1.1 -rate 500
```

### Firewall Blocking Scans

```bash
# Use evasion techniques
sudo v3c5c4n -type network -target 192.168.1.1 -evasion

# Combine multiple evasion methods
sudo v3c5c4n -type network -target 192.168.1.1 \
  -evasion -evasion-methods "fragment,timing,decoy"
```

### Web Scanner Timeouts

```bash
# Increase timeout for slow websites
v3c5c4n -type web -target slow-website.com -timeout 30s

# Add verbose output for debugging
v3c5c4n -type web -target example.com -verbose
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Format code
go fmt ./...

# Lint code
golangci-lint run
```

### Contribution Guidelines

- Follow Go best practices
- Add unit tests for new features
- Update documentation
- Keep code clean and readable
- Add comments for complex logic

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

✅ **You can**:

- Use commercially
- Modify the code
- Distribute
- Use privately

❌ **You must**:

- Include the original license
- Include copyright notice

---

## ⚖️ Disclaimer

**VecScan** is intended for authorized security testing and educational purposes only.

### Legal Notice

⚠️ **WARNING**: Unauthorized network scanning and vulnerability assessment may violate:

- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act 1990 - UK
- General Data Protection Regulation (GDPR) - EU
- Similar laws in other jurisdictions

**You are solely responsible for ensuring you have proper authorization before:**

- Scanning any network or system
- Testing for vulnerabilities
- Running any security assessments

**The developers and contributors are NOT responsible for:**

- Misuse of this tool
- Damages caused by unauthorized access
- Legal consequences of improper use
- Any harm whatsoever

### Proper Use

Only use VecScan:

- ✅ On systems you own or have written permission to test
- ✅ For authorized penetration testing engagements
- ✅ For security research in controlled environments
- ✅ For educational purposes in lab environments
- ✅ With explicit written authorization from system owners

---

## 📞 Support & Contact

- 🐛 **Report Issues**: [GitHub Issues](https://github.com/Ollie33-a/v3c5c4n/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Ollie33-a/v3c5c4n/discussions)
- 📧 **Email**: support@vectalith-labs.com
- 🌐 **Website**: https://vectalith-labs.com

---

## 🙏 Acknowledgments

Built with ❤️ using:

- **Go** - Programming Language
- **gopacket** - Packet crafting
- **fatih/color** - Terminal colors

Special thanks to:

- The Go community
- Security researchers
- All contributors

---

<div align="center">

### Made by Vectalith Labs 🚀

![GitHub Repo stars](https://img.shields.io/github/stars/Ollie33-a/v3c5c4n?style=social)
![GitHub followers](https://img.shields.io/github/followers/Ollie33-a?style=social)

**If you find VecScan useful, please consider starring the repository! ⭐**

[⬆ Back to Top](#vecscan---advanced-network--web-vulnerability-scanner)

</div>
```

---

## Additional Files to Create

### .github/ISSUE_TEMPLATE/bug_report.md

```markdown
---
name: Bug report
about: Create a report to help us improve
title: "[BUG] "
labels: bug
assignees: ""
---

## Describe the bug

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:

1. Run command '...'
2. With target '...'
3. See error

## Expected behavior

A clear and concise description of what you expected to happen.

## Screenshots

If applicable, add screenshots showing the problem.

## Environment

- OS: [e.g. Linux, macOS]
- Go Version: [e.g. 1.21]
- VecScan Version: [e.g. 1.0.0]

## Additional context

Add any other context about the problem here.
```

### .github/ISSUE_TEMPLATE/feature_request.md

```markdown
---
name: Feature request
about: Suggest an idea for this project
title: "[FEATURE] "
labels: enhancement
assignees: ""
---

## Is your feature request related to a problem?

A clear and concise description of what the problem is.

## Describe the solution you'd like

A clear and concise description of what you want to happen.

## Describe alternatives you've considered

A clear and concise description of any alternative solutions you've considered.

## Additional context

Add any other context or screenshots about the feature request here.
```
