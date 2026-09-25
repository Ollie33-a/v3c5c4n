# VecScan - Advanced Network & Web Vulnerability Scanner

<div align="center">

![VecScan Logo](assets/logo.png)

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Ollie33-a/v3c5c4n)](https://github.com/Ollie33-a/v3c5c4n)

**VecScan** is a professional-grade network port scanner and web vulnerability scanner built in Go, designed for security researchers and penetration testers.

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation)

</div>

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Network Scanning](#network-scanning)
  - [Web Scanning](#web-scanning)
  - [Evasion Techniques](#evasion-techniques)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Vulnerability Database](#vulnerability-database)
- [Performance](#performance)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### 🎯 Network Scanning

- **Full Port Range Scanning**: Scan all 65,535 ports with high efficiency
- **TCP & UDP Scanning**: Support for both TCP and UDP protocols
- **Service Identification**: Automatic service name resolution for known ports
- **Banner Grabbing**: Extract service banners and version information
- **Filtered Port Detection**: Identify and handle firewall-filtered ports

### 🔓 Firewall Evasion

- **TCP ACK Scans**: Bypass simple firewall rules
- **Inverse Flag Scans**: FIN, NULL, and Xmas scan techniques
- **Packet Fragmentation**: Split packets to evade IDS/IPS systems
- **Source Port Manipulation**: Use trusted ports (e.g., DNS:53) as source
- **Timing Evasion**: Variable packet timing to avoid detection
- **Decoy Scanning**: Mix real packets with decoys

### 🌐 Web Vulnerability Scanning

- **SQL Injection Detection**: Identify SQL injection vulnerabilities
- **XSS Detection**: Find reflected and stored XSS vulnerabilities
- **CSRF Detection**: Detect missing CSRF protections
- **Security Header Analysis**: Check for missing security headers
- **Directory Traversal**: Test for path traversal vulnerabilities
- **SSL/TLS Analysis**: Certificate validation and security checks

### 📊 Reporting & Export

- **JSON Export**: Structured JSON reports for automation
- **Terminal Reports**: Colored, formatted terminal output
- **CVE Matching**: Automatic CVE identification for found vulnerabilities
- **Confidence Scoring**: Confidence levels for all findings

### ⚡ Performance

- **Multi-threaded Scanning**: Concurrent port scanning (default 64 threads)
- **Rate Limiting**: Configurable packet rate limiting (packets/second)
- **Intelligent Timeouts**: Adaptive timeout handling
- **Memory Efficient**: Low memory footprint for large scans

### 🛡️ Reliability

- **Graceful Shutdown**: Clean exit on Ctrl+C with partial reports
- **Error Handling**: Robust error handling and recovery
- **Retry Logic**: Automatic retry for failed probes
- **Network Resilience**: Handle network interruptions gracefully

---

## Architecture
