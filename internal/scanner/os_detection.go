package scanner

import (
	"fmt"
	"strings"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
)

// OSFingerprint represents detected OS information
type OSFingerprint struct {
	DetectedOS      string
	Confidence      float64
	Family          string // Windows, Linux, macOS, etc.
	ProbableVersion string
	Indicators      []string
	Details         map[string]interface{}
}

// DetectOS detects operating system from open ports
func DetectOS(openPorts []models.PortResult) OSFingerprint {
	os := OSFingerprint{
		Indicators: make([]string, 0),
		Details:    make(map[string]interface{}),
	}

	if len(openPorts) == 0 {
		os.DetectedOS = "Unknown"
		os.Confidence = 0.0
		return os
	}

	// Get all open port numbers
	portNumbers := make(map[int]bool)
	serviceMap := make(map[int]string)

	for _, port := range openPorts {
		portNumbers[port.Port] = true
		serviceMap[port.Port] = strings.ToLower(port.Service)
	}

	// Check for Windows indicators
	windowsScore := checkWindowsIndicators(portNumbers, serviceMap, &os)

	// Check for Linux indicators
	linuxScore := checkLinuxIndicators(portNumbers, serviceMap, &os)

	// Check for macOS indicators
	macOSScore := checkMacOSIndicators(portNumbers, serviceMap, &os)

	// Determine most likely OS
	scores := map[string]float64{
		"Windows": windowsScore,
		"Linux":   linuxScore,
		"macOS":   macOSScore,
	}

	maxScore := 0.0
	bestOS := "Unknown"

	for osName, score := range scores {
		if score > maxScore {
			maxScore = score
			bestOS = osName
		}
	}

	os.DetectedOS = bestOS
	os.Confidence = maxScore
	os.Family = bestOS

	return os
}

// checkWindowsIndicators checks for Windows-specific ports and services
func checkWindowsIndicators(ports map[int]bool, services map[int]string, os *OSFingerprint) float64 {
	score := 0.0

	// Critical Windows indicators
	if ports[3389] { // RDP
		score += 0.30
		os.Indicators = append(os.Indicators, "RDP (3389) - Remote Desktop Protocol")
	}

	if ports[445] { // SMB
		score += 0.25
		os.Indicators = append(os.Indicators, "SMB (445) - Windows File Sharing")
		if ports[139] { // NetBIOS
			score += 0.10
			os.Indicators = append(os.Indicators, "NetBIOS (139) - Windows Networking")
		}
	}

	if ports[135] { // Windows RPC
		score += 0.15
		os.Indicators = append(os.Indicators, "RPC Endpoint (135) - Windows Service")
	}

	if ports[5985] || ports[5986] { // WinRM
		score += 0.15
		os.Indicators = append(os.Indicators, "WinRM (5985/5986) - Windows Management")
	}

	if ports[1433] { // SQL Server
		score += 0.10
		os.Indicators = append(os.Indicators, "MSSQL (1433) - Windows SQL Server")
	}

	if ports[3306] { // MySQL on Windows
		score += 0.05
		os.Indicators = append(os.Indicators, "MySQL (3306) - Database Service")
	}

	if ports[23] { // Telnet (common on older Windows)
		score += 0.05
		os.Indicators = append(os.Indicators, "Telnet (23) - Legacy Windows Service")
	}

	// Negative indicator - SSH usually means NOT Windows (unless WSL)
	if ports[22] {
		score -= 0.15
		os.Indicators = append(os.Indicators, "SSH (22) - Suggests non-native Windows")
	}

	// Version detection attempts
	if ports[445] {
		os.Details["smb_port"] = 445
		os.ProbableVersion = detectWindowsVersion(ports)
	}

	return score
}

// checkLinuxIndicators checks for Linux-specific ports and services
func checkLinuxIndicators(ports map[int]bool, services map[int]string, os *OSFingerprint) float64 {
	score := 0.0

	// Critical Linux indicators
	if ports[22] { // SSH
		score += 0.30
		os.Indicators = append(os.Indicators, "SSH (22) - Secure Shell Access")
	}

	if ports[111] { // Portmapper/Sunrpc
		score += 0.20
		os.Indicators = append(os.Indicators, "Portmapper (111) - RPC Services")
	}

	if ports[2049] { // NFS
		score += 0.20
		os.Indicators = append(os.Indicators, "NFS (2049) - Network File System")
	}

	if ports[25] { // SMTP
		score += 0.10
		os.Indicators = append(os.Indicators, "SMTP (25) - Mail Service")
	}

	if ports[587] { // SMTP Alternative
		score += 0.10
		os.Indicators = append(os.Indicators, "SMTP (587) - Submission Port")
	}

	if ports[143] { // IMAP
		score += 0.10
		os.Indicators = append(os.Indicators, "IMAP (143) - Mail Retrieval")
	}

	if ports[110] { // POP3
		score += 0.10
		os.Indicators = append(os.Indicators, "POP3 (110) - Mail Protocol")
	}

	if ports[5432] { // PostgreSQL
		score += 0.10
		os.Indicators = append(os.Indicators, "PostgreSQL (5432) - Database")
	}

	if ports[3306] { // MySQL
		score += 0.10
		os.Indicators = append(os.Indicators, "MySQL (3306) - Database")
	}

	if ports[3389] { // RDP (unusual on Linux)
		score -= 0.20
		os.Indicators = append(os.Indicators, "RDP (3389) - Suggests non-native Linux")
	}

	if ports[445] { // SMB (unusual on Linux without Samba)
		score -= 0.10
		os.Indicators = append(os.Indicators, "SMB (445) - Samba or non-native")
	}

	// Version detection
	if ports[22] {
		os.Details["ssh_port"] = 22
		os.ProbableVersion = detectLinuxVersion(ports)
	}

	return score
}

// checkMacOSIndicators checks for macOS-specific ports and services
func checkMacOSIndicators(ports map[int]bool, services map[int]string, os *OSFingerprint) float64 {
	score := 0.0

	// Critical macOS indicators
	if ports[22] { // SSH
		score += 0.15
		os.Indicators = append(os.Indicators, "SSH (22) - macOS SSH Access")
	}

	if ports[548] { // AFP (Apple File Protocol)
		score += 0.35
		os.Indicators = append(os.Indicators, "AFP (548) - Apple File Protocol")
	}

	if ports[5900] { // VNC
		score += 0.15
		os.Indicators = append(os.Indicators, "VNC (5900) - Apple Remote Desktop")
	}

	if ports[3689] { // DAAP (iTunes)
		score += 0.20
		os.Indicators = append(os.Indicators, "DAAP (3689) - iTunes Music Sharing")
	}

	if ports[445] { // SMB (Samba on Mac)
		score += 0.10
		os.Indicators = append(os.Indicators, "SMB (445) - macOS Samba")
	}

	if ports[88] { // Kerberos
		score += 0.10
		os.Indicators = append(os.Indicators, "Kerberos (88) - macOS Domain Auth")
	}

	// Negative indicators
	if ports[3389] { // RDP (not typical on Mac)
		score -= 0.10
	}

	if ports[135] || ports[139] { // Windows Networking
		score -= 0.15
	}

	os.ProbableVersion = detectMacOSVersion(ports)

	return score
}

// detectWindowsVersion attempts to detect Windows version
func detectWindowsVersion(ports map[int]bool) string {
	if ports[5985] || ports[5986] {
		return "Windows Vista+ (WinRM enabled)"
	}

	if ports[3389] {
		if ports[445] {
			return "Windows XP/Vista/7/8/10/Server"
		}
	}

	if ports[135] && ports[139] && ports[445] {
		return "Windows NT/XP/Vista/7/8/10/Server"
	}

	return "Windows (version unknown)"
}

// detectLinuxVersion attempts to detect Linux version
func detectLinuxVersion(ports map[int]bool) string {
	indicators := 0

	if ports[111] {
		indicators++ // NFS-based
	}
	if ports[2049] {
		indicators++ // Explicit NFS
	}
	if ports[25] {
		indicators++ // Mail services
	}

	if indicators >= 2 {
		return "Linux Server (enterprise-grade)"
	}

	if ports[22] {
		return "Linux (generic)"
	}

	return "Linux (type unknown)"
}

// detectMacOSVersion attempts to detect macOS version
func detectMacOSVersion(ports map[int]bool) string {
	if ports[548] {
		return "macOS (AFP enabled)"
	}

	if ports[5900] || ports[3689] {
		return "macOS (media/remote services)"
	}

	if ports[22] && ports[445] {
		return "macOS (networking enabled)"
	}

	return "macOS (generic)"
}

// GetOSDescription returns detailed description
func (os *OSFingerprint) GetOSDescription() string {
	var desc strings.Builder

	desc.WriteString(fmt.Sprintf("Detected OS: %s\n", os.DetectedOS))
	desc.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", os.Confidence*100))
	desc.WriteString(fmt.Sprintf("Probable Version: %s\n", os.ProbableVersion))
	desc.WriteString("Indicators:\n")

	for _, indicator := range os.Indicators {
		desc.WriteString(fmt.Sprintf("  - %s\n", indicator))
	}

	return desc.String()
}

// GetOSFamily returns OS family
func (os *OSFingerprint) GetOSFamily() string {
	switch os.DetectedOS {
	case "Windows":
		return "Windows"
	case "Linux":
		return "Linux"
	case "macOS":
		return "Unix/BSD"
	default:
		return "Unknown"
	}
}