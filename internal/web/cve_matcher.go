package web

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
)

// CVEDatabase holds CVE information
type CVEDatabase struct {
	Entries map[string]CVEEntry
}

type CVEEntry struct {
	CVEID       string
	Title       string
	Description string
	Severity    string
	CVSSScore   float64
	Published   string
	Keywords    []string
	ServicePorts []int
}

// Known CVE mappings for services and vulnerabilities
var CVEMappings = map[string][]CVEEntry{
	"ssh": {
		{
			CVEID:       "CVE-2018-15473",
			Title:       "OpenSSH Username Enumeration",
			Description: "OpenSSH allows enumerating valid usernames via timing attacks",
			Severity:    "medium",
			CVSSScore:   5.3,
			Published:   "2018-08-15",
			Keywords:    []string{"openssh", "enumeration", "timing"},
			ServicePorts: []int{22},
		},
		{
			CVEID:       "CVE-2019-16905",
			Title:       "OpenSSH Information Disclosure",
			Description: "Information disclosure vulnerability in OpenSSH",
			Severity:    "high",
			CVSSScore:   7.5,
			Published:   "2019-12-16",
			Keywords:    []string{"openssh", "disclosure"},
			ServicePorts: []int{22},
		},
	},
	"http": {
		{
			CVEID:       "CVE-2021-41773",
			Title:       "Apache HTTP Server Path Traversal",
			Description: "Path traversal vulnerability in Apache HTTP Server",
			Severity:    "critical",
			CVSSScore:   9.8,
			Published:   "2021-10-05",
			Keywords:    []string{"apache", "path traversal", "lfi"},
			ServicePorts: []int{80, 8080},
		},
	},
	"mysql": {
		{
			CVEID:       "CVE-2021-27928",
			Title:       "MySQL Authentication Bypass",
			Description: "Authentication bypass in MySQL Server",
			Severity:    "critical",
			CVSSScore:   9.8,
			Published:   "2021-05-11",
			Keywords:    []string{"mysql", "authentication", "bypass"},
			ServicePorts: []int{3306},
		},
	},
	"postgresql": {
		{
			CVEID:       "CVE-2021-3449",
			Title:       "PostgreSQL Privilege Escalation",
			Description: "Privilege escalation vulnerability in PostgreSQL",
			Severity:    "high",
			CVSSScore:   8.8,
			Published:   "2021-04-29",
			Keywords:    []string{"postgresql", "privilege escalation"},
			ServicePorts: []int{5432},
		},
	},
}

// VulnerabilitySignatures defines patterns for common vulnerabilities
var VulnerabilitySignatures = map[string][]string{
	"sql_injection":     {"union select", "order by", "group by", "syntax error", "database"},
	"xss":               {"script", "onerror", "onload", "alert", "<img"},
	"rce":               {"command", "shell", "exec", "system", "eval"},
	"path_traversal":    {"../", "..\\", "etc/passwd", "windows/system32"},
	"authentication":    {"unauthorized", "forbidden", "authentication failed"},
	"information_disc":  {"version", "powered by", "x-powered-by", "server"},
}

// MatchPortToCVE matches port to known CVEs
func MatchPortToCVE(port int, service string) []models.CVEMatch {
	cves := make([]models.CVEMatch, 0)

	// Normalize service name
	serviceLower := strings.ToLower(strings.TrimSpace(service))

	// Check direct service mapping
	if entries, exists := CVEMappings[serviceLower]; exists {
		for _, entry := range entries {
			cves = append(cves, models.CVEMatch{
				CVEID:           entry.CVEID,
				Title:           entry.Title,
				Severity:        entry.Severity,
				Score:           entry.CVSSScore,
				Description:     entry.Description,
				PublishedDate:   parseDate(entry.Published),
				ReferencesFound: 1,
			})
		}
	}

	// Check port-based mappings
	portCVEs := getPortCVEs(port)
	cves = append(cves, portCVEs...)

	return cves
}

// getPortCVEs returns CVEs for specific ports
func getPortCVEs(port int) []models.CVEMatch {
	cves := make([]models.CVEMatch, 0)

	portCVEMap := map[int][]CVEEntry{
		22: CVEMappings["ssh"],
		80: CVEMappings["http"],
		443: CVEMappings["http"],
		3306: CVEMappings["mysql"],
		5432: CVEMappings["postgresql"],
		139: {
			{
				CVEID:       "CVE-2017-0143",
				Title:       "Microsoft Windows SMB RCE",
				Description: "EternalBlue - Remote Code Execution via SMB",
				Severity:    "critical",
				CVSSScore:   9.8,
				Published:   "2017-03-14",
				Keywords:    []string{"smb", "windows", "rce", "eternalblue"},
				ServicePorts: []int{139, 445},
			},
		},
		445: {
			{
				CVEID:       "CVE-2017-0143",
				Title:       "Microsoft Windows SMB RCE",
				Description: "EternalBlue - Remote Code Execution via SMB",
				Severity:    "critical",
				CVSSScore:   9.8,
				Published:   "2017-03-14",
				Keywords:    []string{"smb", "windows", "rce", "eternalblue"},
				ServicePorts: []int{139, 445},
			},
		},
	}

	if entries, exists := portCVEMap[port]; exists {
		for _, entry := range entries {
			cves = append(cves, models.CVEMatch{
				CVEID:           entry.CVEID,
				Title:           entry.Title,
				Severity:        entry.Severity,
				Score:           entry.CVSSScore,
				Description:     entry.Description,
				PublishedDate:   parseDate(entry.Published),
				ReferencesFound: 1,
			})
		}
	}

	return cves
}

// matchToCVE matches web vulnerability to CVEs
func matchToCVE(vuln *models.WebVulnerability) []string {
	cves := make([]string, 0)

	vulnTitle := strings.ToLower(vuln.Title)
	vulnDesc := strings.ToLower(vuln.Description)

	// Known vulnerability patterns
	patterns := map[string][]string{
		"sql injection":       {"CVE-2019-9193", "CVE-2018-20225", "CVE-2021-27928"},
		"xss":                 {"CVE-2020-5410", "CVE-2019-8943", "CVE-2021-3129"},
		"csrf":                {"CVE-2021-21240", "CVE-2020-26217"},
		"directory traversal": {"CVE-2021-21985", "CVE-2020-3452", "CVE-2021-41773"},
		"lfi":                 {"CVE-2021-22911", "CVE-2020-13999", "CVE-2021-41773"},
		"rce":                 {"CVE-2021-44228", "CVE-2021-3129", "CVE-2021-27928"},
		"authentication":      {"CVE-2021-21972", "CVE-2021-21985", "CVE-2019-9193"},
		"security header":     {"CVE-2020-5410", "CVE-2019-8943"},
	}

	for pattern, cveList := range patterns {
		if strings.Contains(vulnTitle, pattern) || strings.Contains(vulnDesc, pattern) {
			cves = append(cves, cveList...)
		}
	}

	return cves
}

func parseDate(dateStr string) time.Time {
	if t, err := time.Parse("2006-01-02", dateStr); err == nil {
		return t
	}
	return time.Now()
}