package web

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"

    "github.com/Ollie33-a/v3c5c4n/internal/models"
)

// CVEDatabase holds CVE information
type CVEDatabase struct {
    Entries map[string]models.CVEMatch
}

// LoadCVEDatabase loads CVE database from JSON file
func LoadCVEDatabase(filePath string) (*CVEDatabase, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read CVE database: %w", err)
    }

    var entries map[string]models.CVEMatch
    if err := json.Unmarshal(data, &entries); err != nil {
        return nil, fmt.Errorf("failed to parse CVE database: %w", err)
    }

    return &CVEDatabase{Entries: entries}, nil
}

// matchToCVE matches vulnerability to CVEs
func matchToCVE(vuln *models.WebVulnerability) []string {
    cves := make([]string, 0)

    // This is a simplified matching algorithm
    // In production, use actual CVE API (NVD, etc.)

    vulnTitle := strings.ToLower(vuln.Title)
    vulnDesc := strings.ToLower(vuln.Description)

    // Known vulnerability patterns
    patterns := map[string][]string{
        "sql injection":       {"CVE-2019-9193", "CVE-2018-20225"},
        "xss":                 {"CVE-2020-5410", "CVE-2019-8943"},
        "csrf":                {"CVE-2021-21240", "CVE-2020-26217"},
        "directory traversal": {"CVE-2021-21985", "CVE-2020-3452"},
        "lfi":                 {"CVE-2021-22911", "CVE-2020-13999"},
        "rce":                 {"CVE-2021-44228", "CVE-2021-3129"},
        "authentication":      {"CVE-2021-21972", "CVE-2021-21985"},
    }

    for pattern, cveList := range patterns {
        if strings.Contains(vulnTitle, pattern) || strings.Contains(vulnDesc, pattern) {
            cves = append(cves, cveList...)
        }
    }

    return cves
}