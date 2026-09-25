package scanner

import (
    "fmt"
    "math/rand"
    "time"
)

// EversionTechnique defines evasion technique configuration
type EversionTechnique struct {
    Name        string
    Description string
    DelayMs     int
    UseFrags    bool
    SpoofSource bool
}

// EvasionEngine manages firewall evasion techniques
type EvasionEngine struct {
    techniques map[string]EversionTechnique
}

// NewEvasionEngine creates a new evasion engine
func NewEvasionEngine() *EvasionEngine {
    return &EvasionEngine{
        techniques: map[string]EversionTechnique{
            "ack": {
                Name:        "TCP ACK Scan",
                Description: "Send ACK packets to determine filtered vs unfiltered ports",
                DelayMs:     10,
                UseFrags:    false,
                SpoofSource: false,
            },
            "fin": {
                Name:        "FIN Scan",
                Description: "Send FIN packets; no response = open|filtered, RST = closed",
                DelayMs:     15,
                UseFrags:    true,
                SpoofSource: true,
            },
            "null": {
                Name:        "NULL Scan",
                Description: "Send packets with no flags set",
                DelayMs:     15,
                UseFrags:    true,
                SpoofSource: true,
            },
            "xmas": {
                Name:        "Xmas Scan",
                Description: "Send packets with FIN, PSH, and URG flags set",
                DelayMs:     15,
                UseFrags:    true,
                SpoofSource: true,
            },
            "fragment": {
                Name:        "Packet Fragmentation",
                Description: "Fragment packets into multiple pieces to evade IDS/IPS",
                DelayMs:     20,
                UseFrags:    true,
                SpoofSource: false,
            },
            "spoof": {
                Name:        "Source Port Manipulation",
                Description: "Use DNS (port 53) as source port to evade filtering",
                DelayMs:     10,
                UseFrags:    true,
                SpoofSource: true,
            },
            "decoy": {
                Name:        "Decoy Scan",
                Description: "Send decoy packets mixed with real scan packets",
                DelayMs:     25,
                UseFrags:    false,
                SpoofSource: true,
            },
            "timing": {
                Name:        "Timing Evasion",
                Description: "Vary packet timing to avoid rate-based detection",
                DelayMs:     50,
                UseFrags:    true,
                SpoofSource: false,
            },
        },
    }
}

// GetTechnique returns evasion technique by name
func (ee *EvasionEngine) GetTechnique(name string) (EversionTechnique, error) {
    technique, exists := ee.techniques[name]
    if !exists {
        return EversionTechnique{}, fmt.Errorf("unknown evasion technique: %s", name)
    }
    return technique, nil
}

// ListTechniques returns all available techniques
func (ee *EvasionEngine) ListTechniques() []string {
    techniques := make([]string, 0, len(ee.techniques))
    for name := range ee.techniques {
        techniques = append(techniques, name)
    }
    return techniques
}

// ApplyEvasion applies evasion technique delay
func (ee *EvasionEngine) ApplyEvasion(technique string) {
    if t, err := ee.GetTechnique(technique); err == nil {
        delay := time.Duration(t.DelayMs) + time.Duration(rand.Intn(20))*time.Millisecond
        time.Sleep(delay)
    }
}

// ShouldFragment returns whether packet should be fragmented
func (ee *EvasionEngine) ShouldFragment(technique string) bool {
    if t, err := ee.GetTechnique(technique); err == nil {
        return t.UseFrags
    }
    return false
}

// ShouldSpoof returns whether source should be spoofed
func (ee *EvasionEngine) ShouldSpoof(technique string) bool {
    if t, err := ee.GetTechnique(technique); err == nil {
        return t.SpoofSource
    }
    return false
}