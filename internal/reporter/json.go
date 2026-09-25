package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Ollie33-a/v3c5c4n/internal/models"
	"github.com/Ollie33-a/v3c5c4n/internal/scanner"
)

// JSONReporter generates JSON reports
type JSONReporter struct {
	outputPath string
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(outputPath string) *JSONReporter {
	return &JSONReporter{outputPath: outputPath}
}

// WriteNetworkReport writes network scan results to JSON
func (jr *JSONReporter) WriteNetworkReport(result *models.HostResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(jr.outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// WriteWebReport writes web scan results to JSON
func (jr *JSONReporter) WriteWebReport(result *models.WebScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(jr.outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// WriteSubnetReport writes subnet scan results to JSON
func (jr *JSONReporter) WriteSubnetReport(result *scanner.SubnetResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(jr.outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}