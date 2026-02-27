package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// SARIF 2.1.0 types (subset for Triton findings).

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	InformationURI  string           `json:"informationUri"`
	Rules           []sarifRule      `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifRuleConfig    `json:"defaultConfiguration,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// Pre-defined SARIF rule IDs and levels.
var sarifRules = []sarifRule{
	{
		ID:               "triton/pqc-unsafe",
		ShortDescription: sarifMessage{Text: "UNSAFE cryptographic algorithm detected"},
		FullDescription:  sarifMessage{Text: "Algorithm is quantum-vulnerable and must be replaced"},
		DefaultConfig:    &sarifRuleConfig{Level: "error"},
	},
	{
		ID:               "triton/pqc-deprecated",
		ShortDescription: sarifMessage{Text: "DEPRECATED cryptographic algorithm detected"},
		FullDescription:  sarifMessage{Text: "Algorithm is deprecated and should be migrated"},
		DefaultConfig:    &sarifRuleConfig{Level: "warning"},
	},
	{
		ID:               "triton/pqc-transitional",
		ShortDescription: sarifMessage{Text: "TRANSITIONAL cryptographic algorithm detected"},
		FullDescription:  sarifMessage{Text: "Algorithm needs a migration plan for PQC readiness"},
		DefaultConfig:    &sarifRuleConfig{Level: "note"},
	},
	{
		ID:               "triton/pqc-safe",
		ShortDescription: sarifMessage{Text: "SAFE cryptographic algorithm detected"},
		FullDescription:  sarifMessage{Text: "Algorithm is quantum-resistant"},
		DefaultConfig:    &sarifRuleConfig{Level: "note"},
	},
}

// sarifRuleIndex maps PQC status to rule ID and level.
var sarifRuleIndex = map[string]struct {
	ruleID string
	level  string
}{
	"UNSAFE":       {"triton/pqc-unsafe", "error"},
	"DEPRECATED":   {"triton/pqc-deprecated", "warning"},
	"TRANSITIONAL": {"triton/pqc-transitional", "note"},
	"SAFE":         {"triton/pqc-safe", "note"},
}

// GenerateSARIF produces a SARIF 2.1.0 report file.
func (g *Generator) GenerateSARIF(result *model.ScanResult, filename string) error {
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Triton",
						Version:        result.Metadata.ToolVersion,
						InformationURI: "https://github.com/amiryahaya/triton",
						Rules:          sarifRules,
					},
				},
				Results: buildSARIFResults(result),
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling SARIF: %w", err)
	}
	return os.WriteFile(filename, data, 0o644)
}

func buildSARIFResults(result *model.ScanResult) []sarifResult {
	var results []sarifResult

	for i := range result.Findings {
		f := &result.Findings[i]
		if f.CryptoAsset == nil {
			continue
		}

		status := strings.ToUpper(f.CryptoAsset.PQCStatus)
		ri, ok := sarifRuleIndex[status]
		if !ok {
			continue
		}

		msg := fmt.Sprintf("%s (%s) — PQC Status: %s",
			f.CryptoAsset.Algorithm,
			f.Module,
			f.CryptoAsset.PQCStatus,
		)
		if f.CryptoAsset.KeySize > 0 {
			msg += fmt.Sprintf(", Key Size: %d bits", f.CryptoAsset.KeySize)
		}

		sr := sarifResult{
			RuleID:  ri.ruleID,
			Level:   ri.level,
			Message: sarifMessage{Text: msg},
		}

		// Add location based on source type.
		loc := buildSARIFLocation(f)
		if loc != nil {
			sr.Locations = []sarifLocation{*loc}
		}

		results = append(results, sr)
	}

	return results
}

func buildSARIFLocation(f *model.Finding) *sarifLocation {
	switch f.Source.Type {
	case "file":
		if f.Source.Path == "" {
			return nil
		}
		return &sarifLocation{
			PhysicalLocation: &sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI: f.Source.Path,
				},
			},
		}
	case "network":
		if f.Source.Endpoint == "" {
			return nil
		}
		return &sarifLocation{
			LogicalLocations: []sarifLogicalLocation{
				{Name: f.Source.Endpoint, Kind: "network-endpoint"},
			},
		}
	case "process":
		name := f.Source.Path
		if name == "" {
			return nil
		}
		return &sarifLocation{
			LogicalLocations: []sarifLogicalLocation{
				{Name: name, Kind: "process"},
			},
		}
	default:
		return nil
	}
}
