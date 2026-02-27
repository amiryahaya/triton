package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy defines a set of compliance rules and thresholds.
type Policy struct {
	Version    string     `yaml:"version" json:"version"`
	Name       string     `yaml:"name" json:"name"`
	Rules      []Rule     `yaml:"rules" json:"rules"`
	Thresholds Thresholds `yaml:"thresholds" json:"thresholds"`
}

// Rule defines a single policy rule that can match findings and trigger actions.
type Rule struct {
	ID        string    `yaml:"id" json:"id"`
	Severity  string    `yaml:"severity" json:"severity"` // error, warning, note
	Condition Condition `yaml:"condition" json:"condition"`
	Action    string    `yaml:"action" json:"action"` // fail, warn
	Message   string    `yaml:"message,omitempty" json:"message,omitempty"`
}

// Condition specifies what a rule matches against.
type Condition struct {
	PQCStatus       string `yaml:"pqc_status,omitempty" json:"pqc_status,omitempty"`
	AlgorithmFamily string `yaml:"algorithm_family,omitempty" json:"algorithm_family,omitempty"`
	Algorithm       string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	KeySizeBelow    int    `yaml:"key_size_below,omitempty" json:"key_size_below,omitempty"`
	KeySizeAbove    int    `yaml:"key_size_above,omitempty" json:"key_size_above,omitempty"`
	Module          string `yaml:"module,omitempty" json:"module,omitempty"`
	Category        int    `yaml:"category,omitempty" json:"category,omitempty"`
}

// Thresholds define aggregate limits that trigger policy failure.
type Thresholds struct {
	MinNACSAReadiness float64 `yaml:"min_nacsa_readiness,omitempty" json:"min_nacsa_readiness,omitempty"`
	MaxUnsafeCount    *int    `yaml:"max_unsafe_count,omitempty" json:"max_unsafe_count,omitempty"`
	MaxDeprecated     *int    `yaml:"max_deprecated_count,omitempty" json:"max_deprecated_count,omitempty"`
	MinSafePercent    float64 `yaml:"min_safe_percent,omitempty" json:"min_safe_percent,omitempty"`
}

// LoadFromFile parses a YAML policy file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML bytes into a Policy.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if p.Version == "" {
		return nil, fmt.Errorf("policy missing required 'version' field")
	}
	if p.Name == "" {
		return nil, fmt.Errorf("policy missing required 'name' field")
	}
	return &p, nil
}
