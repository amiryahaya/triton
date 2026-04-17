package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/amiryahaya/triton/pkg/model"
)

const (
	exemptionTypeAlgorithm  = "algorithm"
	exemptionTypeThumbprint = "thumbprint"
	expiryDateLayout        = "2006-01-02"
)

// ExemptionList holds active and expired exemptions loaded from a YAML file.
type ExemptionList struct {
	Version    string      `yaml:"version"`
	Exemptions []Exemption `yaml:"exemptions"`
}

// Exemption describes a single approved exception to a policy rule.
type Exemption struct {
	// Type is "algorithm" or "thumbprint".
	Type string `yaml:"type"`

	// Algorithm fields (type: algorithm)
	Algorithm string `yaml:"algorithm,omitempty"`
	// Location is an optional filepath.Match glob pattern.
	Location string `yaml:"location,omitempty"`
	// Module is an optional case-insensitive module name filter.
	Module string `yaml:"module,omitempty"`

	// Thumbprint fields (type: thumbprint)
	SerialNumber string `yaml:"serial_number,omitempty"`
	Issuer       string `yaml:"issuer,omitempty"`

	// Common fields
	Reason     string `yaml:"reason"`          // required
	Expires    string `yaml:"expires,omitempty"` // YYYY-MM-DD; absent = never expires
	ApprovedBy string `yaml:"approved_by,omitempty"`
}

// ParseExemptions parses YAML bytes into an ExemptionList and validates required fields.
func ParseExemptions(data []byte) (*ExemptionList, error) {
	var el ExemptionList
	if err := yaml.Unmarshal(data, &el); err != nil {
		return nil, fmt.Errorf("parsing exemptions YAML: %w", err)
	}
	if el.Version == "" {
		return nil, fmt.Errorf("exemptions file missing required 'version' field")
	}
	for i, e := range el.Exemptions {
		if e.Reason == "" {
			return nil, fmt.Errorf("exemption[%d]: missing required 'reason' field", i)
		}
		if e.Type != exemptionTypeAlgorithm && e.Type != exemptionTypeThumbprint {
			return nil, fmt.Errorf("exemption[%d]: invalid type %q; must be %q or %q",
				i, e.Type, exemptionTypeAlgorithm, exemptionTypeThumbprint)
		}
	}
	return &el, nil
}

// LoadExemptionsFile reads a YAML file from disk and calls ParseExemptions.
func LoadExemptionsFile(path string) (*ExemptionList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading exemptions file: %w", err)
	}
	return ParseExemptions(data)
}

// IsExempt reports whether finding f is covered by any active (non-expired) exemption.
// It returns (true, index) when matched, or (false, -1) when not matched.
// Safe to call on a nil *ExemptionList.
func (el *ExemptionList) IsExempt(f *model.Finding, now time.Time) (bool, int) {
	if el == nil {
		return false, -1
	}
	if f == nil || f.CryptoAsset == nil {
		return false, -1
	}

	for i := range el.Exemptions {
		e := &el.Exemptions[i]

		// Skip expired exemptions.
		if e.Expires != "" {
			exp, err := time.Parse(expiryDateLayout, e.Expires)
			if err == nil && !now.Before(exp) {
				// now >= exp means the exemption has expired (we use strict before)
				continue
			}
		}

		if e.matches(f) {
			return true, i
		}
	}
	return false, -1
}

// matches tests whether exemption e covers finding f (ignoring expiry).
func (e *Exemption) matches(f *model.Finding) bool {
	a := f.CryptoAsset

	switch e.Type {
	case exemptionTypeThumbprint:
		if a.SerialNumber == "" || e.SerialNumber == "" {
			return false
		}
		if a.SerialNumber != e.SerialNumber {
			return false
		}
		if !strings.EqualFold(a.Issuer, e.Issuer) {
			return false
		}
		return true

	case exemptionTypeAlgorithm:
		if !strings.EqualFold(a.Algorithm, e.Algorithm) {
			return false
		}
		// Optional location narrowing (glob).
		if e.Location != "" {
			matched, err := filepath.Match(e.Location, f.Source.Path)
			if err != nil || !matched {
				return false
			}
		}
		// Optional module narrowing.
		if e.Module != "" && !strings.EqualFold(f.Module, e.Module) {
			return false
		}
		return true
	}

	return false
}

// ExpiredExemptions returns all exemptions whose expiry date is before now.
func (el *ExemptionList) ExpiredExemptions(now time.Time) []model.ExemptionExpired {
	if el == nil {
		return nil
	}
	var out []model.ExemptionExpired
	for _, e := range el.Exemptions {
		if e.Expires == "" {
			continue
		}
		exp, err := time.Parse(expiryDateLayout, e.Expires)
		if err != nil {
			continue
		}
		if now.Before(exp) {
			// Not yet expired.
			continue
		}
		out = append(out, model.ExemptionExpired{
			Algorithm: e.Algorithm,
			Location:  e.Location,
			ExpiredOn: e.Expires,
		})
	}
	return out
}
