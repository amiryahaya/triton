package scanner

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// Module category constants for Finding.Category field.
const (
	CategoryRuntime    = 1
	CategoryBinary     = 2
	CategoryLibrary    = 3
	CategoryKernel     = 4
	CategoryCert       = 5
	CategorySourceCode = 6
	CategoryWebApp     = 7
	CategoryConfig     = 8
	CategoryNetwork    = 9
)

// Confidence levels for Finding.Confidence field.
const (
	ConfidenceDefinitive  = 0.95 // Parsed and verified (certs, keys, protocol probes)
	ConfidenceHigh        = 0.90 // Config directive or strong pattern match
	ConfidenceMedium      = 0.85 // Package or config file match
	ConfidenceMediumLow   = 0.80 // Source code pattern match
	ConfidenceLow         = 0.75 // Transitive dependency
	ConfidenceSpeculative = 0.50 // Unreachable dependency
)

// newFinding creates a Finding with common fields pre-populated.
func newFinding(module string, category int, source model.FindingSource, asset *model.CryptoAsset, confidence float64) *model.Finding {
	return &model.Finding{
		ID:          uuid.New().String(),
		Category:    category,
		Source:      source,
		CryptoAsset: asset,
		Confidence:  confidence,
		Module:      module,
		Timestamp:   time.Now(),
	}
}
