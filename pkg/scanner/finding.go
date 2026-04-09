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

// appendNonNil is a tiny guard that drops nil findings before
// appending to a parser's output slice. Finding builders may
// return nil for degenerate tokens (pure OpenSSL list operators
// like `!`, `-`, `+`), and the engine collector would panic
// dereferencing a nil pointer. Centralizing the guard keeps
// every parser callsite a one-liner and makes the "never leak
// nil" invariant visible in one place. Used by web_server,
// vpn_config, container_signatures and any future config-style
// scanner.
func appendNonNil(out *[]*model.Finding, f *model.Finding) {
	if f != nil {
		*out = append(*out, f)
	}
}

// newFinding creates a Finding with common fields pre-populated.
func newFinding(module string, category int, source model.FindingSource, asset *model.CryptoAsset, confidence float64) *model.Finding {
	return &model.Finding{
		ID:          uuid.Must(uuid.NewV7()).String(),
		Category:    category,
		Source:      source,
		CryptoAsset: asset,
		Confidence:  confidence,
		Module:      module,
		Timestamp:   time.Now(),
	}
}
