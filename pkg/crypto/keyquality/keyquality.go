// Package keyquality audits parsed public keys for catastrophic
// material-level failures that are orthogonal to algorithm-family
// classification. Each check is offline, per-key, and sub-millisecond.
//
// Returned warnings are attached to model.CryptoAsset.QualityWarnings
// by the keys/certificates scanners.
package keyquality

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

// Severity levels for quality warnings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
)

// Warning codes (stable strings; appear in serialised findings and reports).
const (
	CodeROCA         = "ROCA"
	CodeDebianWeak   = "DEBIAN-WEAK"
	CodeSmallPrime   = "SMALL-PRIME"
	CodeSizeMismatch = "SIZE-MISMATCH"
)

// Warning is one key-material quality failure.
type Warning struct {
	Code     string
	Severity string
	Message  string
	CVE      string
}

// Format renders a Warning as a single human-readable line.
func (w Warning) Format() string {
	s := fmt.Sprintf("[%s] %s: %s", w.Severity, w.Code, w.Message)
	if w.CVE != "" {
		s += " [" + w.CVE + "]"
	}
	return s
}

// Analyze runs all applicable quality checks on a parsed public key.
// algo is the caller's classification string ("RSA", "DSA", "ECDSA", ...).
// keySize is the caller's reported key size in bits.
// Non-applicable checks silently skip; ECDSA/Ed25519 keys get only the
// universal size-mismatch check.
//
// Never panics on unknown key types. Returns an empty slice on a clean key.
func Analyze(pub crypto.PublicKey, algo string, keySize int) []Warning {
	var out []Warning

	// Size mismatch runs on anything with a parseable bit length.
	if w, ok := sizeMismatchCheck(pub, keySize); ok {
		out = append(out, w)
	}

	rsaPub, isRSA := pub.(*rsa.PublicKey)
	if !isRSA {
		return out
	}

	// RSA-specific checks.
	if w, ok := smallPrimeCheck(rsaPub); ok {
		out = append(out, w)
	}
	if w, ok := rocaCheck(rsaPub); ok {
		out = append(out, w)
	}
	if w, ok := debianWeakCheck(pub, algo, keySize); ok {
		out = append(out, w)
	}
	return out
}

// Flatten converts warnings to a []string form (used by HTML rendering only).
func Flatten(ws []Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Format())
	}
	return out
}

// ToModel converts internal Warnings to the model.QualityWarning form
// stored on CryptoAsset.
func ToModel(ws []Warning) []model.QualityWarning {
	out := make([]model.QualityWarning, 0, len(ws))
	for _, w := range ws {
		out = append(out, model.QualityWarning{
			Code:     w.Code,
			Severity: w.Severity,
			Message:  w.Message,
			CVE:      w.CVE,
		})
	}
	return out
}
