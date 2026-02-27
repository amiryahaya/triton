package crypto

import "strings"

// ComplianceInfo holds CNSA 2.0 and NIST IR 8547 compliance status for an algorithm.
type ComplianceInfo struct {
	CNSA2Approved      bool   // Is this algorithm in the CNSA 2.0 approved set?
	CNSA2Status        string // "Approved", "Not Approved", "Deprecated"
	NISTDeprecatedYear int    // Year NIST marks it deprecated (0 = not applicable)
	NISTDisallowedYear int    // Year NIST disallows it (0 = not applicable)
	Warning            string // Human-readable compliance warning
}

// CNSA 2.0 approved algorithms (NSA Commercial National Security Algorithm Suite 2.0).
// Only these are approved for new acquisitions after 2027.
var cnsa2Approved = map[string]bool{
	"AES-256":     true,
	"AES-256-GCM": true,
	"AES-256-CBC": true,
	"AES-256-CTR": true,
	"AES-256-CCM": true,
	"ML-KEM-1024": true,
	"ML-DSA-87":   true,
	"SHA-384":     true,
	"SHA-512":     true,
	"SHA3-384":    true,
	"SHA3-512":    true,
	"LMS":         true,
	"XMSS":        true,
	"HMAC-SHA384": true,
	"HMAC-SHA512": true,
}

// cnsa2Timeline maps milestones.
// - 2027: New acquisitions must use CNSA 2.0 algorithms
// - 2030: Non-compliant equipment must be phased out
// - 2035: Full quantum-resistant enforcement
const (
	CNSA2NewAcquisition = 2027
	CNSA2PhaseOut       = 2030
	CNSA2FullEnforce    = 2035
)

// nistTimeline holds NIST IR 8547 deprecated/disallowed years per algorithm family.
type nistTimeline struct {
	DeprecatedYear int // Year the algorithm is deprecated
	DisallowedYear int // Year the algorithm is disallowed
}

// NIST IR 8547 timeline for classical asymmetric algorithms.
var nistClassicalTimeline = map[string]nistTimeline{
	"RSA":     {DeprecatedYear: 2030, DisallowedYear: 2035},
	"ECDSA":   {DeprecatedYear: 2030, DisallowedYear: 2035},
	"EdDSA":   {DeprecatedYear: 2030, DisallowedYear: 2035},
	"DH":      {DeprecatedYear: 2030, DisallowedYear: 2035},
	"ECDH":    {DeprecatedYear: 2030, DisallowedYear: 2035},
	"DSA":     {DeprecatedYear: 2025, DisallowedYear: 2030},
	"ElGamal": {DeprecatedYear: 2025, DisallowedYear: 2030},
}

// GetCompliance returns CNSA 2.0 and NIST IR 8547 compliance info for an algorithm.
func GetCompliance(algorithm string) ComplianceInfo {
	info := ComplianceInfo{}

	// Check CNSA 2.0 approval
	if cnsa2Approved[algorithm] {
		info.CNSA2Approved = true
		info.CNSA2Status = "Approved"
	} else {
		info.CNSA2Status = "Not Approved"
	}

	// Check NIST IR 8547 timeline
	algoInfo := ClassifyAlgorithm(algorithm, 0)
	family := algoInfo.Family

	if timeline, ok := nistClassicalTimeline[family]; ok {
		info.NISTDeprecatedYear = timeline.DeprecatedYear
		info.NISTDisallowedYear = timeline.DisallowedYear
	}

	// Generate warning based on combined status
	info.Warning = generateComplianceWarning(info, algoInfo)

	return info
}

// generateComplianceWarning creates a human-readable warning string.
func generateComplianceWarning(ci ComplianceInfo, ai AlgorithmInfo) string {
	var warnings []string

	// CNSA 2.0 warnings
	if !ci.CNSA2Approved {
		switch ai.Status {
		case UNSAFE:
			warnings = append(warnings, "CRITICAL: Algorithm is unsafe and not CNSA 2.0 approved. Immediate replacement required.")
		case DEPRECATED:
			warnings = append(warnings, "Algorithm is deprecated and not CNSA 2.0 approved. Replace before 2027.")
		case TRANSITIONAL:
			if ci.NISTDisallowedYear > 0 {
				warnings = append(warnings, "Algorithm will be deprecated by NIST in "+itoa(ci.NISTDeprecatedYear)+
					" and disallowed in "+itoa(ci.NISTDisallowedYear)+". Not CNSA 2.0 approved. Plan migration to PQC.")
			} else {
				warnings = append(warnings, "Algorithm is not CNSA 2.0 approved. Plan migration to quantum-resistant alternative.")
			}
		case SAFE:
			if isPQCFamily(ai.Family) && !ci.CNSA2Approved {
				warnings = append(warnings, "PQC algorithm but not in CNSA 2.0 approved set. Consider ML-KEM-1024 or ML-DSA-87.")
			}
			// Symmetric SAFE algorithms without CNSA 2.0 approval get no warning
		}
	}

	return strings.Join(warnings, " ")
}

// itoa is a simple int-to-string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
