package policy

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(i int) *int { return &i }

func testResult() *model.ScanResult {
	now := time.Now()
	return &model.ScanResult{
		ID: "test-scan",
		Metadata: model.ScanMetadata{
			Timestamp: now,
			Hostname:  "test-host",
		},
		Findings: []model.Finding{
			{
				ID:       "f1",
				Category: 2,
				Source:    model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "RSA-2048",
					PQCStatus: "TRANSITIONAL",
					KeySize:   2048,
				},
				Module: "certificates",
			},
			{
				ID:       "f2",
				Category: 3,
				Source:    model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "AES-256-GCM",
					PQCStatus: "SAFE",
					KeySize:   256,
				},
				Module: "libraries",
			},
			{
				ID:       "f3",
				Category: 2,
				Source:    model.FindingSource{Type: "file", Path: "/etc/ssh/host_key"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "DES",
					PQCStatus: "UNSAFE",
					KeySize:   56,
				},
				Module: "keys",
			},
			{
				ID:       "f4",
				Category: 5,
				Source:    model.FindingSource{Type: "file", Path: "/app/hash.py"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "MD5",
					PQCStatus: "DEPRECATED",
				},
				Module: "scripts",
			},
		},
		Summary: model.Summary{
			TotalFindings:         4,
			TotalCryptoAssets:     4,
			Safe:                  1,
			Transitional:          1,
			Deprecated:            1,
			Unsafe:                1,
			NACSAReadinessPercent: 25.0,
		},
	}
}

func TestEvaluate_PQCStatusRule(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-unsafe",
				Severity:  "error",
				Condition: Condition{PQCStatus: "UNSAFE"},
				Action:    "fail",
			},
		},
	}

	result := testResult()
	eval := Evaluate(pol, result)

	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.Len(t, eval.Violations, 1)
	assert.Equal(t, "no-unsafe", eval.Violations[0].RuleID)
	assert.Equal(t, "DES", eval.Violations[0].Finding.CryptoAsset.Algorithm)
}

func TestEvaluate_AlgorithmFamilyRule(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-rsa-small",
				Severity:  "error",
				Condition: Condition{AlgorithmFamily: "RSA", KeySizeBelow: 4096},
				Action:    "fail",
			},
		},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.Len(t, eval.Violations, 1)
	assert.Equal(t, "RSA-2048", eval.Violations[0].Finding.CryptoAsset.Algorithm)
}

func TestEvaluate_ModuleFilter(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "scripts-only",
				Severity:  "warning",
				Condition: Condition{Module: "scripts", PQCStatus: "DEPRECATED"},
				Action:    "warn",
			},
		},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictWarn, eval.Verdict)
	assert.Len(t, eval.Violations, 1)
	assert.Equal(t, "MD5", eval.Violations[0].Finding.CryptoAsset.Algorithm)
}

func TestEvaluate_CategoryFilter(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "cat5",
				Severity:  "warning",
				Condition: Condition{Category: 5},
				Action:    "warn",
			},
		},
	}

	eval := Evaluate(pol, testResult())
	assert.Len(t, eval.Violations, 1)
}

func TestEvaluate_NoViolations(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Permissive",
		Rules: []Rule{
			{
				ID:        "no-quantum",
				Severity:  "error",
				Condition: Condition{Algorithm: "QuantumBreaker-9000"},
				Action:    "fail",
			},
		},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestEvaluate_ThresholdMaxUnsafe(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "Threshold Test",
		Thresholds: Thresholds{MaxUnsafeCount: intPtr(0)},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictFail, eval.Verdict)
	require.Len(t, eval.ThresholdViolations, 1)
	assert.Equal(t, "max_unsafe_count", eval.ThresholdViolations[0].Name)
}

func TestEvaluate_ThresholdNACSAReadiness(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "NACSA Threshold",
		Thresholds: Thresholds{MinNACSAReadiness: 60.0},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictFail, eval.Verdict)
	require.Len(t, eval.ThresholdViolations, 1)
	assert.Equal(t, "min_nacsa_readiness", eval.ThresholdViolations[0].Name)
}

func TestEvaluate_ThresholdMinSafePercent(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "Safe Percent",
		Thresholds: Thresholds{MinSafePercent: 50.0},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictFail, eval.Verdict)
}

func TestEvaluate_ThresholdPass(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "Easy Thresholds",
		Thresholds: Thresholds{MaxUnsafeCount: intPtr(100)},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.ThresholdViolations)
}

func TestEvaluate_WarnDoesNotOverrideFail(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Mixed",
		Rules: []Rule{
			{ID: "fail-rule", Severity: "error", Condition: Condition{PQCStatus: "UNSAFE"}, Action: "fail"},
			{ID: "warn-rule", Severity: "warning", Condition: Condition{PQCStatus: "DEPRECATED"}, Action: "warn"},
		},
	}

	eval := Evaluate(pol, testResult())
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.Len(t, eval.Violations, 2)
}

func TestEvaluate_FindingWithoutCryptoAsset(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{ID: "any", Severity: "error", Condition: Condition{PQCStatus: "UNSAFE"}, Action: "fail"},
		},
	}

	result := &model.ScanResult{
		Findings: []model.Finding{
			{ID: "no-crypto", CryptoAsset: nil},
		},
	}

	eval := Evaluate(pol, result)
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestEvaluate_BuiltinNACSA(t *testing.T) {
	pol, err := LoadBuiltin("nacsa-2030")
	require.NoError(t, err)

	eval := Evaluate(pol, testResult())
	// Should fail: has unsafe and readiness below 60%
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.True(t, len(eval.Violations) > 0)
}

func TestMatchesFamily(t *testing.T) {
	tests := []struct {
		algo   string
		family string
		want   bool
	}{
		{"RSA-2048", "RSA", true},
		{"RSA-4096", "RSA", true},
		{"AES-256-GCM", "AES", true},
		{"ECDSA-P256", "ECDSA", true},
		{"Ed25519", "EdDSA", true},
		{"Ed448", "EdDSA", true},
		{"3DES", "DES", true},
		{"DES", "DES", true},
		{"SHA-256", "SHA", true},
		{"SHA-1", "SHA", true},
		{"SHA3-256", "SHA3", true},
		{"ML-KEM-768", "Lattice", true},
		{"ML-DSA-65", "Lattice", true},
		{"AES-256-GCM", "RSA", false},
		{"RSA-2048", "AES", false},
	}

	for _, tt := range tests {
		t.Run(tt.algo+"_"+tt.family, func(t *testing.T) {
			a := &model.CryptoAsset{Algorithm: tt.algo}
			assert.Equal(t, tt.want, matchesFamily(a, tt.family))
		})
	}
}
