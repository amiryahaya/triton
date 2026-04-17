package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
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
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
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
				Source:   model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
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
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssh/host_key"},
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
				Source:   model.FindingSource{Type: "file", Path: "/app/hash.py"},
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
	eval := Evaluate(pol, result, nil)

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

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestEvaluate_ThresholdMaxUnsafe(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "Threshold Test",
		Thresholds: Thresholds{MaxUnsafeCount: intPtr(0)},
	}

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
	assert.Equal(t, VerdictFail, eval.Verdict)
}

func TestEvaluate_ThresholdPass(t *testing.T) {
	pol := &Policy{
		Version:    "1",
		Name:       "Easy Thresholds",
		Thresholds: Thresholds{MaxUnsafeCount: intPtr(100)},
	}

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, testResult(), nil)
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

	eval := Evaluate(pol, result, nil)
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestEvaluate_BuiltinNACSA(t *testing.T) {
	pol, err := LoadBuiltin("nacsa-2030")
	require.NoError(t, err)

	eval := Evaluate(pol, testResult(), nil)
	// Should fail: has unsafe and readiness below 60%
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.True(t, len(eval.Violations) > 0)
}

func TestEvaluateSystem_BasicViolation(t *testing.T) {
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

	sys := &model.System{
		Name: "Test System",
		CryptoAssets: []model.CryptoAsset{
			{Algorithm: "DES", PQCStatus: "UNSAFE", KeySize: 56},
			{Algorithm: "AES-256-GCM", PQCStatus: "SAFE", KeySize: 256},
		},
	}

	eval := EvaluateSystem(pol, sys)
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.Len(t, eval.Violations, 1)
	assert.Equal(t, 2, eval.FindingsChecked)
}

func TestEvaluateSystem_Pass(t *testing.T) {
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

	sys := &model.System{
		Name: "Safe System",
		CryptoAssets: []model.CryptoAsset{
			{Algorithm: "AES-256-GCM", PQCStatus: "SAFE", KeySize: 256},
			{Algorithm: "ML-KEM-768", PQCStatus: "SAFE"},
		},
	}

	eval := EvaluateSystem(pol, sys)
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestEvaluate_PerSystemResults(t *testing.T) {
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
	eval := Evaluate(pol, result, nil)

	// Should have system evaluations from GroupFindingsIntoSystems
	assert.NotEmpty(t, eval.SystemEvaluations)

	// Verify per-system verdicts exist with names
	for _, se := range eval.SystemEvaluations {
		assert.NotEmpty(t, se.SystemName, "system name should not be empty")
		assert.Contains(t, []Verdict{VerdictPass, VerdictWarn, VerdictFail}, se.Verdict)
	}
}

func TestMatchesConditionForAsset_SkipsModuleFilter(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "DES",
		PQCStatus: "UNSAFE",
	}

	// Rule with Module filter should NOT match in asset context
	cond := &Condition{PQCStatus: "UNSAFE", Module: "certificates"}
	assert.False(t, matchesConditionForAsset(asset, cond),
		"should skip rules with Module filter in asset context")

	// Rule with Category filter should NOT match in asset context
	cond2 := &Condition{PQCStatus: "UNSAFE", Category: 5}
	assert.False(t, matchesConditionForAsset(asset, cond2),
		"should skip rules with Category filter in asset context")

	// Rule without Module/Category filter should match
	cond3 := &Condition{PQCStatus: "UNSAFE"}
	assert.True(t, matchesConditionForAsset(asset, cond3))
}

func TestEvaluateSystem_ModuleFilteredRulesSkipped(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "cert-unsafe",
				Severity:  "error",
				Condition: Condition{PQCStatus: "UNSAFE", Module: "certificates"},
				Action:    "fail",
			},
		},
	}

	sys := &model.System{
		Name: "Test System",
		CryptoAssets: []model.CryptoAsset{
			{Algorithm: "DES", PQCStatus: "UNSAFE"},
		},
	}

	eval := EvaluateSystem(pol, sys)
	// Rule has Module filter, so it should not apply at asset level
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
}

func TestToModelResult(t *testing.T) {
	eval := &EvaluationResult{
		PolicyName:      "test-policy",
		Verdict:         VerdictFail,
		RulesEvaluated:  5,
		FindingsChecked: 12,
		Violations: []Violation{
			{RuleID: "r1", Severity: "error", Action: "fail", Message: "aggregate bad algo"},
			{RuleID: "r2", Severity: "warning", Action: "warn", Message: "aggregate weak key"},
		},
		ThresholdViolations: []ThresholdViolation{
			{Name: "min_safe_percent", Expected: ">= 50.0%", Actual: "25.0%", Message: "too low"},
		},
		SystemEvaluations: []SystemEvaluation{
			{
				SystemName:      "TLS Service",
				Verdict:         VerdictFail,
				FindingsChecked: 3,
				Violations: []Violation{
					{RuleID: "r1", Severity: "error", Action: "fail", Message: "bad algo"},
				},
				ThresholdViolations: []ThresholdViolation{
					{Name: "max_unsafe", Expected: "<= 0", Actual: "1", Message: "too many"},
				},
			},
		},
	}

	mr := eval.ToModelResult()
	require.NotNil(t, mr)
	assert.Equal(t, "test-policy", mr.PolicyName)
	assert.Equal(t, "FAIL", mr.Verdict)
	assert.Equal(t, 5, mr.RulesEvaluated)
	assert.Equal(t, 12, mr.FindingsChecked)

	// Aggregate violations
	require.Len(t, mr.Violations, 2)
	assert.Equal(t, "r1", mr.Violations[0].RuleID)
	assert.Equal(t, "fail", mr.Violations[0].Action)
	assert.Equal(t, "r2", mr.Violations[1].RuleID)

	// Aggregate threshold violations
	require.Len(t, mr.ThresholdViolations, 1)
	assert.Equal(t, "min_safe_percent", mr.ThresholdViolations[0].Name)
	assert.Equal(t, ">= 50.0%", mr.ThresholdViolations[0].Expected)
	assert.Equal(t, "25.0%", mr.ThresholdViolations[0].Actual)

	// Per-system evaluations
	require.Len(t, mr.SystemEvaluations, 1)
	assert.Equal(t, "TLS Service", mr.SystemEvaluations[0].SystemName)
	assert.Equal(t, "FAIL", mr.SystemEvaluations[0].Verdict)
	assert.Len(t, mr.SystemEvaluations[0].Violations, 1)
	assert.Len(t, mr.SystemEvaluations[0].ThresholdViolations, 1)
	assert.Equal(t, "r1", mr.SystemEvaluations[0].Violations[0].RuleID)
}

func TestMatchSystemPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"TLS Service (localhost:443)", "TLS*", true},
		{"TLS Service (localhost:443)", "*443*", true},
		{"SSH Service (10.0.0.1:22)", "SSH*", true},
		{"Files in /etc/ssl", "Files*", true},
		{"TLS Service (localhost:443)", "SSH*", false},
		{"any", "", true},
		{"any", "*", true},
		{"TLS Service", "tls*", true},         // case-insensitive
		{"TLS Service", "TLS Service", true},  // exact match
		{"TLS Service", "SSH Service", false}, // exact non-match
		{"", "TLS*", false},                   // empty name
		{"TLS Service", "**", true},           // double star
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.want, matchSystemPattern(tt.name, tt.pattern))
		})
	}
}

func TestEvaluate_SystemPatternRule(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:       "scripts-unsafe",
				Severity: "error",
				Condition: Condition{
					PQCStatus:     "UNSAFE",
					SystemPattern: "Files*",
				},
				Action: "fail",
			},
		},
	}

	result := &model.ScanResult{
		ID: "test",
		Findings: []model.Finding{
			{
				ID:     "f1",
				Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				Module: "certificates",
				CryptoAsset: &model.CryptoAsset{
					Algorithm:  "DES",
					PQCStatus:  "UNSAFE",
					SystemName: "Files in /etc/ssl",
				},
			},
			{
				ID:     "f2",
				Source: model.FindingSource{Type: "file", Path: "/home/user/key.pem"},
				Module: "keys",
				CryptoAsset: &model.CryptoAsset{
					Algorithm:  "DES",
					PQCStatus:  "UNSAFE",
					SystemName: "Files in /home/user",
				},
			},
		},
		Summary: model.Summary{Unsafe: 2},
	}

	eval := Evaluate(pol, result, nil)
	// Both findings should match the SystemPattern "Files*"
	assert.Equal(t, VerdictFail, eval.Verdict)
	assert.Len(t, eval.Violations, 2)
}

func TestEvaluateSystem_PerSystemThresholds(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Threshold Test",
		Thresholds: Thresholds{
			PerSystem: []SystemThresholds{
				{
					SystemPattern:  "*",
					MaxUnsafeCount: intPtr(0),
					MinSafePercent: 50.0,
				},
			},
		},
	}

	sys := &model.System{
		Name: "Mixed System",
		CryptoAssets: []model.CryptoAsset{
			{Algorithm: "DES", PQCStatus: "UNSAFE"},
			{Algorithm: "AES-256-GCM", PQCStatus: "SAFE"},
		},
	}

	eval := EvaluateSystem(pol, sys)
	assert.Equal(t, VerdictFail, eval.Verdict)
	// 50% safe (1/2) == 50.0% threshold (strict less-than), so only MaxUnsafeCount triggers
	require.Len(t, eval.ThresholdViolations, 1)
	assert.Equal(t, "per_system_max_unsafe", eval.ThresholdViolations[0].Name)
	assert.Equal(t, "1", eval.ThresholdViolations[0].Actual)
}

func TestEvaluate_RiskLevelOnViolation(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-unsafe",
				Severity:  "error",
				RiskLevel: "critical",
				Condition: Condition{PQCStatus: "UNSAFE"},
				Action:    "fail",
			},
		},
	}

	eval := Evaluate(pol, testResult(), nil)
	require.Len(t, eval.Violations, 1)
	assert.Equal(t, "critical", eval.Violations[0].RiskLevel)
}

func TestEvaluate_RiskLevelDefaultsMedium(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-unsafe",
				Severity:  "error",
				Condition: Condition{PQCStatus: "UNSAFE"},
				Action:    "fail",
				// RiskLevel intentionally omitted — should default to "medium"
			},
		},
	}

	eval := Evaluate(pol, testResult(), nil)
	require.Len(t, eval.Violations, 1)
	assert.Equal(t, "medium", eval.Violations[0].RiskLevel)
}

func TestEvaluate_RiskSummary(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{ID: "r-critical-1", Severity: "error", RiskLevel: "critical", Condition: Condition{PQCStatus: "UNSAFE"}, Action: "fail"},
			{ID: "r-critical-2", Severity: "error", RiskLevel: "critical", Condition: Condition{Algorithm: "DES"}, Action: "fail"},
			{ID: "r-high", Severity: "error", RiskLevel: "high", Condition: Condition{PQCStatus: "DEPRECATED"}, Action: "warn"},
			{ID: "r-low", Severity: "warning", RiskLevel: "low", Condition: Condition{Algorithm: "MD5"}, Action: "warn"},
		},
	}

	// testResult has: DES (UNSAFE), MD5 (DEPRECATED)
	// r-critical-1 matches DES (UNSAFE): 1 critical
	// r-critical-2 matches DES: 1 critical
	// r-high matches MD5 (DEPRECATED): 1 high
	// r-low matches MD5: 1 low
	eval := Evaluate(pol, testResult(), nil)
	require.NotNil(t, eval.RiskSummary)
	assert.Equal(t, 2, eval.RiskSummary.Critical)
	assert.Equal(t, 1, eval.RiskSummary.High)
	assert.Equal(t, 0, eval.RiskSummary.Medium)
	assert.Equal(t, 1, eval.RiskSummary.Low)
}

func TestEvaluate_RiskSummaryNilWhenNoViolations(t *testing.T) {
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

	eval := Evaluate(pol, testResult(), nil)
	assert.Empty(t, eval.Violations)
	assert.Nil(t, eval.RiskSummary)
}

// --- Task 4: Exemption wiring into Evaluate() ---

func TestEvaluate_WithExemptions(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-sha1",
				Severity:  "error",
				Condition: Condition{Algorithm: "SHA-1"},
				Action:    "fail",
			},
		},
	}

	result := &model.ScanResult{
		ID: "test-scan",
		Findings: []model.Finding{
			{
				ID:     "f1",
				Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				Module: "certificates",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "SHA-1",
					PQCStatus: "DEPRECATED",
				},
			},
		},
		Summary: model.Summary{TotalFindings: 1, Deprecated: 1},
	}

	el, err := ParseExemptions([]byte(`
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy system, migration planned Q4"
    expires: "2099-01-01"
    approved_by: "security-team"
`))
	require.NoError(t, err)

	eval := Evaluate(pol, result, el)
	// Exemption suppresses the SHA-1 violation
	assert.Equal(t, VerdictPass, eval.Verdict)
	assert.Empty(t, eval.Violations)
	// Audit trail: one exemption applied
	mr := eval.ToModelResult()
	require.NotNil(t, mr)
	require.Len(t, mr.ExemptionsApplied, 1)
	ea := mr.ExemptionsApplied[0]
	assert.Equal(t, "Legacy system, migration planned Q4", ea.Reason)
	assert.Equal(t, "security-team", ea.ApprovedBy)
	assert.Equal(t, 1, ea.FindingCount)
	assert.Equal(t, "SHA-1", ea.Algorithm)
}

func TestEvaluate_ExemptionExpired(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "Test",
		Rules: []Rule{
			{
				ID:        "no-sha1",
				Severity:  "error",
				Condition: Condition{Algorithm: "SHA-1"},
				Action:    "fail",
			},
		},
	}

	result := &model.ScanResult{
		ID: "test-scan",
		Findings: []model.Finding{
			{
				ID:     "f1",
				Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				Module: "certificates",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "SHA-1",
					PQCStatus: "DEPRECATED",
				},
			},
		},
		Summary: model.Summary{TotalFindings: 1, Deprecated: 1},
	}

	el, err := ParseExemptions([]byte(`
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Expired legacy exemption"
    expires: "2020-01-01"
`))
	require.NoError(t, err)

	eval := Evaluate(pol, result, el)
	// Expired exemption → violation is NOT suppressed
	assert.Equal(t, VerdictFail, eval.Verdict)
	require.Len(t, eval.Violations, 1)
	// Audit trail: one expired exemption reported
	mr := eval.ToModelResult()
	require.NotNil(t, mr)
	assert.Empty(t, mr.ExemptionsApplied)
	require.Len(t, mr.ExemptionsExpired, 1)
	assert.Equal(t, "SHA-1", mr.ExemptionsExpired[0].Algorithm)
	assert.Equal(t, "2020-01-01", mr.ExemptionsExpired[0].ExpiredOn)
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
