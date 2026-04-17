# Policy Risk Levels + Exemptions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add risk level classification (critical/high/medium/low) to policy rules and a separate exemptions YAML file for excluding known-accepted findings from policy violations.

**Architecture:** Risk levels are a string field on `Rule`, carried through `Violation` → `model.PolicyViolation` → reports. A `RiskSummary` is computed after evaluation. Exemptions are loaded from a separate YAML file and applied as a pre-filter before rule matching in `Evaluate()`. Both features are backward-compatible (nil-safe, optional fields).

**Tech Stack:** Go 1.25, existing `gopkg.in/yaml.v3`, `path/filepath` for glob matching. No new dependencies.

---

## File Map

### New files

| File | Responsibility |
|------|----------------|
| `pkg/policy/exemptions.go` | `ExemptionList`, `Exemption` types, `LoadExemptions()`, `ValidateExemptions()`, `IsExempt()` |
| `pkg/policy/exemptions_test.go` | Exemption parsing, matching, expiry, validation, nil-safety tests |

### Modified files

| File | Changes |
|------|---------|
| `pkg/policy/policy.go` | Add `RiskLevel string` to `Rule` struct |
| `pkg/policy/engine.go` | Add `*ExemptionList` param to `Evaluate()`. Pre-filter exemptions. Compute `RiskSummary`. Carry `RiskLevel` to `Violation`. Update `ToModelResult()`. |
| `pkg/policy/engine_test.go` | Add risk level + exemption integration tests |
| `pkg/model/types.go` | Add `RiskLevel` to `PolicyViolation`. Add `RiskSummary`, `ExemptionApplied`, `ExemptionExpired` types. Add fields to `PolicyEvaluationResult`. |
| `pkg/policy/builtin/nacsa-2030.yaml` | Add `risk_level` to each rule |
| `pkg/policy/builtin/cnsa-2.0.yaml` | Add `risk_level` to each rule |
| `cmd/root.go` | Add `--exemptions` flag + env var wiring |
| `pkg/report/generator.go` | Risk breakdown bar, risk badges on violations, exemptions section |
| `pkg/report/cyclonedx.go` | `triton:risk-level` property |

---

## Phase 1: Model + Risk Levels

### Task 1: Add model types for risk summary and exemptions

**Files:**
- Modify: `pkg/model/types.go`

- [ ] **Step 1: Add RiskLevel to PolicyViolation**

After the existing `Message` field in `PolicyViolation` (around line 53), add:

```go
RiskLevel string `json:"riskLevel,omitempty"` // critical|high|medium|low
```

- [ ] **Step 2: Add new types and fields to PolicyEvaluationResult**

After the `SystemEvaluations` field in `PolicyEvaluationResult` (around line 81), add:

```go
RiskSummary       *RiskSummary       `json:"riskSummary,omitempty"`
ExemptionsApplied []ExemptionApplied `json:"exemptionsApplied,omitempty"`
ExemptionsExpired []ExemptionExpired `json:"exemptionsExpired,omitempty"`
```

Add new types after `PolicyEvaluationResult`:

```go
// RiskSummary counts policy violations by risk level.
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ExemptionApplied records an exemption that matched findings during evaluation.
type ExemptionApplied struct {
	Reason       string `json:"reason"`
	Expires      string `json:"expires,omitempty"`
	ApprovedBy   string `json:"approvedBy,omitempty"`
	FindingCount int    `json:"findingCount"`
	Algorithm    string `json:"algorithm,omitempty"`
	Location     string `json:"location,omitempty"`
}

// ExemptionExpired records an exemption that has passed its expiry date.
type ExemptionExpired struct {
	Algorithm string `json:"algorithm"`
	Location  string `json:"location,omitempty"`
	ExpiredOn string `json:"expiredOn"`
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add pkg/model/types.go
git commit -m "model: add RiskSummary, ExemptionApplied, ExemptionExpired types"
```

### Task 2: Add risk_level to Rule and wire through engine

**Files:**
- Modify: `pkg/policy/policy.go`
- Modify: `pkg/policy/engine.go`
- Modify: `pkg/policy/engine_test.go`

- [ ] **Step 1: Write failing tests**

Add to `pkg/policy/engine_test.go`:

```go
func TestEvaluate_RiskLevelOnViolation(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "risk-test",
		Rules: []Rule{{
			ID:        "critical-rule",
			Severity:  "error",
			RiskLevel: "critical",
			Condition: Condition{PQCStatus: "UNSAFE"},
			Action:    "fail",
		}},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "f1", Module: "test",
			CryptoAsset: &model.CryptoAsset{Algorithm: "DES", PQCStatus: "UNSAFE"},
		}},
	}
	eval := Evaluate(pol, result, nil)
	require.Len(t, eval.Violations, 1)
	assert.Equal(t, "critical", eval.Violations[0].RiskLevel)
}

func TestEvaluate_RiskLevelDefaultsMedium(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "default-risk",
		Rules: []Rule{{
			ID:        "no-risk-level",
			Severity:  "error",
			Condition: Condition{PQCStatus: "UNSAFE"},
			Action:    "fail",
			// RiskLevel intentionally omitted
		}},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "f1", Module: "test",
			CryptoAsset: &model.CryptoAsset{Algorithm: "DES", PQCStatus: "UNSAFE"},
		}},
	}
	eval := Evaluate(pol, result, nil)
	require.Len(t, eval.Violations, 1)
	assert.Equal(t, "medium", eval.Violations[0].RiskLevel, "should default to medium")
}

func TestEvaluate_RiskSummary(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "risk-summary",
		Rules: []Rule{
			{ID: "r1", Severity: "error", RiskLevel: "critical", Condition: Condition{Algorithm: "DES"}, Action: "fail"},
			{ID: "r2", Severity: "error", RiskLevel: "critical", Condition: Condition{Algorithm: "RC4"}, Action: "fail"},
			{ID: "r3", Severity: "warning", RiskLevel: "high", Condition: Condition{Algorithm: "MD5"}, Action: "warn"},
			{ID: "r4", Severity: "warning", RiskLevel: "low", Condition: Condition{Algorithm: "SHA-256"}, Action: "warn"},
		},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{
			{ID: "f1", CryptoAsset: &model.CryptoAsset{Algorithm: "DES"}},
			{ID: "f2", CryptoAsset: &model.CryptoAsset{Algorithm: "RC4"}},
			{ID: "f3", CryptoAsset: &model.CryptoAsset{Algorithm: "MD5"}},
			{ID: "f4", CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-256"}},
		},
	}
	eval := Evaluate(pol, result, nil)
	require.NotNil(t, eval.RiskSummary)
	assert.Equal(t, 2, eval.RiskSummary.Critical)
	assert.Equal(t, 1, eval.RiskSummary.High)
	assert.Equal(t, 0, eval.RiskSummary.Medium)
	assert.Equal(t, 1, eval.RiskSummary.Low)
}

func TestEvaluate_RiskSummaryNilWhenNoViolations(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "no-violations",
		Rules: []Rule{{
			ID: "r1", Severity: "error", RiskLevel: "critical",
			Condition: Condition{Algorithm: "NONEXISTENT"}, Action: "fail",
		}},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{
			{ID: "f1", CryptoAsset: &model.CryptoAsset{Algorithm: "AES-256"}},
		},
	}
	eval := Evaluate(pol, result, nil)
	assert.Nil(t, eval.RiskSummary, "no violations = nil risk summary")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestEvaluate_RiskLevel|TestEvaluate_RiskSummary" ./pkg/policy/...`
Expected: FAIL — `Evaluate` signature mismatch (3 args vs 2), `RiskLevel` field not found.

- [ ] **Step 3: Add RiskLevel to Rule in policy.go**

In `pkg/policy/policy.go`, add to the `Rule` struct after `Message`:

```go
RiskLevel string `yaml:"risk_level,omitempty" json:"risk_level,omitempty"` // critical|high|medium|low; default "medium"
```

- [ ] **Step 4: Update Violation and engine.go**

In `pkg/policy/engine.go`:

1. Add `RiskLevel string` to the `Violation` struct (after `Message`).

2. Add `RiskSummary *RiskSummary` to `EvaluationResult` (after `SystemEvaluations`). Define `RiskSummary` in engine.go:

```go
// RiskSummary counts violations by risk level.
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
```

3. Change `Evaluate` signature to accept exemptions (nil for now):

```go
func Evaluate(pol *Policy, result *model.ScanResult, exemptions *ExemptionList) *EvaluationResult {
```

For now, add `type ExemptionList struct{}` as a placeholder at the top of engine.go so it compiles. The real implementation comes in Task 3.

4. In the violation creation block (line ~87-93), add risk level:

```go
riskLevel := rule.RiskLevel
if riskLevel == "" {
	riskLevel = "medium"
}
eval.Violations = append(eval.Violations, Violation{
	RuleID:    rule.ID,
	Severity:  rule.Severity,
	Action:    rule.Action,
	Message:   msg,
	RiskLevel: riskLevel,
	Finding:   f,
})
```

Do the same in `EvaluateSystem` (line ~150-155).

5. After the main evaluation loop, compute RiskSummary:

```go
if len(eval.Violations) > 0 {
	rs := &RiskSummary{}
	for _, v := range eval.Violations {
		switch v.RiskLevel {
		case "critical":
			rs.Critical++
		case "high":
			rs.High++
		case "medium":
			rs.Medium++
		case "low":
			rs.Low++
		}
	}
	eval.RiskSummary = rs
}
```

6. Update `ToModelResult()` to carry RiskLevel and RiskSummary:

In the violations loop, add `RiskLevel: v.RiskLevel` to the `model.PolicyViolation`.

After building `r`, add:
```go
if e.RiskSummary != nil {
	r.RiskSummary = &model.RiskSummary{
		Critical: e.RiskSummary.Critical,
		High:     e.RiskSummary.High,
		Medium:   e.RiskSummary.Medium,
		Low:      e.RiskSummary.Low,
	}
}
```

7. Fix ALL existing callers of `Evaluate()` to pass `nil` as the third argument. Search for `policy.Evaluate(` in `cmd/root.go`, `pkg/server/`, and test files.

- [ ] **Step 5: Run tests**

Run: `go test -v -run "TestEvaluate_RiskLevel|TestEvaluate_RiskSummary" ./pkg/policy/...`
Expected: all 4 new tests PASS.

- [ ] **Step 6: Run all existing policy tests**

Run: `go test -v ./pkg/policy/... -count=1`
Expected: all pass (existing tests unaffected since `nil` exemptions = no change).

- [ ] **Step 7: Verify full build**

Run: `go build ./...`
Expected: clean (all callers updated with nil third arg).

- [ ] **Step 8: Commit**

```bash
git add pkg/policy/policy.go pkg/policy/engine.go pkg/policy/engine_test.go cmd/root.go
git commit -m "feat(policy): add risk_level to rules with RiskSummary computation"
```

---

## Phase 2: Exemptions

### Task 3: Exemptions loader and matcher

**Files:**
- Create: `pkg/policy/exemptions.go`
- Create: `pkg/policy/exemptions_test.go`

- [ ] **Step 1: Write failing tests**

```go
package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestLoadExemptions_ValidYAML(t *testing.T) {
	yaml := `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    location: "/etc/ssh/sshd_config"
    reason: "Vendor requires SHA-1"
    expires: "2027-12-31"
    approved_by: "CISO"
`
	el, err := ParseExemptions([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, el.Exemptions, 1)
	assert.Equal(t, "algorithm", el.Exemptions[0].Type)
	assert.Equal(t, "SHA-1", el.Exemptions[0].Algorithm)
	assert.Equal(t, "CISO", el.Exemptions[0].ApprovedBy)
}

func TestLoadExemptions_MissingReason(t *testing.T) {
	yaml := `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
`
	_, err := ParseExemptions([]byte(yaml))
	assert.Error(t, err, "reason is required")
}

func TestLoadExemptions_MissingVersion(t *testing.T) {
	yaml := `
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "test"
`
	_, err := ParseExemptions([]byte(yaml))
	assert.Error(t, err)
}

func TestIsExempt_AlgorithmMatch(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "test",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, idx := el.IsExempt(f, time.Now())
	assert.True(t, exempt)
	assert.Equal(t, 0, idx)
}

func TestIsExempt_AlgorithmCaseInsensitive(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "sha-1", Reason: "test",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.True(t, exempt)
}

func TestIsExempt_AlgorithmWithLocation(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Location: "/etc/ssh/sshd_config", Reason: "test",
		}},
	}
	match := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
		Source:      model.FindingSource{Path: "/etc/ssh/sshd_config"},
	}
	noMatch := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
		Source:      model.FindingSource{Path: "/etc/nginx/nginx.conf"},
	}
	exempt, _ := el.IsExempt(match, time.Now())
	assert.True(t, exempt)
	exempt, _ = el.IsExempt(noMatch, time.Now())
	assert.False(t, exempt)
}

func TestIsExempt_AlgorithmWithLocationGlob(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Location: "/etc/ssh/*", Reason: "test",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
		Source:      model.FindingSource{Path: "/etc/ssh/sshd_config"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.True(t, exempt)
}

func TestIsExempt_AlgorithmWithModule(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Module: "configs", Reason: "test",
		}},
	}
	match := &model.Finding{
		Module:      "configs",
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	noMatch := &model.Finding{
		Module:      "certificates",
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, _ := el.IsExempt(match, time.Now())
	assert.True(t, exempt)
	exempt, _ = el.IsExempt(noMatch, time.Now())
	assert.False(t, exempt)
}

func TestIsExempt_Thumbprint(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type:         "thumbprint",
			SerialNumber: "12345",
			Issuer:       "CN=Test CA",
			Reason:       "legacy CA",
		}},
	}
	match := &model.Finding{
		CryptoAsset: &model.CryptoAsset{SerialNumber: "12345", Issuer: "CN=Test CA"},
	}
	noMatch := &model.Finding{
		CryptoAsset: &model.CryptoAsset{SerialNumber: "99999", Issuer: "CN=Test CA"},
	}
	exempt, _ := el.IsExempt(match, time.Now())
	assert.True(t, exempt)
	exempt, _ = el.IsExempt(noMatch, time.Now())
	assert.False(t, exempt)
}

func TestIsExempt_Expired(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "test",
			Expires: "2020-01-01",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.False(t, exempt, "expired exemption should not match")
}

func TestIsExempt_NotExpired(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "test",
			Expires: "2099-12-31",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.True(t, exempt)
}

func TestIsExempt_NilList(t *testing.T) {
	var el *ExemptionList
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.False(t, exempt, "nil list should never exempt")
}

func TestIsExempt_NilAsset(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "test",
		}},
	}
	f := &model.Finding{CryptoAsset: nil}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.False(t, exempt, "nil asset should never match")
}

func TestIsExempt_AlgorithmMismatch(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "test",
		}},
	}
	f := &model.Finding{
		CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-256"},
	}
	exempt, _ := el.IsExempt(f, time.Now())
	assert.False(t, exempt)
}

func TestExpiredExemptions(t *testing.T) {
	el := &ExemptionList{
		Exemptions: []Exemption{
			{Type: "algorithm", Algorithm: "SHA-1", Reason: "test", Expires: "2020-01-01"},
			{Type: "algorithm", Algorithm: "3DES", Reason: "test2"},
		},
	}
	expired := el.ExpiredExemptions(time.Now())
	require.Len(t, expired, 1)
	assert.Equal(t, "SHA-1", expired[0].Algorithm)
	assert.Equal(t, "2020-01-01", expired[0].ExpiredOn)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestLoadExemptions|TestIsExempt|TestExpiredExemptions" ./pkg/policy/...`
Expected: FAIL — types not defined.

- [ ] **Step 3: Implement exemptions.go**

```go
package policy

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/amiryahaya/triton/pkg/model"
)

// ExemptionList holds known-accepted findings that should be excluded from
// policy violations. Loaded from a separate YAML file via --exemptions flag.
type ExemptionList struct {
	Version    string      `yaml:"version"`
	Exemptions []Exemption `yaml:"exemptions"`
}

// Exemption defines a single finding to exempt from policy evaluation.
type Exemption struct {
	Type         string `yaml:"type"`                    // "thumbprint" or "algorithm"
	Algorithm    string `yaml:"algorithm,omitempty"`      // for type=algorithm
	Location     string `yaml:"location,omitempty"`       // glob pattern for source path
	Module       string `yaml:"module,omitempty"`         // module name filter
	SerialNumber string `yaml:"serial_number,omitempty"`  // for type=thumbprint
	Issuer       string `yaml:"issuer,omitempty"`         // for type=thumbprint
	Reason       string `yaml:"reason"`                   // required — audit trail
	Expires      string `yaml:"expires,omitempty"`        // ISO date (YYYY-MM-DD), optional
	ApprovedBy   string `yaml:"approved_by,omitempty"`    // optional
}

// ParseExemptions parses YAML bytes into an ExemptionList and validates.
func ParseExemptions(data []byte) (*ExemptionList, error) {
	var el ExemptionList
	if err := yaml.Unmarshal(data, &el); err != nil {
		return nil, fmt.Errorf("parsing exemptions YAML: %w", err)
	}
	if el.Version == "" {
		return nil, fmt.Errorf("exemptions missing required 'version' field")
	}
	for i, e := range el.Exemptions {
		if e.Reason == "" {
			return nil, fmt.Errorf("exemption %d: 'reason' is required", i)
		}
		if e.Type != "algorithm" && e.Type != "thumbprint" {
			return nil, fmt.Errorf("exemption %d: type must be 'algorithm' or 'thumbprint', got %q", i, e.Type)
		}
	}
	return &el, nil
}

// LoadExemptionsFile loads and parses an exemptions YAML file.
func LoadExemptionsFile(path string) (*ExemptionList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading exemptions file: %w", err)
	}
	return ParseExemptions(data)
}

// IsExempt checks whether a finding is exempted. Returns (true, index) if
// an exemption matches, (false, -1) otherwise. Nil-safe: a nil ExemptionList
// never exempts anything.
func (el *ExemptionList) IsExempt(f *model.Finding, now time.Time) (bool, int) {
	if el == nil || f == nil || f.CryptoAsset == nil {
		return false, -1
	}

	for i, e := range el.Exemptions {
		// Check expiry
		if e.Expires != "" {
			expiry, err := time.Parse("2006-01-02", e.Expires)
			if err == nil && now.After(expiry) {
				continue // expired exemption — skip
			}
		}

		switch e.Type {
		case "thumbprint":
			if e.SerialNumber != "" && f.CryptoAsset.SerialNumber == e.SerialNumber &&
				e.Issuer != "" && strings.EqualFold(f.CryptoAsset.Issuer, e.Issuer) {
				return true, i
			}

		case "algorithm":
			if !strings.EqualFold(f.CryptoAsset.Algorithm, e.Algorithm) {
				continue
			}
			// Algorithm matches — check optional location/module narrowing
			if e.Location != "" {
				matched, _ := filepath.Match(e.Location, f.Source.Path)
				if !matched {
					continue
				}
			}
			if e.Module != "" && !strings.EqualFold(f.Module, e.Module) {
				continue
			}
			return true, i
		}
	}
	return false, -1
}

// ExpiredExemptions returns exemptions that have passed their expiry date.
func (el *ExemptionList) ExpiredExemptions(now time.Time) []model.ExemptionExpired {
	if el == nil {
		return nil
	}
	var expired []model.ExemptionExpired
	for _, e := range el.Exemptions {
		if e.Expires == "" {
			continue
		}
		expiry, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			continue
		}
		if now.After(expiry) {
			expired = append(expired, model.ExemptionExpired{
				Algorithm: e.Algorithm,
				Location:  e.Location,
				ExpiredOn: e.Expires,
			})
		}
	}
	return expired
}
```

Note: Add `"os"` to the imports.

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestLoadExemptions|TestIsExempt|TestExpiredExemptions" ./pkg/policy/...`
Expected: all 14 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/policy/exemptions.go pkg/policy/exemptions_test.go
git commit -m "feat(policy): add exemptions loader with matching and expiry"
```

### Task 4: Wire exemptions into Evaluate()

**Files:**
- Modify: `pkg/policy/engine.go`
- Modify: `pkg/policy/engine_test.go`

- [ ] **Step 1: Write failing tests**

Add to `engine_test.go`:

```go
func TestEvaluate_WithExemptions(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "exempt-test",
		Rules: []Rule{{
			ID: "no-sha1", Severity: "error", RiskLevel: "high",
			Condition: Condition{Algorithm: "SHA-1"}, Action: "fail",
		}},
	}
	exemptions := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "vendor required",
		}},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "f1", Module: "test",
			CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
		}},
	}
	eval := Evaluate(pol, result, exemptions)
	assert.Empty(t, eval.Violations, "exempted finding should produce no violations")
	assert.Equal(t, VerdictPass, eval.Verdict)
	require.Len(t, eval.ExemptionsApplied, 1)
	assert.Equal(t, "vendor required", eval.ExemptionsApplied[0].Reason)
	assert.Equal(t, 1, eval.ExemptionsApplied[0].FindingCount)
}

func TestEvaluate_ExemptionExpired(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "expired-exempt",
		Rules: []Rule{{
			ID: "no-sha1", Severity: "error", RiskLevel: "high",
			Condition: Condition{Algorithm: "SHA-1"}, Action: "fail",
		}},
	}
	exemptions := &ExemptionList{
		Exemptions: []Exemption{{
			Type: "algorithm", Algorithm: "SHA-1", Reason: "was accepted",
			Expires: "2020-01-01",
		}},
	}
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "f1", Module: "test",
			CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1"},
		}},
	}
	eval := Evaluate(pol, result, exemptions)
	assert.NotEmpty(t, eval.Violations, "expired exemption should not prevent violation")
	assert.Equal(t, VerdictFail, eval.Verdict)
	require.Len(t, eval.ExemptionsExpired, 1)
	assert.Equal(t, "2020-01-01", eval.ExemptionsExpired[0].ExpiredOn)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestEvaluate_WithExemptions|TestEvaluate_ExemptionExpired" ./pkg/policy/...`
Expected: FAIL — `ExemptionsApplied`/`ExemptionsExpired` fields don't exist on EvaluationResult.

- [ ] **Step 3: Update engine.go**

1. Remove the placeholder `type ExemptionList struct{}` (if added in Task 2). The real type is now in `exemptions.go`.

2. Add fields to `EvaluationResult`:

```go
ExemptionsApplied []model.ExemptionApplied `json:"exemptionsApplied,omitempty"`
ExemptionsExpired []model.ExemptionExpired `json:"exemptionsExpired,omitempty"`
```

3. In `Evaluate()`, add exemption pre-filter before the rule loop. Replace the finding loop (lines ~78-101) with:

```go
now := time.Now()
exemptionHits := make(map[int]int) // exemption index → hit count

for i := range result.Findings {
	f := &result.Findings[i]

	// Pre-filter: check exemptions before rules
	if exempt, idx := exemptions.IsExempt(f, now); exempt {
		exemptionHits[idx]++
		continue
	}

	for j := range pol.Rules {
		rule := &pol.Rules[j]
		if matchesCondition(f, &rule.Condition) {
			// ... existing violation creation with RiskLevel ...
		}
	}
}
```

4. After the evaluation loop, build `ExemptionsApplied`:

```go
if exemptions != nil {
	for idx, count := range exemptionHits {
		e := exemptions.Exemptions[idx]
		eval.ExemptionsApplied = append(eval.ExemptionsApplied, model.ExemptionApplied{
			Reason:       e.Reason,
			Expires:      e.Expires,
			ApprovedBy:   e.ApprovedBy,
			FindingCount: count,
			Algorithm:    e.Algorithm,
			Location:     e.Location,
		})
	}
	eval.ExemptionsExpired = exemptions.ExpiredExemptions(now)
}
```

5. Update `ToModelResult()` to carry exemptions:

```go
r.ExemptionsApplied = e.ExemptionsApplied
r.ExemptionsExpired = e.ExemptionsExpired
```

6. Add `"time"` to imports.

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestEvaluate_WithExemptions|TestEvaluate_ExemptionExpired" ./pkg/policy/...`
Expected: both PASS.

- [ ] **Step 5: Run all policy tests**

Run: `go test -v ./pkg/policy/... -count=1`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/policy/engine.go pkg/policy/engine_test.go
git commit -m "feat(policy): wire exemptions into Evaluate() with audit trail"
```

---

## Phase 3: Builtin Updates + CLI

### Task 5: Update builtin policies with risk levels

**Files:**
- Modify: `pkg/policy/builtin/nacsa-2030.yaml`
- Modify: `pkg/policy/builtin/cnsa-2.0.yaml`

- [ ] **Step 1: Update nacsa-2030.yaml**

Add `risk_level` to each rule:

```yaml
version: "1"
name: "NACSA PQC Compliance 2030"
rules:
  - id: no-unsafe-algorithms
    severity: error
    risk_level: critical
    condition:
      pqc_status: UNSAFE
    action: fail
    message: "UNSAFE algorithm detected — must be replaced before 2030"

  - id: no-rsa-below-2048
    severity: error
    risk_level: critical
    condition:
      algorithm_family: RSA
      key_size_below: 2048
    action: fail
    message: "RSA key below 2048 bits — non-compliant"

  - id: no-des
    severity: error
    risk_level: critical
    condition:
      algorithm_family: DES
    action: fail
    message: "DES/3DES detected — must migrate to AES-256 or PQC-safe algorithm"

  - id: no-md5
    severity: error
    risk_level: high
    condition:
      algorithm: MD5
    action: fail
    message: "MD5 detected — must migrate to SHA-256 or stronger"

  - id: no-sha1
    severity: warning
    risk_level: high
    condition:
      algorithm: SHA-1
    action: warn
    message: "SHA-1 detected — deprecated, migrate to SHA-256+"

  - id: no-rc4
    severity: error
    risk_level: critical
    condition:
      algorithm: RC4
    action: fail
    message: "RC4 detected — broken cipher, must be removed"

  - id: deprecated-warning
    severity: warning
    risk_level: medium
    condition:
      pqc_status: DEPRECATED
    action: warn
    message: "Deprecated algorithm — create migration plan"

thresholds:
  min_nacsa_readiness: 60.0
  max_unsafe_count: 0
```

- [ ] **Step 2: Update cnsa-2.0.yaml**

Add `risk_level` to each rule:

```yaml
version: "1"
name: "CNSA 2.0 Commercial National Security Algorithm Suite"
rules:
  - id: cnsa2-no-unsafe
    severity: error
    risk_level: critical
    condition:
      pqc_status: UNSAFE
    action: fail
    message: "CNSA 2.0 violation — UNSAFE algorithm must be replaced"

  - id: cnsa2-no-rsa-below-3072
    severity: error
    risk_level: critical
    condition:
      algorithm_family: RSA
      key_size_below: 3072
    action: fail
    message: "CNSA 2.0 requires RSA >= 3072 bits (RSA-4096 recommended)"

  - id: cnsa2-no-ecdsa-below-384
    severity: error
    risk_level: high
    condition:
      algorithm_family: ECDSA
      key_size_below: 384
    action: fail
    message: "CNSA 2.0 requires ECDSA P-384 or stronger"

  - id: cnsa2-no-sha-below-384
    severity: warning
    risk_level: low
    condition:
      algorithm: SHA-256
    action: warn
    message: "CNSA 2.0 prefers SHA-384 or SHA-512"

  - id: cnsa2-no-deprecated
    severity: warning
    risk_level: medium
    condition:
      pqc_status: DEPRECATED
    action: warn
    message: "CNSA 2.0 — deprecated algorithm should be migrated"

thresholds:
  max_unsafe_count: 0
  min_safe_percent: 50.0
```

- [ ] **Step 3: Verify builtins load correctly**

Run: `go test -v -run TestBuiltin ./pkg/policy/... -count=1`
Expected: PASS (existing builtin tests should still parse correctly).

- [ ] **Step 4: Commit**

```bash
git add pkg/policy/builtin/nacsa-2030.yaml pkg/policy/builtin/cnsa-2.0.yaml
git commit -m "feat(policy): add risk_level to NACSA-2030 and CNSA-2.0 builtin rules"
```

### Task 6: CLI --exemptions flag

**Files:**
- Modify: `cmd/root.go`

- [ ] **Step 1: Add flag and env var**

After the `--policy` flag declaration (around line 163), add:

```go
rootCmd.PersistentFlags().String("exemptions", "",
	"Exemptions YAML file for known-accepted findings (env: TRITON_EXEMPTIONS_FILE)")
```

- [ ] **Step 2: Wire into evaluateScanPolicy**

In `evaluateScanPolicy()` (around line 700), after loading the policy, load exemptions:

```go
var exemptions *policy.ExemptionList
exemptionsPath, _ := cmd.Flags().GetString("exemptions")
if exemptionsPath == "" {
	exemptionsPath = os.Getenv("TRITON_EXEMPTIONS_FILE")
}
if exemptionsPath != "" {
	exemptions, err = policy.LoadExemptionsFile(exemptionsPath)
	if err != nil {
		return fmt.Errorf("loading exemptions: %w", err)
	}
}

eval := policy.Evaluate(pol, result, exemptions)
```

Note: `evaluateScanPolicy` currently doesn't take `cmd` as a parameter. You'll need to either pass the exemptions path as a package-level var (like `scanPolicyArg`) or restructure slightly. Follow the existing pattern: add a `var scanExemptionsArg string` at the top of the file and bind it to the flag, then use it in `evaluateScanPolicy`.

- [ ] **Step 3: Verify build**

Run: `go build ./cmd/...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add cmd/root.go
git commit -m "cli: add --exemptions flag and TRITON_EXEMPTIONS_FILE env var"
```

---

## Phase 4: Report Rendering

### Task 7: HTML risk breakdown and exemptions section

**Files:**
- Modify: `pkg/report/generator.go`
- Modify: `pkg/report/generator_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestGenerateHTML_RiskSummaryBar(t *testing.T) {
	result := &model.ScanResult{
		PolicyEvaluation: &model.PolicyEvaluationResult{
			PolicyName: "test-policy",
			Verdict:    "FAIL",
			RiskSummary: &model.RiskSummary{
				Critical: 3, High: 5, Medium: 2, Low: 1,
			},
			Violations: []model.PolicyViolation{
				{RuleID: "r1", RiskLevel: "critical", Action: "fail", Message: "test"},
			},
		},
	}
	out, err := GenerateHTML(result)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "3 Critical")
	assert.Contains(t, s, "5 High")
	assert.Contains(t, s, "2 Medium")
	assert.Contains(t, s, "1 Low")
}

func TestGenerateHTML_ExemptionsSection(t *testing.T) {
	result := &model.ScanResult{
		PolicyEvaluation: &model.PolicyEvaluationResult{
			PolicyName: "test-policy",
			Verdict:    "PASS",
			ExemptionsApplied: []model.ExemptionApplied{
				{Algorithm: "SHA-1", Location: "/etc/ssh/sshd_config", Reason: "Vendor requires", FindingCount: 2, Expires: "2027-12-31", ApprovedBy: "CISO"},
			},
			ExemptionsExpired: []model.ExemptionExpired{
				{Algorithm: "3DES", ExpiredOn: "2026-01-01"},
			},
		},
	}
	out, err := GenerateHTML(result)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "Exemptions Applied")
	assert.Contains(t, s, "SHA-1")
	assert.Contains(t, s, "Vendor requires")
	assert.Contains(t, s, "CISO")
	assert.Contains(t, s, "Expired Exemptions")
	assert.Contains(t, s, "3DES")
}

func TestGenerateHTML_RiskBadgeOnViolation(t *testing.T) {
	result := &model.ScanResult{
		PolicyEvaluation: &model.PolicyEvaluationResult{
			PolicyName: "test-policy",
			Verdict:    "FAIL",
			Violations: []model.PolicyViolation{
				{RuleID: "r1", RiskLevel: "critical", Action: "fail", Message: "test critical"},
			},
		},
	}
	out, err := GenerateHTML(result)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "critical")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestGenerateHTML_RiskSummary|TestGenerateHTML_Exemptions|TestGenerateHTML_RiskBadge" ./pkg/report/...`
Expected: FAIL — no risk/exemption rendering yet.

- [ ] **Step 3: Implement HTML rendering**

In `generator.go`, in the policy section (after the verdict banner, around line 371):

1. **Risk breakdown bar** — after the violations count line, add:

```go
if pe.RiskSummary != nil {
	b.WriteString(`<div style="margin:10px 0;font-size:0.95em">`)
	b.WriteString(fmt.Sprintf(`<span style="color:#b71c1c;font-weight:bold">■ %d Critical</span> `, pe.RiskSummary.Critical))
	b.WriteString(fmt.Sprintf(`<span style="color:#e65100;font-weight:bold">■ %d High</span> `, pe.RiskSummary.High))
	b.WriteString(fmt.Sprintf(`<span style="color:#f9a825;font-weight:bold">■ %d Medium</span> `, pe.RiskSummary.Medium))
	b.WriteString(fmt.Sprintf(`<span style="color:#1565c0;font-weight:bold">■ %d Low</span>`, pe.RiskSummary.Low))
	b.WriteString(`</div>`)
}
```

2. **Risk badge on violation rows** — in the violations-by-rule table, add a Risk column. In the `ruleAgg` struct, add `riskLevel string`. Populate from the first violation's `RiskLevel`. Add a `<th>Risk</th>` header and render the badge with appropriate color.

3. **Exemptions section** — after the violations table, add:

```go
if len(pe.ExemptionsApplied) > 0 {
	b.WriteString(fmt.Sprintf(`<h3>Exemptions Applied (%d)</h3><ul>`, len(pe.ExemptionsApplied)))
	for _, ea := range pe.ExemptionsApplied {
		label := html.EscapeString(ea.Algorithm)
		if ea.Location != "" {
			label += " at " + html.EscapeString(ea.Location)
		}
		expires := "permanent"
		if ea.Expires != "" {
			expires = html.EscapeString(ea.Expires)
		}
		approver := ""
		if ea.ApprovedBy != "" {
			approver = " · Approved by: " + html.EscapeString(ea.ApprovedBy)
		}
		b.WriteString(fmt.Sprintf(`<li><strong>%s</strong> (%d findings)<br>Reason: %s<br>Expires: %s%s</li>`,
			label, ea.FindingCount, html.EscapeString(ea.Reason), expires, approver))
	}
	b.WriteString(`</ul>`)
}
if len(pe.ExemptionsExpired) > 0 {
	b.WriteString(fmt.Sprintf(`<h3 style="color:#b71c1c">⚠ Expired Exemptions (%d)</h3><ul>`, len(pe.ExemptionsExpired)))
	for _, ee := range pe.ExemptionsExpired {
		label := html.EscapeString(ee.Algorithm)
		if ee.Location != "" {
			label += " at " + html.EscapeString(ee.Location)
		}
		b.WriteString(fmt.Sprintf(`<li><strong>%s</strong> — expired %s, findings now evaluated</li>`,
			label, html.EscapeString(ee.ExpiredOn)))
	}
	b.WriteString(`</ul>`)
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestGenerateHTML_RiskSummary|TestGenerateHTML_Exemptions|TestGenerateHTML_RiskBadge" ./pkg/report/...`
Expected: all 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/report/generator.go pkg/report/generator_test.go
git commit -m "feat(report): add risk breakdown bar and exemptions section to HTML"
```

### Task 8: CycloneDX risk-level property

**Files:**
- Modify: `pkg/report/cyclonedx.go`
- Modify: `pkg/report/cyclonedx_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestCycloneDX_RiskLevelProperty(t *testing.T) {
	result := &model.ScanResult{
		PolicyEvaluation: &model.PolicyEvaluationResult{
			Violations: []model.PolicyViolation{
				{RuleID: "r1", RiskLevel: "critical", Message: "test"},
			},
		},
	}
	out, err := GenerateCycloneDX(result)
	require.NoError(t, err)
	// Risk level should appear as a property somewhere in the output
	assert.Contains(t, string(out), "triton:risk-level")
	assert.Contains(t, string(out), "critical")
}
```

Note: The exact integration point depends on how CycloneDX currently renders policy violations. If violations are not rendered in CycloneDX at all yet, this test verifies new functionality. If they are, it adds the risk-level property alongside existing violation data. The implementer should check `cyclonedx.go` for the existing policy rendering path and add the property there.

- [ ] **Step 2: Implement and test**

- [ ] **Step 3: Commit**

```bash
git add pkg/report/cyclonedx.go pkg/report/cyclonedx_test.go
git commit -m "feat(report): add triton:risk-level property to CycloneDX"
```

---

## Phase 5: Verification

### Task 9: Full build, lint, and test

- [ ] **Step 1: Run full build**

Run: `go build ./...`

- [ ] **Step 2: Run lint**

Run: `make lint`

- [ ] **Step 3: Run all tests**

Run: `go test ./...`

- [ ] **Step 4: Fix any issues and commit**

### Task 10: Update CLAUDE.md

- [ ] **Step 1: Add policy enhancements to CLAUDE.md**

In the policy engine section, add mention of risk levels and exemptions support.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for policy risk levels and exemptions"
```
