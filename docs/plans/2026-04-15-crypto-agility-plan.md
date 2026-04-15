# Crypto Agility Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a new `pkg/agility/` package that produces a per-system, multi-dimensional crypto-agility score (0-100) with actionable recommendations, surfaced in the HTML report.

**Architecture:** Pure-function scorer that consumes an already-aggregated `*model.ScanResult` (no scanner changes). Four weighted dimensions (PQC Coverage 0.35, Protocol Agility 0.25, Configuration Flexibility 0.20, Operational Readiness 0.20) rolled into a 0-100 Overall score per host. A rules-driven recommendation engine emits 0-3 actions per low-scoring dimension. The report generator calls `agility.AssessAll(result)` and renders a new HTML panel. Orthogonal to CAMM (existing 0-4 maturity model) — both are rendered; agility is the numerical, actionable view.

**Tech Stack:** Go 1.25, stdlib only. No new deps. HTML uses existing inline-CSS pattern (no JS).

---

## File Structure

### Create
- `pkg/agility/types.go` — `Score`, `Dimension`, `Signal`, `Recommendation`, `Effort` (S/M/L), dimension name constants, package doc comment.
- `pkg/agility/assess.go` — `AssessAll(*model.ScanResult) []Score` entry point; per-host grouping; weight table; overall computation.
- `pkg/agility/dim_pqc.go` — `scorePQCCoverage(findings []model.Finding) Dimension`.
- `pkg/agility/dim_protocol.go` — `scoreProtocolAgility(findings []model.Finding) Dimension`.
- `pkg/agility/dim_config.go` — `scoreConfigFlexibility(findings []model.Finding) Dimension`.
- `pkg/agility/dim_operational.go` — `scoreOperationalReadiness(findings []model.Finding, assets []model.CryptoAsset, now time.Time) Dimension`.
- `pkg/agility/recommend.go` — `generateRecommendations(score Score, findings []model.Finding) []Recommendation`.
- `pkg/agility/assess_test.go` — end-to-end scenario tests (high / mixed / low agility synthetic systems) + weight sanity tests.
- `pkg/agility/dim_pqc_test.go` — unit tests per dimension.
- `pkg/agility/dim_protocol_test.go`
- `pkg/agility/dim_config_test.go`
- `pkg/agility/dim_operational_test.go`
- `pkg/agility/recommend_test.go`

### Modify
- `pkg/report/generator.go` — insert new HTML section between the CAMM block (line ~312) and Policy Analysis Summary (line ~315). Add helper `generateAgilityPanel(*model.ScanResult, *strings.Builder)`.
- `pkg/report/generator_test.go` — add `TestGenerateHTMLAgilityPanel` (non-empty findings) + `TestGenerateHTMLNoAgilityPanel` (empty findings).

### Out of Scope (explicit)
- No CSV / CycloneDX / SARIF / JSON report changes (deferred PR).
- No REST API endpoint (deferred PR).
- No web dashboard UI (deferred PR).
- No schema migration, no DB writes, no trend tracking (deferred PR).
- No changes to scanner modules or `pkg/crypto/agility.go` (the existing asset-level labels).

---

## Conventions

- **Hostname grouping:** `finding.Source.Endpoint` if non-empty (network findings), else fall back to `result.Metadata.Hostname`. Findings with neither are grouped under hostname `"unknown"`.
- **Determinism:** Every function that iterates maps must sort keys before returning to keep HTML diffs stable across runs.
- **"Now" injection:** `scoreOperationalReadiness` takes a `time.Time` parameter — tests pass fixed time, `AssessAll` passes `time.Now().UTC()`.
- **No floating-point scoring:** All dimension scores are `int` in [0, 100]; overall is `int` computed as `int(math.Round(weighted_sum))`.
- **Zero-finding behaviour:** `AssessAll` returns `nil` (not empty slice) when `result` has no findings. The HTML helper MUST noop when `AssessAll` returns `nil`.
- **Commit discipline:** Every task ends with a commit. Commit messages follow `<type>(<scope>): <subject>` where `<scope>` is `agility` or `report`.

---

## Task 1: Package skeleton + types

**Files:**
- Create: `pkg/agility/types.go`
- Create: `pkg/agility/assess.go` (stub only)
- Create: `pkg/agility/assess_test.go` (one compile-smoke test)

- [ ] **Step 1: Write `pkg/agility/types.go`**

```go
// Package agility computes multi-dimensional crypto-agility scores per host.
//
// Orthogonal to pkg/crypto.AssessCAMM (maturity level 0-4) and
// pkg/crypto.AssessCryptoAgility (per-asset Malay label): this package
// produces a numerical 0-100 score with actionable recommendations.
package agility

import "time"

// Dimension names (stable identifiers used in reports, JSON, and tests).
const (
	DimPQCCoverage       = "PQC Coverage"
	DimProtocolAgility   = "Protocol Agility"
	DimConfigFlexibility = "Configuration Flexibility"
	DimOperationalReady  = "Operational Readiness"
)

// Effort is a coarse T-shirt sizing of recommendation effort.
type Effort string

const (
	EffortSmall  Effort = "S"
	EffortMedium Effort = "M"
	EffortLarge  Effort = "L"
)

// Signal is a single piece of evidence that contributed to a dimension score.
type Signal struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Contributes int    `json:"contributes"` // signed delta against the dimension baseline
}

// Dimension is one of the four scored dimensions.
type Dimension struct {
	Name        string   `json:"name"`
	Score       int      `json:"score"`  // 0-100
	Weight      float64  `json:"weight"` // contribution to Overall, sums to 1.0 across dimensions
	Signals     []Signal `json:"signals,omitempty"`
	Explanation string   `json:"explanation"`
}

// Recommendation is one actionable next step for a low-scoring dimension.
type Recommendation struct {
	Dimension string `json:"dimension"`
	Action    string `json:"action"`
	Effort    Effort `json:"effort"`
	Impact    int    `json:"impact"` // expected dimension-score delta if applied
}

// Score is the per-host agility assessment.
type Score struct {
	Hostname        string           `json:"hostname"`
	Overall         int              `json:"overall"` // 0-100
	Dimensions      []Dimension      `json:"dimensions"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	GeneratedAt     time.Time        `json:"generatedAt"`
}
```

- [ ] **Step 2: Write `pkg/agility/assess.go` stub**

```go
package agility

import "github.com/amiryahaya/triton/pkg/model"

// AssessAll returns one Score per host in the scan result.
// Returns nil when result is nil or has no findings.
func AssessAll(result *model.ScanResult) []Score {
	if result == nil || len(result.Findings) == 0 {
		return nil
	}
	// Real implementation lands in Task 6.
	return nil
}
```

- [ ] **Step 3: Write `pkg/agility/assess_test.go`**

```go
package agility

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessAll_EmptyInput(t *testing.T) {
	if got := AssessAll(nil); got != nil {
		t.Errorf("AssessAll(nil) = %v, want nil", got)
	}
	if got := AssessAll(&model.ScanResult{}); got != nil {
		t.Errorf("AssessAll(empty) = %v, want nil", got)
	}
}
```

- [ ] **Step 4: Run test, expect PASS**

Run: `go test ./pkg/agility/...`
Expected: `ok  github.com/amiryahaya/triton/pkg/agility`

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/
git commit -m "feat(agility): package skeleton + core types"
```

---

## Task 2: Dimension 1 — PQC Coverage

**Scoring rule:** Score = 100 * (SAFE + HYBRID) / TotalAssets. Hybrid assets count fully. No assets → score 50 (neutral, cannot assess). Assets without PQCStatus field are ignored in denominator.

**Files:**
- Create: `pkg/agility/dim_pqc.go`
- Create: `pkg/agility/dim_pqc_test.go`

- [ ] **Step 1: Write `pkg/agility/dim_pqc_test.go` (RED)**

```go
package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func findingWithAsset(algo, status string, hybrid bool) model.Finding {
	return model.Finding{
		Module:    "test",
		Timestamp: time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algo,
			PQCStatus: status,
			IsHybrid:  hybrid,
		},
	}
}

func TestScorePQCCoverage_AllSafe(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
		findingWithAsset("AES-256", model.PQCStatusSafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
	if d.Name != DimPQCCoverage {
		t.Errorf("Name = %q, want %q", d.Name, DimPQCCoverage)
	}
}

func TestScorePQCCoverage_AllUnsafe(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		findingWithAsset("MD5", model.PQCStatusUnsafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScorePQCCoverage_Mixed(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		findingWithAsset("MD5", model.PQCStatusUnsafe, false),
		findingWithAsset("AES-256", model.PQCStatusSafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (2/4)", d.Score)
	}
}

func TestScorePQCCoverage_HybridCountsAsSafe(t *testing.T) {
	fs := []model.Finding{
		// Hybrid with classical label should still credit coverage.
		findingWithAsset("X25519MLKEM768", model.PQCStatusTransitional, true),
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScorePQCCoverage_NoAssets(t *testing.T) {
	fs := []model.Finding{{Module: "noop"}}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}
```

- [ ] **Step 2: Run tests, verify FAIL**

Run: `go test ./pkg/agility/ -run TestScorePQCCoverage`
Expected: FAIL with `undefined: scorePQCCoverage`.

- [ ] **Step 3: Write `pkg/agility/dim_pqc.go`**

```go
package agility

import (
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightPQCCoverage = 0.35

func scorePQCCoverage(findings []model.Finding) Dimension {
	var total, covered int
	for i := range findings {
		a := findings[i].CryptoAsset
		if a == nil || a.PQCStatus == "" {
			continue
		}
		total++
		if a.IsHybrid || a.PQCStatus == model.PQCStatusSafe {
			covered++
		}
	}

	d := Dimension{
		Name:   DimPQCCoverage,
		Weight: weightPQCCoverage,
	}
	if total == 0 {
		d.Score = 50
		d.Explanation = "No classified crypto assets; cannot assess PQC coverage."
		return d
	}
	d.Score = (covered * 100) / total
	d.Signals = []Signal{
		{Name: "total_assets", Value: fmt.Sprintf("%d", total), Contributes: 0},
		{Name: "pqc_safe_or_hybrid", Value: fmt.Sprintf("%d", covered), Contributes: d.Score},
	}
	d.Explanation = fmt.Sprintf("%d of %d assets are PQC-safe or hybrid.", covered, total)
	return d
}
```

- [ ] **Step 4: Run tests, verify PASS**

Run: `go test ./pkg/agility/ -run TestScorePQCCoverage -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/dim_pqc.go pkg/agility/dim_pqc_test.go
git commit -m "feat(agility): PQC Coverage dimension scorer"
```

---

## Task 3: Dimension 2 — Protocol Agility

**Scoring rule:** Composite of three sub-signals, each 0-100, averaged:
1. **TLS version ceiling** — any TLS 1.3 finding → 100; max TLS 1.2 → 60; max TLS 1.1 → 20; max TLS 1.0 → 0; no TLS findings → skipped (sub-signal omitted).
2. **Named-group diversity** — unique curve/group names seen in protocol findings: ≥4 → 100, 3 → 75, 2 → 50, 1 → 25, 0 → 0.
3. **Hybrid group presence** — any `IsHybrid` finding from protocol/web_server/vpn_config modules → 100; else 0.

Final score = average of the sub-signals that fired. If zero fired, score = 50 (neutral, no protocol observable).

Only findings from modules `protocol`, `web_server`, `vpn_config` contribute. TLS version is read from `finding.CryptoAsset.Algorithm` (protocol scanner writes values like `"TLS 1.3"`).

**Files:**
- Create: `pkg/agility/dim_protocol.go`
- Create: `pkg/agility/dim_protocol_test.go`

- [ ] **Step 1: Write `pkg/agility/dim_protocol_test.go` (RED)**

```go
package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func protoFinding(module, algo string, hybrid bool) model.Finding {
	return model.Finding{
		Module:    module,
		Timestamp: time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algo,
			IsHybrid:  hybrid,
		},
	}
}

func TestScoreProtocolAgility_TLS13AndHybrid(t *testing.T) {
	fs := []model.Finding{
		protoFinding("protocol", "TLS 1.3", false),
		protoFinding("protocol", "X25519MLKEM768", true),
		protoFinding("protocol", "secp256r1", false),
		protoFinding("protocol", "X25519", false),
		protoFinding("protocol", "secp384r1", false),
	}
	d := scoreProtocolAgility(fs)
	// TLS ceiling 100, diversity 100 (4 groups), hybrid 100 → 100
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}

func TestScoreProtocolAgility_LegacyTLSOnly(t *testing.T) {
	fs := []model.Finding{
		protoFinding("protocol", "TLS 1.0", false),
		protoFinding("protocol", "secp256r1", false),
	}
	d := scoreProtocolAgility(fs)
	// ceiling 0, diversity 25, hybrid 0 → avg 8
	if d.Score != 8 {
		t.Errorf("Score = %d, want 8", d.Score)
	}
}

func TestScoreProtocolAgility_NoProtocolFindings(t *testing.T) {
	fs := []model.Finding{
		{Module: "certificates", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	d := scoreProtocolAgility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}

func TestScoreProtocolAgility_WebServerContributes(t *testing.T) {
	fs := []model.Finding{
		protoFinding("web_server", "TLS 1.2", false),
		protoFinding("web_server", "X25519", false),
		protoFinding("web_server", "secp256r1", false),
	}
	d := scoreProtocolAgility(fs)
	// ceiling 60, diversity 50 (2 groups), no hybrid → avg = 55
	if d.Score != 55 {
		t.Errorf("Score = %d, want 55", d.Score)
	}
}
```

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/agility/ -run TestScoreProtocolAgility`
Expected: `undefined: scoreProtocolAgility`.

- [ ] **Step 3: Write `pkg/agility/dim_protocol.go`**

```go
package agility

import (
	"fmt"
	"sort"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightProtocolAgility = 0.25

var protocolModules = map[string]bool{
	"protocol":    true,
	"web_server":  true,
	"vpn_config":  true,
}

func scoreProtocolAgility(findings []model.Finding) Dimension {
	d := Dimension{Name: DimProtocolAgility, Weight: weightProtocolAgility}

	var maxTLS int = -1 // -1 = not observed
	groups := make(map[string]bool)
	hasHybrid := false
	protocolFindings := 0

	for i := range findings {
		f := &findings[i]
		if !protocolModules[f.Module] || f.CryptoAsset == nil {
			continue
		}
		protocolFindings++
		algo := f.CryptoAsset.Algorithm
		if v := tlsVersionScore(algo); v >= 0 && v > maxTLS {
			maxTLS = v
		}
		if isNamedGroup(algo) {
			groups[algo] = true
		}
		if f.CryptoAsset.IsHybrid {
			hasHybrid = true
		}
	}

	if protocolFindings == 0 {
		d.Score = 50
		d.Explanation = "No TLS/VPN protocol findings; cannot assess protocol agility."
		return d
	}

	var sum, fired int
	if maxTLS >= 0 {
		sum += maxTLS
		fired++
		d.Signals = append(d.Signals, Signal{Name: "tls_version_ceiling", Value: tlsVersionLabel(maxTLS), Contributes: maxTLS})
	}
	divScore := diversityScore(len(groups))
	if len(groups) > 0 {
		sum += divScore
		fired++
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d.Signals = append(d.Signals, Signal{Name: "named_group_diversity", Value: strings.Join(keys, ","), Contributes: divScore})
	}
	hybridScore := 0
	if hasHybrid {
		hybridScore = 100
	}
	sum += hybridScore
	fired++
	d.Signals = append(d.Signals, Signal{Name: "hybrid_group_present", Value: fmt.Sprintf("%t", hasHybrid), Contributes: hybridScore})

	if fired == 0 {
		d.Score = 50
	} else {
		d.Score = sum / fired
	}
	d.Explanation = fmt.Sprintf("TLS ceiling %s, %d distinct groups, hybrid=%t.",
		tlsVersionLabel(maxTLS), len(groups), hasHybrid)
	return d
}

func tlsVersionScore(algo string) int {
	switch strings.TrimSpace(algo) {
	case "TLS 1.3":
		return 100
	case "TLS 1.2":
		return 60
	case "TLS 1.1":
		return 20
	case "TLS 1.0":
		return 0
	}
	return -1
}

func tlsVersionLabel(score int) string {
	switch score {
	case 100:
		return "TLS 1.3"
	case 60:
		return "TLS 1.2"
	case 20:
		return "TLS 1.1"
	case 0:
		return "TLS 1.0"
	}
	return "n/a"
}

func diversityScore(n int) int {
	switch {
	case n >= 4:
		return 100
	case n == 3:
		return 75
	case n == 2:
		return 50
	case n == 1:
		return 25
	}
	return 0
}

// isNamedGroup is a coarse heuristic: TLS group algorithm names tend to match
// IANA registry tokens. We treat anything non-empty that isn't a TLS version
// label and isn't a cipher suite string as a group.
func isNamedGroup(algo string) bool {
	if algo == "" {
		return false
	}
	if tlsVersionScore(algo) >= 0 {
		return false
	}
	// Cipher suite strings contain "_WITH_" (IANA) or multiple "-" tokens with AES/GCM; skip.
	if strings.Contains(algo, "_WITH_") {
		return false
	}
	return true
}
```

- [ ] **Step 4: Run, verify PASS**

Run: `go test ./pkg/agility/ -run TestScoreProtocolAgility -v`
Expected: all 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/dim_protocol.go pkg/agility/dim_protocol_test.go
git commit -m "feat(agility): Protocol Agility dimension scorer"
```

---

## Task 4: Dimension 3 — Configuration Flexibility

**Scoring rule:** Ratio of config-referenced crypto findings vs hardcoded findings.
- **Config modules:** `configs`, `web_server`, `vpn_config`, `certstore`, `container_signatures`.
- **Hardcoded modules:** `binaries`, `asn1_oid`, `java_bytecode`, `kernel`, `codesign`.
- Other modules (`certificates`, `keys`, `packages`, `process`, `deps`, ...) are neutral — excluded from the ratio.

Score = `100 * config / (config + hardcoded)`. If both are zero → 50 (neutral). If only config → 100; only hardcoded → 0.

**Files:**
- Create: `pkg/agility/dim_config.go`
- Create: `pkg/agility/dim_config_test.go`

- [ ] **Step 1: Write `pkg/agility/dim_config_test.go` (RED)**

```go
package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func modFinding(module string) model.Finding {
	return model.Finding{
		Module:      module,
		Timestamp:   time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"},
	}
}

func TestScoreConfigFlexibility_AllConfig(t *testing.T) {
	fs := []model.Finding{
		modFinding("configs"),
		modFinding("web_server"),
		modFinding("vpn_config"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}

func TestScoreConfigFlexibility_AllHardcoded(t *testing.T) {
	fs := []model.Finding{
		modFinding("binaries"),
		modFinding("asn1_oid"),
		modFinding("java_bytecode"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScoreConfigFlexibility_Mixed(t *testing.T) {
	fs := []model.Finding{
		modFinding("configs"),
		modFinding("configs"),
		modFinding("binaries"),
		modFinding("asn1_oid"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (2/4)", d.Score)
	}
}

func TestScoreConfigFlexibility_Neutral(t *testing.T) {
	fs := []model.Finding{
		modFinding("certificates"),
		modFinding("packages"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}
```

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/agility/ -run TestScoreConfigFlexibility`
Expected: `undefined: scoreConfigFlexibility`.

- [ ] **Step 3: Write `pkg/agility/dim_config.go`**

```go
package agility

import (
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightConfigFlexibility = 0.20

var configModules = map[string]bool{
	"configs":              true,
	"web_server":           true,
	"vpn_config":           true,
	"certstore":            true,
	"container_signatures": true,
}

var hardcodedModules = map[string]bool{
	"binaries":      true,
	"asn1_oid":      true,
	"java_bytecode": true,
	"kernel":        true,
	"codesign":      true,
}

func scoreConfigFlexibility(findings []model.Finding) Dimension {
	d := Dimension{Name: DimConfigFlexibility, Weight: weightConfigFlexibility}

	var cfg, hard int
	for i := range findings {
		m := findings[i].Module
		switch {
		case configModules[m]:
			cfg++
		case hardcodedModules[m]:
			hard++
		}
	}
	total := cfg + hard
	if total == 0 {
		d.Score = 50
		d.Explanation = "No config-vs-hardcoded signal; neutral score."
		return d
	}
	d.Score = (cfg * 100) / total
	d.Signals = []Signal{
		{Name: "config_referenced", Value: fmt.Sprintf("%d", cfg), Contributes: d.Score},
		{Name: "hardcoded", Value: fmt.Sprintf("%d", hard), Contributes: -((hard * 100) / total)},
	}
	d.Explanation = fmt.Sprintf("%d config-referenced vs %d hardcoded crypto findings.", cfg, hard)
	return d
}
```

- [ ] **Step 4: Run, verify PASS**

Run: `go test ./pkg/agility/ -run TestScoreConfigFlexibility -v`
Expected: all 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/dim_config.go pkg/agility/dim_config_test.go
git commit -m "feat(agility): Configuration Flexibility dimension scorer"
```

---

## Task 5: Dimension 4 — Operational Readiness

**Scoring rule:** Composite of three sub-signals, each 0-100, averaged across those that fire:
1. **Cert expiry rotation cadence** — looks at certificates (findings where `Module == "certificates"` and `NotAfter != nil`). Median days-to-expiry: ≤90 → 100; ≤180 → 75; ≤365 → 50; ≤730 → 25; >730 → 0. Skip if no certificates.
2. **HSM detected** — any finding with `Module == "hsm"` → 100 else 0. Always fires.
3. **Automation tool detected** — any finding whose `Source.Path` or `Source.Evidence` contains (case-insensitive) `cert-manager`, `certbot`, `acme`, `lego`, `hashicorp-vault` → 100 else 0. Always fires.

Final = average of fired sub-signals. If only HSM+automation fire and both are 0, score = 0.

**Files:**
- Create: `pkg/agility/dim_operational.go`
- Create: `pkg/agility/dim_operational_test.go`

- [ ] **Step 1: Write `pkg/agility/dim_operational_test.go` (RED)**

```go
package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

var refNow = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

func certFinding(daysToExpiry int) model.Finding {
	exp := refNow.AddDate(0, 0, daysToExpiry)
	return model.Finding{
		Module:    "certificates",
		Timestamp: refNow,
		CryptoAsset: &model.CryptoAsset{
			Algorithm: "RSA-2048",
			NotAfter:  &exp,
		},
	}
}

func TestScoreOperational_ShortRotationsOnly(t *testing.T) {
	fs := []model.Finding{certFinding(30), certFinding(60), certFinding(80)}
	d := scoreOperationalReadiness(fs, refNow)
	// Median 60 → 100 (cert), HSM 0, automation 0 → avg = 33
	if d.Score != 33 {
		t.Errorf("Score = %d, want 33", d.Score)
	}
}

func TestScoreOperational_HSMPresent(t *testing.T) {
	fs := []model.Finding{
		{Module: "hsm", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-3072"}},
	}
	d := scoreOperationalReadiness(fs, refNow)
	// No certs → cert skipped. HSM 100, automation 0 → avg = 50
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScoreOperational_AutomationDetected(t *testing.T) {
	f := model.Finding{
		Module: "packages",
		Source: model.FindingSource{Path: "/usr/bin/certbot"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"},
	}
	d := scoreOperationalReadiness([]model.Finding{f}, refNow)
	// No certs → cert skipped. HSM 0, automation 100 → avg = 50
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScoreOperational_LongRotations(t *testing.T) {
	fs := []model.Finding{certFinding(800), certFinding(900)}
	d := scoreOperationalReadiness(fs, refNow)
	// Median 850 → 0. HSM 0, automation 0 → 0
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScoreOperational_AllThreeFire(t *testing.T) {
	fs := []model.Finding{
		certFinding(60),
		{Module: "hsm", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-3072"}},
		{Module: "packages", Source: model.FindingSource{Evidence: "cert-manager installed"},
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	d := scoreOperationalReadiness(fs, refNow)
	// 100+100+100 / 3 = 100
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}
```

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/agility/ -run TestScoreOperational`
Expected: `undefined: scoreOperationalReadiness`.

- [ ] **Step 3: Write `pkg/agility/dim_operational.go`**

```go
package agility

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightOperational = 0.20

var automationNeedles = []string{"cert-manager", "certbot", "acme", "lego", "hashicorp-vault"}

func scoreOperationalReadiness(findings []model.Finding, now time.Time) Dimension {
	d := Dimension{Name: DimOperationalReady, Weight: weightOperational}

	certScore, certFired := certRotationScore(findings, now)
	hasHSM := false
	hasAutomation := false
	for i := range findings {
		f := &findings[i]
		if f.Module == "hsm" {
			hasHSM = true
		}
		hay := strings.ToLower(f.Source.Path + " " + f.Source.Evidence)
		for _, n := range automationNeedles {
			if strings.Contains(hay, n) {
				hasAutomation = true
				break
			}
		}
	}

	var sum, fired int
	if certFired {
		sum += certScore
		fired++
		d.Signals = append(d.Signals, Signal{Name: "cert_rotation_cadence", Value: fmt.Sprintf("%d", certScore), Contributes: certScore})
	}
	hsmScore := 0
	if hasHSM {
		hsmScore = 100
	}
	sum += hsmScore
	fired++
	d.Signals = append(d.Signals, Signal{Name: "hsm_present", Value: fmt.Sprintf("%t", hasHSM), Contributes: hsmScore})

	autoScore := 0
	if hasAutomation {
		autoScore = 100
	}
	sum += autoScore
	fired++
	d.Signals = append(d.Signals, Signal{Name: "automation_tool", Value: fmt.Sprintf("%t", hasAutomation), Contributes: autoScore})

	if fired == 0 {
		d.Score = 50
	} else {
		d.Score = sum / fired
	}
	d.Explanation = fmt.Sprintf("HSM=%t, automation=%t, cert-rotation-score=%d.", hasHSM, hasAutomation, certScore)
	return d
}

// certRotationScore returns (score, fired). fired=false when no cert findings.
func certRotationScore(findings []model.Finding, now time.Time) (int, bool) {
	var days []int
	for i := range findings {
		f := &findings[i]
		if f.Module != "certificates" || f.CryptoAsset == nil || f.CryptoAsset.NotAfter == nil {
			continue
		}
		delta := int(f.CryptoAsset.NotAfter.Sub(now).Hours() / 24)
		if delta < 0 {
			delta = 0 // already expired = urgent rotation window
		}
		days = append(days, delta)
	}
	if len(days) == 0 {
		return 0, false
	}
	sort.Ints(days)
	med := days[len(days)/2]
	switch {
	case med <= 90:
		return 100, true
	case med <= 180:
		return 75, true
	case med <= 365:
		return 50, true
	case med <= 730:
		return 25, true
	}
	return 0, true
}
```

- [ ] **Step 4: Run, verify PASS**

Run: `go test ./pkg/agility/ -run TestScoreOperational -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/dim_operational.go pkg/agility/dim_operational_test.go
git commit -m "feat(agility): Operational Readiness dimension scorer"
```

---

## Task 6: Wire up `AssessAll` — per-host grouping and overall score

**Behaviour:** group findings by host (per Conventions), score each host across 4 dimensions, compute weighted Overall, return deterministic slice sorted by hostname.

**Files:**
- Modify: `pkg/agility/assess.go`
- Modify: `pkg/agility/assess_test.go` (add scenario tests)

- [ ] **Step 1: Extend `pkg/agility/assess_test.go`**

```go
func TestAssessAll_WeightsSumToOne(t *testing.T) {
	sum := weightPQCCoverage + weightProtocolAgility + weightConfigFlexibility + weightOperational
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("weights sum = %f, want 1.0", sum)
	}
}

func TestAssessAll_HighAgilityHost(t *testing.T) {
	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "host-hi"},
		Findings: []model.Finding{
			// PQC: 2/2 safe
			findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
			findingWithAsset("AES-256", model.PQCStatusSafe, false),
			// Protocol: TLS 1.3 + 4 groups + hybrid
			protoFinding("protocol", "TLS 1.3", false),
			protoFinding("protocol", "X25519MLKEM768", true),
			protoFinding("protocol", "X25519", false),
			protoFinding("protocol", "secp256r1", false),
			protoFinding("protocol", "secp384r1", false),
			// Config: all config
			modFinding("configs"),
			modFinding("web_server"),
			// Operational: short rotation + automation
			{Module: "certificates", CryptoAsset: &model.CryptoAsset{
				Algorithm: "RSA-2048",
				NotAfter:  ptrTime(now.AddDate(0, 0, 60)),
			}},
			{Module: "packages", Source: model.FindingSource{Evidence: "cert-manager"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
		},
	}
	scores := AssessAll(result)
	if len(scores) != 1 {
		t.Fatalf("len(scores) = %d, want 1", len(scores))
	}
	s := scores[0]
	if s.Hostname != "host-hi" {
		t.Errorf("Hostname = %q, want host-hi", s.Hostname)
	}
	if s.Overall < 85 {
		t.Errorf("Overall = %d, want >= 85", s.Overall)
	}
	if len(s.Dimensions) != 4 {
		t.Errorf("len(Dimensions) = %d, want 4", len(s.Dimensions))
	}
}

func TestAssessAll_LowAgilityHost(t *testing.T) {
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "host-lo"},
		Findings: []model.Finding{
			findingWithAsset("MD5", model.PQCStatusUnsafe, false),
			findingWithAsset("RSA-1024", model.PQCStatusUnsafe, false),
			protoFinding("protocol", "TLS 1.0", false),
			modFinding("binaries"),
			modFinding("asn1_oid"),
		},
	}
	scores := AssessAll(result)
	if len(scores) != 1 {
		t.Fatalf("len(scores) = %d, want 1", len(scores))
	}
	if scores[0].Overall > 25 {
		t.Errorf("Overall = %d, want <= 25", scores[0].Overall)
	}
}

func TestAssessAll_MultiHostGrouping(t *testing.T) {
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "fallback"},
		Findings: []model.Finding{
			{
				Module: "protocol",
				Source: model.FindingSource{Endpoint: "a.example.com:443"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.3"},
			},
			{
				Module: "protocol",
				Source: model.FindingSource{Endpoint: "b.example.com:443"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.2"},
			},
			// falls back to metadata hostname
			findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		},
	}
	scores := AssessAll(result)
	if len(scores) != 3 {
		t.Fatalf("len(scores) = %d, want 3 (a, b, fallback)", len(scores))
	}
	// Must be sorted by hostname deterministically
	want := []string{"a.example.com:443", "b.example.com:443", "fallback"}
	for i, s := range scores {
		if s.Hostname != want[i] {
			t.Errorf("scores[%d].Hostname = %q, want %q", i, s.Hostname, want[i])
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
```

Add imports: `"time"`, `"github.com/amiryahaya/triton/pkg/model"` (already present).

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/agility/`
Expected: the three new tests fail because AssessAll returns nil.

- [ ] **Step 3: Replace `pkg/agility/assess.go`**

```go
package agility

import (
	"math"
	"sort"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// AssessAll returns one Score per host observed in the scan result, sorted by
// hostname. Returns nil when result is nil or has no findings.
func AssessAll(result *model.ScanResult) []Score {
	if result == nil || len(result.Findings) == 0 {
		return nil
	}
	fallback := result.Metadata.Hostname
	if fallback == "" {
		fallback = "unknown"
	}
	groups := groupFindingsByHost(result.Findings, fallback)
	now := time.Now().UTC()

	hosts := make([]string, 0, len(groups))
	for h := range groups {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	scores := make([]Score, 0, len(hosts))
	for _, h := range hosts {
		scores = append(scores, scoreHost(h, groups[h], now))
	}
	return scores
}

func groupFindingsByHost(findings []model.Finding, fallback string) map[string][]model.Finding {
	out := make(map[string][]model.Finding)
	for i := range findings {
		h := findings[i].Source.Endpoint
		if h == "" {
			h = fallback
		}
		out[h] = append(out[h], findings[i])
	}
	return out
}

func scoreHost(host string, findings []model.Finding, now time.Time) Score {
	dims := []Dimension{
		scorePQCCoverage(findings),
		scoreProtocolAgility(findings),
		scoreConfigFlexibility(findings),
		scoreOperationalReadiness(findings, now),
	}
	var weighted float64
	for _, d := range dims {
		weighted += float64(d.Score) * d.Weight
	}
	s := Score{
		Hostname:    host,
		Overall:     int(math.Round(weighted)),
		Dimensions:  dims,
		GeneratedAt: now,
	}
	// Recommendations are wired in Task 7.
	return s
}
```

- [ ] **Step 4: Run all agility tests, verify PASS**

Run: `go test ./pkg/agility/ -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/agility/assess.go pkg/agility/assess_test.go
git commit -m "feat(agility): AssessAll entry point with per-host grouping and weighted overall"
```

---

## Task 7: Recommendation engine

**Behaviour:** For each dimension scoring below a threshold, emit 0-3 recommendations drawn from a rules table. Recommendations ordered by Impact descending. Triggers depend on the scan context (e.g. nginx detected → nginx-specific action).

**Rules (initial set):**

| Dimension | Threshold | Trigger | Action | Effort | Impact |
|---|---|---|---|---|---|
| PQC Coverage | <40 | any Java bytecode finding | "Enable BouncyCastle PQC provider in Java apps (add bcprov-jdk18on + register in java.security)." | M | 25 |
| PQC Coverage | <40 | any web_server finding | "Add hybrid PQC group to nginx/Apache (`ssl_ecdh_curve X25519MLKEM768:X25519`). Needs OpenSSL 3.5+." | M | 20 |
| PQC Coverage | <40 | any OpenSSL library finding | "Upgrade to OpenSSL 3.5+ to unlock hybrid ML-KEM groups." | L | 15 |
| Protocol Agility | <50 | any TLS 1.0/1.1 finding | "Disable TLS 1.0/1.1 at the proxy edge; enforce TLS 1.2 minimum." | S | 20 |
| Protocol Agility | <50 | no hybrid groups seen | "Add at least one hybrid named group (X25519MLKEM768) to cipher preference list." | M | 25 |
| Protocol Agility | <50 | single named group | "Broaden named-group list to include X25519, secp256r1, secp384r1 for client compat." | S | 15 |
| Config Flexibility | <40 | Java bytecode dominates | "Move JCE provider config to java.security instead of compile-time pinning." | M | 20 |
| Config Flexibility | <40 | binaries findings present | "Switch compile-time-pinned crypto to runtime-configurable provider (EVP-style) where possible." | L | 25 |
| Operational Readiness | <40 | cert median >365d | "Shorten cert validity to ≤180d and enable cert-manager/certbot auto-renewal." | M | 30 |
| Operational Readiness | <40 | no automation detected | "Deploy cert-manager (K8s) or certbot (systemd) for automated cert rotation." | M | 25 |
| Operational Readiness | <40 | no HSM | "Evaluate HSM/KMS adoption for root-of-trust key material (AWS KMS, HashiCorp Vault)." | L | 10 |

Cap to top 3 recommendations per dimension. Dimension threshold used for eligibility only — if dimension score ≥ threshold, skip that dimension entirely.

**Files:**
- Create: `pkg/agility/recommend.go`
- Create: `pkg/agility/recommend_test.go`
- Modify: `pkg/agility/assess.go` (call generator)

- [ ] **Step 1: Write `pkg/agility/recommend_test.go` (RED)**

```go
package agility

import (
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestGenerateRecommendations_LowPQCWithJava(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimPQCCoverage, Score: 10},
		{Name: DimProtocolAgility, Score: 80},
		{Name: DimConfigFlexibility, Score: 80},
		{Name: DimOperationalReady, Score: 80},
	}}
	findings := []model.Finding{
		{Module: "java_bytecode", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	recs := generateRecommendations(s, findings)
	if len(recs) == 0 {
		t.Fatal("want at least 1 recommendation")
	}
	found := false
	for _, r := range recs {
		if r.Dimension == DimPQCCoverage && strings.Contains(r.Action, "BouncyCastle") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BouncyCastle recommendation, got %v", recs)
	}
}

func TestGenerateRecommendations_SkipWhenAboveThreshold(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimPQCCoverage, Score: 90},
		{Name: DimProtocolAgility, Score: 90},
		{Name: DimConfigFlexibility, Score: 90},
		{Name: DimOperationalReady, Score: 90},
	}}
	recs := generateRecommendations(s, nil)
	if len(recs) != 0 {
		t.Errorf("want 0 recommendations, got %d", len(recs))
	}
}

func TestGenerateRecommendations_CapAtThreePerDim(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimOperationalReady, Score: 10},
	}}
	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	longCert := now.AddDate(2, 0, 0)
	findings := []model.Finding{
		{Module: "certificates", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048", NotAfter: &longCert}},
		// no HSM, no automation → all three ops rules should fire, but capped at 3
	}
	recs := generateRecommendations(s, findings)
	count := 0
	for _, r := range recs {
		if r.Dimension == DimOperationalReady {
			count++
		}
	}
	if count > 3 {
		t.Errorf("recommendations for DimOperationalReady = %d, want <= 3", count)
	}
	if count < 1 {
		t.Errorf("recommendations for DimOperationalReady = 0, want >= 1")
	}
}

func TestGenerateRecommendations_OrderedByImpact(t *testing.T) {
	s := Score{Dimensions: []Dimension{{Name: DimPQCCoverage, Score: 10}}}
	findings := []model.Finding{
		{Module: "java_bytecode", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
		{Module: "web_server", CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.3"}},
	}
	recs := generateRecommendations(s, findings)
	for i := 1; i < len(recs); i++ {
		if recs[i-1].Dimension == recs[i].Dimension && recs[i-1].Impact < recs[i].Impact {
			t.Errorf("recs not sorted by Impact desc within dimension: %+v", recs)
		}
	}
}
```

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/agility/ -run TestGenerateRecommendations`
Expected: `undefined: generateRecommendations`.

- [ ] **Step 3: Write `pkg/agility/recommend.go`**

```go
package agility

import (
	"sort"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

const (
	threshLow         = 40
	threshProtocolLow = 50
	recsPerDimension  = 3
)

type rule struct {
	dim       string
	threshold int
	applies   func(findings []model.Finding) bool
	rec       Recommendation
}

var recommendationRules = []rule{
	// PQC Coverage
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasModule("java_bytecode"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Enable BouncyCastle PQC provider in Java apps (add bcprov-jdk18on + register in java.security).",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasModule("web_server"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Add hybrid PQC group to nginx/Apache (ssl_ecdh_curve X25519MLKEM768:X25519). Requires OpenSSL 3.5+.",
			Effort:    EffortMedium, Impact: 20,
		},
	},
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasLibrary("openssl"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Upgrade to OpenSSL 3.5+ to unlock hybrid ML-KEM groups.",
			Effort:    EffortLarge, Impact: 15,
		},
	},
	// Protocol Agility
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: hasAlgorithm("TLS 1.0", "TLS 1.1"),
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Disable TLS 1.0/1.1 at the proxy edge; enforce TLS 1.2 minimum.",
			Effort:    EffortSmall, Impact: 20,
		},
	},
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: noHybridGroups,
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Add at least one hybrid named group (X25519MLKEM768) to cipher preference list.",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: lowGroupDiversity,
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Broaden named-group list to include X25519, secp256r1, secp384r1 for client compatibility.",
			Effort:    EffortSmall, Impact: 15,
		},
	},
	// Config Flexibility
	{
		dim: DimConfigFlexibility, threshold: threshLow,
		applies: moduleDominates("java_bytecode"),
		rec: Recommendation{
			Dimension: DimConfigFlexibility,
			Action:    "Move JCE provider config to java.security instead of compile-time pinning.",
			Effort:    EffortMedium, Impact: 20,
		},
	},
	{
		dim: DimConfigFlexibility, threshold: threshLow,
		applies: hasModule("binaries"),
		rec: Recommendation{
			Dimension: DimConfigFlexibility,
			Action:    "Switch compile-time-pinned crypto to runtime-configurable provider (EVP-style) where possible.",
			Effort:    EffortLarge, Impact: 25,
		},
	},
	// Operational Readiness
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: certMedianAbove(365),
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Shorten cert validity to <=180d and enable cert-manager/certbot auto-renewal.",
			Effort:    EffortMedium, Impact: 30,
		},
	},
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: noAutomationTool,
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Deploy cert-manager (Kubernetes) or certbot (systemd) for automated cert rotation.",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: noHSM,
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Evaluate HSM/KMS adoption for root-of-trust key material (AWS KMS, HashiCorp Vault).",
			Effort:    EffortLarge, Impact: 10,
		},
	},
}

func generateRecommendations(s Score, findings []model.Finding) []Recommendation {
	dimScore := make(map[string]int, len(s.Dimensions))
	for _, d := range s.Dimensions {
		dimScore[d.Name] = d.Score
	}

	byDim := make(map[string][]Recommendation)
	for _, r := range recommendationRules {
		if score, ok := dimScore[r.dim]; !ok || score >= r.threshold {
			continue
		}
		if !r.applies(findings) {
			continue
		}
		byDim[r.dim] = append(byDim[r.dim], r.rec)
	}

	var out []Recommendation
	// Stable dimension order: declaration order of dim constants.
	for _, dim := range []string{DimPQCCoverage, DimProtocolAgility, DimConfigFlexibility, DimOperationalReady} {
		recs := byDim[dim]
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Impact > recs[j].Impact })
		if len(recs) > recsPerDimension {
			recs = recs[:recsPerDimension]
		}
		out = append(out, recs...)
	}
	return out
}

// --- predicate helpers ---

func hasModule(module string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].Module == module {
				return true
			}
		}
		return false
	}
}

func hasLibrary(sub string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].CryptoAsset != nil && strings.Contains(strings.ToLower(fs[i].CryptoAsset.Library), sub) {
				return true
			}
		}
		return false
	}
}

func hasAlgorithm(algos ...string) func([]model.Finding) bool {
	want := make(map[string]bool, len(algos))
	for _, a := range algos {
		want[a] = true
	}
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].CryptoAsset != nil && want[fs[i].CryptoAsset.Algorithm] {
				return true
			}
		}
		return false
	}
}

func noHybridGroups(fs []model.Finding) bool {
	for i := range fs {
		if fs[i].CryptoAsset != nil && fs[i].CryptoAsset.IsHybrid {
			return false
		}
	}
	return true
}

func lowGroupDiversity(fs []model.Finding) bool {
	groups := make(map[string]bool)
	for i := range fs {
		if !protocolModules[fs[i].Module] || fs[i].CryptoAsset == nil {
			continue
		}
		if isNamedGroup(fs[i].CryptoAsset.Algorithm) {
			groups[fs[i].CryptoAsset.Algorithm] = true
		}
	}
	return len(groups) <= 1
}

func moduleDominates(module string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		var target, total int
		for i := range fs {
			total++
			if fs[i].Module == module {
				target++
			}
		}
		return total > 0 && (target*2) > total
	}
}

func certMedianAbove(days int) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		now := time.Now().UTC()
		score, fired := certRotationScore(fs, now)
		// certRotationScore encodes thresholds: <=365 scores >=50.
		return fired && score < 50 && days == 365
	}
}

func noAutomationTool(fs []model.Finding) bool {
	for i := range fs {
		hay := strings.ToLower(fs[i].Source.Path + " " + fs[i].Source.Evidence)
		for _, n := range automationNeedles {
			if strings.Contains(hay, n) {
				return false
			}
		}
	}
	return true
}

func noHSM(fs []model.Finding) bool {
	for i := range fs {
		if fs[i].Module == "hsm" {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Wire recommendations into `scoreHost` (edit `pkg/agility/assess.go`)**

Replace the `Recommendations are wired in Task 7.` comment block with a call:

```go
	s.Recommendations = generateRecommendations(s, findings)
	return s
```

- [ ] **Step 5: Run all agility tests**

Run: `go test ./pkg/agility/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/agility/recommend.go pkg/agility/recommend_test.go pkg/agility/assess.go
git commit -m "feat(agility): recommendation engine driven by dimension scores"
```

---

## Task 8: HTML report panel

**Placement:** new panel rendered between the CAMM block and the Policy Analysis block inside `GenerateHTML`. Noops when `AssessAll` returns nil.

**Visual layout:**
- `<h2>Crypto Agility Assessment</h2>`
- For each host: host header (`<h3>`), overall-score badge (color-coded — green ≥70, amber 40-69, red <40), 4 horizontal CSS bars (width = score%), recommendations as a `<ul>`.

**Files:**
- Modify: `pkg/report/generator.go`
- Modify: `pkg/report/generator_test.go`

- [ ] **Step 1: Add test `TestGenerateHTMLAgilityPanel` (RED) to `pkg/report/generator_test.go`**

```go
func TestGenerateHTMLAgilityPanel(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "agility.html")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "agility-host"},
		Systems:  []model.System{{Name: "demo"}},
		Findings: []model.Finding{
			{
				Module: "protocol",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "TLS 1.3", PQCStatus: model.PQCStatusSafe, IsHybrid: true,
				},
			},
			{
				Module: "binaries",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "MD5", PQCStatus: model.PQCStatusUnsafe,
				},
			},
		},
	}
	g := New(tmp)
	if err := g.GenerateHTML(result, out); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, "Crypto Agility Assessment") {
		t.Error("missing section heading")
	}
	if !strings.Contains(html, "agility-host") {
		t.Error("missing hostname in panel")
	}
	if !strings.Contains(html, "PQC Coverage") {
		t.Error("missing PQC Coverage dimension label")
	}
}

func TestGenerateHTMLNoAgilityPanelWhenNoFindings(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "noagility.html")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "empty"},
		Systems:  []model.System{{Name: "demo"}},
	}
	g := New(tmp)
	if err := g.GenerateHTML(result, out); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Crypto Agility Assessment") {
		t.Error("agility section should be omitted when no findings")
	}
}
```

If `os`, `strings`, `filepath` are not imported in `generator_test.go`, add them.

- [ ] **Step 2: Run, verify FAIL**

Run: `go test ./pkg/report/ -run 'TestGenerateHTML(Agility|NoAgility)' -v`
Expected: FAIL — "missing section heading".

- [ ] **Step 3: Add import + panel helper to `pkg/report/generator.go`**

At top, extend imports with `"github.com/amiryahaya/triton/pkg/agility"`.

At the end of the file, add:

```go
// generateAgilityPanel writes the Crypto Agility Assessment HTML section.
// Noop if there are no scored hosts.
func (g *Generator) generateAgilityPanel(result *model.ScanResult, b *strings.Builder) {
	scores := agility.AssessAll(result)
	if len(scores) == 0 {
		return
	}
	b.WriteString(`	<h2>Crypto Agility Assessment</h2>
	<style>
		.agility-host { border:1px solid #ddd; border-radius:8px; padding:16px; margin:12px 0; }
		.agility-badge { display:inline-block; padding:4px 12px; border-radius:4px; font-weight:bold; color:#fff; margin-left:12px; }
		.agility-high { background:#2e7d32; }
		.agility-mid  { background:#e65100; }
		.agility-low  { background:#b71c1c; }
		.agility-bar-wrap { background:#eee; border-radius:4px; height:14px; width:300px; display:inline-block; vertical-align:middle; margin:0 8px; }
		.agility-bar      { background:#1a237e; height:14px; border-radius:4px; }
		.agility-dim      { margin:6px 0; font-size:0.9em; }
	</style>
`)
	for _, s := range scores {
		cls := "agility-low"
		switch {
		case s.Overall >= 70:
			cls = "agility-high"
		case s.Overall >= 40:
			cls = "agility-mid"
		}
		b.WriteString(fmt.Sprintf(`	<div class="agility-host">
		<h3>%s <span class="agility-badge %s">Overall: %d/100</span></h3>
`, html.EscapeString(s.Hostname), cls, s.Overall))
		for _, d := range s.Dimensions {
			b.WriteString(fmt.Sprintf(`		<div class="agility-dim"><strong>%s</strong> <span class="agility-bar-wrap"><span class="agility-bar" style="width:%d%%"></span></span> %d/100 &mdash; %s</div>
`, html.EscapeString(d.Name), d.Score, d.Score, html.EscapeString(d.Explanation)))
		}
		if len(s.Recommendations) > 0 {
			b.WriteString(`		<h4>Recommended actions</h4>
		<ul>
`)
			for _, r := range s.Recommendations {
				b.WriteString(fmt.Sprintf(`			<li>[<strong>%s</strong>, effort %s, impact +%d] %s <em>(%s)</em></li>
`, html.EscapeString(r.Dimension), html.EscapeString(string(r.Effort)), r.Impact, html.EscapeString(r.Action), html.EscapeString(r.Dimension)))
			}
			b.WriteString(`		</ul>
`)
		}
		b.WriteString(`	</div>
`)
	}
}
```

- [ ] **Step 4: Call `generateAgilityPanel` from `GenerateHTML`**

In `pkg/report/generator.go`, find the line immediately before `// Policy Analysis Summary (if policy evaluation data is present)` comment (currently near line 314). Insert:

```go
	g.generateAgilityPanel(result, &b)
```

- [ ] **Step 5: Run, verify PASS**

Run: `go test ./pkg/report/ -run 'TestGenerateHTML(Agility|NoAgility)' -v && go test ./pkg/report/ ./pkg/agility/`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/report/generator.go pkg/report/generator_test.go
git commit -m "feat(report): render Crypto Agility Assessment panel in HTML report"
```

---

## Task 9: Full-suite verification + lint

- [ ] **Step 1: Full unit test suite**

Run: `make test`
Expected: all green.

- [ ] **Step 2: Lint**

Run: `make lint`
Expected: clean. Fix any golangci-lint findings.

- [ ] **Step 3: Format check**

Run: `make fmt && git diff --exit-code`
Expected: no changes.

- [ ] **Step 4: Coverage spot-check for new package**

Run: `go test -cover ./pkg/agility/`
Expected: coverage ≥ 80%.

- [ ] **Step 5: Integration smoke — scan real directory, generate HTML, grep for section**

```bash
make build
./bin/triton --profile quick --scan-dir testdata 2>/dev/null || true
# agility panel may or may not appear depending on findings; at minimum verify no panic:
./bin/triton --profile comprehensive --scan-dir ./pkg --output-dir /tmp/triton-agility-smoke --skip-interactive 2>&1 | tail -20
ls /tmp/triton-agility-smoke/triton-report-*.html | head -1 | xargs grep -c "Crypto Agility Assessment"
```

Expected: binary builds, scan completes without error, HTML contains the section (count ≥ 1) if any findings exist.

- [ ] **Step 6: Commit any fix-ups and push branch**

```bash
git status  # should be clean or contain only lint fixes
git push -u origin feat/crypto-agility
```

---

## Task 10: Request code review

- [ ] **Step 1: Dispatch `superpowers:code-reviewer` on the branch**

Brief the reviewer with: "Review feat/crypto-agility end-to-end. New `pkg/agility/` package (scoring + recommendations) and HTML report panel in `pkg/report/generator.go`. Check: scoring edge cases (div-by-zero, nil CryptoAsset), rule-table correctness, HTML injection safety (every user-controlled field must go through `html.EscapeString`), determinism of output ordering."

- [ ] **Step 2: Apply review fixes in-branch**

For each finding:
- TDD: write failing test proving the bug, then fix.
- Commit each fix separately: `fix(agility): <subject>` or `fix(report): <subject>`.

- [ ] **Step 3: Dispatch `pensive:full-review` (architecture + bug-hunt in parallel)**

Apply fixes as above. Batch trivial doc tweaks into a single commit.

- [ ] **Step 4: Re-run `make test && make lint`**

Expected: clean.

- [ ] **Step 5: Open PR**

```bash
gh pr create --title "feat(agility): multi-dimensional crypto-agility scoring + HTML panel" --body "$(cat <<'EOF'
## Summary
- New `pkg/agility/` package: per-host 0-100 score across four dimensions (PQC Coverage, Protocol Agility, Configuration Flexibility, Operational Readiness)
- Recommendation engine emits up to 3 actionable next steps per low-scoring dimension
- HTML report gains a Crypto Agility Assessment panel with color-coded overall badge and per-dimension bars

## Pre-landing review
- superpowers:code-reviewer — applied
- pensive:full-review — applied

## Test plan
- [x] `go test ./pkg/agility/` (unit + scenario tests)
- [x] `go test ./pkg/report/` (HTML panel render + noop paths)
- [x] `make test && make lint` green
- [x] Smoke: `triton --profile comprehensive` on pkg/ produces HTML with the new panel

## Follow-ups (tracked in memory)
- CSV/CycloneDX/SARIF surfacing
- `GET /api/v1/systems/:hostname/agility` endpoint
- Web dashboard UI panel
- Abstraction-layer detection (EVP vs direct API)
- Trend tracking (schema change)
EOF
)"
```

---

## Self-Review Completed

- **Spec coverage:** All four dimensions, recommendation engine, HTML panel, tests covered. CSV/API/UI/trend explicitly deferred per scope proposal.
- **Placeholder scan:** None found. Every task has code blocks.
- **Type consistency:** `Score`, `Dimension`, `Recommendation`, `Effort` defined in Task 1, used consistently in Tasks 2-8. `Signal` used in dimension scorers. Module-name string constants (`"protocol"`, `"web_server"`, etc.) match real scanner output verified via grep.
- **Cross-task consistency:** `protocolModules` defined in Task 3 reused in Task 7 (`lowGroupDiversity`). `automationNeedles` + `certRotationScore` defined in Task 5 reused in Task 7. `isNamedGroup` helper from Task 3 reused in Task 7. No forward references.
