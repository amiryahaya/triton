# Policy Risk Levels + Exemptions

**Date:** 2026-04-17
**Branch:** `feat/policy-risk-exemptions`
**Scope:** Two enhancements to the existing YAML policy engine — risk level classification on rules and a separate exemptions file for known-accepted findings.

## Background

Triton's policy engine (`pkg/policy/`) evaluates scan findings against YAML rules and produces PASS/WARN/FAIL verdicts. Two gaps identified from PCert 4.5.5 analysis:

1. **No risk prioritization** — All violations are equal. A "RSA-1024 in production TLS" violation has the same weight as a "SHA-256 instead of SHA-384" preference warning. Compliance teams need triage: Critical/High/Medium/Low.
2. **No exemption mechanism** — Known-accepted findings (legacy CA, vendor-required algorithm) cannot be excluded from violations. Every scan produces the same false positives.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Risk model | Rule-level risk_level field | Simpler than PCert's multifilter cascade. Rule already declares the concern; risk level is metadata on the rule. |
| Risk values | critical, high, medium, low | Standard 4-level risk classification. Default: medium. |
| Exemption format | Separate YAML file | Exemptions are operational decisions, not policy definitions. Different owners, different change cadence. Survives policy upgrades. |
| Exemption matching | Thumbprint (serial+issuer) for certs, algorithm+location for others | Covers all finding types. Algorithm+location matches how compliance teams document accepted risks. |
| Exemption location | `--exemptions` CLI flag + env var | Same pattern as `--policy`. Nil-safe — no exemptions = no change in behavior. |
| Expiry | Optional ISO date on each exemption | Temporary exemptions auto-expire. Expired exemptions flagged in reports. |

## Feature 1: Risk Levels

### Rule schema change

Existing `rules` gain one optional field:

```yaml
rules:
  - id: weak-rsa
    severity: error
    risk_level: critical    # NEW — critical|high|medium|low (default: medium)
    condition:
      algorithm_family: RSA
      key_size_below: 2048
    action: fail
    message: "RSA key below 2048 bits"
```

### Data flow

```
Rule (risk_level: "critical")
  → matchesCondition() fires
    → Violation { RuleID, Severity, Action, Message, RiskLevel: "critical" }
      → model.PolicyViolation { ..., RiskLevel: "critical" }
        → HTML: violation row with colored risk badge
        → CycloneDX: triton:risk-level property
        → SARIF: level mapped from risk (critical→error, high→warning, medium→note, low→none)
```

Risk level is metadata carried through the pipeline. It does NOT change the verdict logic — `action: fail|warn` still determines PASS/WARN/FAIL.

### Risk summary

Computed after evaluation:

```go
type RiskSummary struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
}
```

Added to `EvaluationResult` and `model.PolicyEvaluationResult`.

### Builtin policy updates

**NACSA-2030:**

| Rule ID | Risk Level | Rationale |
|---------|-----------|-----------|
| `unsafe-algorithm` | critical | UNSAFE = immediately breakable |
| `weak-rsa-key` | critical | RSA < 2048 is breakable now |
| `des-algorithm` | critical | DES is trivially breakable |
| `rc4-algorithm` | critical | RC4 is broken |
| `md5-algorithm` | high | Collision attacks practical |
| `sha1-algorithm` | high | Collision attacks demonstrated |
| `deprecated-algorithm` | medium | DEPRECATED but not immediately breakable |

**CNSA 2.0:**

| Rule ID | Risk Level | Rationale |
|---------|-----------|-----------|
| `unsafe-algorithm` | critical | UNSAFE in CNSA context |
| `weak-rsa-key` | critical | RSA < 3072 for CNSA |
| `weak-ecdsa-key` | high | ECDSA < P-384 |
| `sha256-preference` | low | Works but SHA-384+ preferred |
| `deprecated-algorithm` | medium | Deprecated in CNSA timeline |

### HTML rendering

Risk breakdown bar in policy section:

```
┌─────────────────────────────────────────────┐
│ FAIL — NACSA-2030 PQC Compliance            │
│ 7 rules evaluated · 147 findings checked    │
│ 23 violations                               │
│                                             │
│ Risk: ██ 3 Critical  ███ 5 High             │
│       ████ 8 Medium  ██ 7 Low               │
└─────────────────────────────────────────────┘
```

Violation table rows get colored risk badges (red/orange/yellow/blue).

## Feature 2: Exemptions

### File format

Separate YAML file, loaded via `--exemptions` flag:

```yaml
version: "1"
exemptions:
  # Certificate exemption by serial+issuer
  - type: thumbprint
    serial_number: "123456789"
    issuer: "CN=Legacy Root CA,O=Example Corp"
    reason: "Legacy CA, vendor replacement scheduled Q3 2027"
    expires: 2027-09-30
    approved_by: "CISO"

  # Algorithm at specific location
  - type: algorithm
    algorithm: "SHA-1"
    location: "/etc/ssh/sshd_config"
    reason: "Hardware appliance requires SHA-1 MAC"
    expires: 2026-12-31

  # Algorithm from specific module (broader)
  - type: algorithm
    algorithm: "SHA-1"
    module: "configs"
    reason: "Legacy config files accepted during migration"
    expires: 2027-06-30

  # Algorithm anywhere (broadest)
  - type: algorithm
    algorithm: "3DES"
    reason: "Payment processing requires 3DES, PCI override"
```

### Matching rules

Evaluated before rule checking. A finding matching an exemption is skipped entirely.

| Exemption type | Matches when |
|---|---|
| `thumbprint` | `CryptoAsset.SerialNumber` matches AND `CryptoAsset.Issuer` matches |
| `algorithm` + location | `CryptoAsset.Algorithm` matches (case-insensitive) AND `FindingSource.Path` matches location (glob) |
| `algorithm` + module | `CryptoAsset.Algorithm` matches AND `Finding.Module` matches |
| `algorithm` alone | `CryptoAsset.Algorithm` matches (any source) |

### Expiry

- Past `expires` date → exemption ignored, finding evaluated normally
- No `expires` → permanent exemption
- Expired exemptions listed in evaluation result for audit

### Evaluation flow

```
for each finding:
    if exemptions.IsExempt(finding):
        record exemption hit (reason, count)
        continue  // skip all rule checks
    for each rule:
        if matchesCondition(finding, rule):
            add violation with rule.RiskLevel
```

### Audit trail in reports

HTML report gets an exemptions section after violations:

```
Exemptions Applied (3)
  • SHA-1 at /etc/ssh/sshd_config (2 findings)
    Reason: Hardware appliance requires SHA-1
    Expires: 2026-12-31 · Approved by: CISO

  • 3DES (5 findings)
    Reason: Payment processing PCI override
    Expires: permanent

⚠ Expired Exemptions (1)
  • SHA-1 at /opt/legacy/app.conf
    Expired: 2026-03-15 — findings now evaluated
```

### CLI integration

```bash
triton --policy nacsa-2030 --exemptions /path/to/exemptions.yaml
```

Env var: `TRITON_EXEMPTIONS_FILE=/etc/triton/exemptions.yaml`

## Model Changes

### pkg/model/types.go

New field on `PolicyViolation`:
```go
RiskLevel string `json:"riskLevel,omitempty"` // critical|high|medium|low
```

New fields on `PolicyEvaluationResult`:
```go
RiskSummary       *RiskSummary       `json:"riskSummary,omitempty"`
ExemptionsApplied []ExemptionApplied `json:"exemptionsApplied,omitempty"`
ExemptionsExpired []ExemptionExpired `json:"exemptionsExpired,omitempty"`
```

New types:
```go
type RiskSummary struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
}

type ExemptionApplied struct {
    Reason       string `json:"reason"`
    Expires      string `json:"expires,omitempty"`
    ApprovedBy   string `json:"approvedBy,omitempty"`
    FindingCount int    `json:"findingCount"`
    Algorithm    string `json:"algorithm,omitempty"`
    Location     string `json:"location,omitempty"`
}

type ExemptionExpired struct {
    Algorithm string `json:"algorithm"`
    Location  string `json:"location,omitempty"`
    ExpiredOn string `json:"expiredOn"`
}
```

## Package Changes

### pkg/policy/

| File | Change |
|------|--------|
| `policy.go` | Add `RiskLevel string` to `Rule` struct |
| `engine.go` | Add `exemptions *ExemptionList` param to `Evaluate()`. Pre-filter exemptions. Compute `RiskSummary`. Carry `RiskLevel` to violations. |
| `exemptions.go` | NEW — `ExemptionList`, `Exemption` types, `LoadExemptions()`, `IsExempt()` |
| `exemptions_test.go` | NEW — parsing, matching, expiry, nil-safety tests |
| `builtin/nacsa-2030.yaml` | Add `risk_level` to each rule |
| `builtin/cnsa-2.0.yaml` | Add `risk_level` to each rule |

### cmd/root.go

Add `--exemptions` flag + `TRITON_EXEMPTIONS_FILE` env var. Wire to `policy.Evaluate()`.

### pkg/report/

| File | Change |
|------|--------|
| `generator.go` | Risk breakdown bar in policy section. Exemptions section. Risk badge per violation row. |
| `cyclonedx.go` | `triton:risk-level` property on violation components |

## Testing Strategy

### Unit tests

| File | Key cases |
|---|---|
| `engine_test.go` (additions) | RiskLevelOnViolation, RiskLevelDefault, RiskSummary counts, RiskSummaryEmpty, WithExemptions (no violation), ExemptionExpired (violation created) |
| `exemptions_test.go` (new) | AlgorithmMatch, AlgorithmLocation, AlgorithmLocationGlob, AlgorithmMismatch, Thumbprint (serial+issuer), Expired, NoExpiry, NilList, LoadValidYAML, MissingReason validation |
| `generator_test.go` (additions) | RiskSummaryBar, ExemptionSection |
| `cyclonedx_test.go` (additions) | RiskLevelProperty |

### Coverage target

- `exemptions.go`: >85%
- Risk level additions: >80%

## New Dependencies

None.

## Backward Compatibility

- `risk_level` is optional on rules — existing custom policies work unchanged
- `Evaluate()` accepts nil exemptions — existing callers work unchanged
- Existing builtins gain `risk_level` but this is additive (no field removal)
- No schema migration (no database changes)

## Deferred

- Risk trend tracking over time (needs schema migration)
- Web UI risk dashboard
- API endpoint for risk summary
- Exemption management UI
- Per-system exemptions
- Exemption approval workflow
