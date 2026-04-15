# Crypto Agility Assessment — Scope Proposal (DRAFT, NOT A PLAN)

> **Status:** scope-only proposal; NOT yet an implementation plan. Approval required before writing the executable plan and dispatching subagents.

## Why

Triton currently has asset-level agility labels (`pkg/crypto/agility.go`, ~167 lines) producing Malay text for the Jadual 2 government CSV (column H "Sokongan Crypto-Agility"). Used by `pkg/report/excel.go` and `pkg/model/grouper.go`.

That covers per-asset classification only — a single string label per crypto asset. It does NOT answer the actual question buyers (NACSA, NIST, CISO teams) ask: **"How fast can this *system* migrate to PQC?"** That requires:

1. System-level scoring (one score per host, not per asset)
2. Multi-dimensional breakdown (where am I weak?)
3. Recommendations (what do I do Tuesday morning?)

This is differentiating — no competitor (CBOMkit, Syft, Snyk, Trivy, Wiz) ships a multi-dimensional crypto-agility assessment.

## Proposed PR #1 scope

### In scope

**Package:** `pkg/agility/` (new) — agility assessment engine.

**Types:**
```go
type Score struct {
    Hostname        string
    Overall         int                    // 0-100 weighted sum
    Dimensions      map[string]Dimension   // 4 dimensions
    Recommendations []Recommendation
    GeneratedAt     time.Time
}

type Dimension struct {
    Name        string  // e.g. "PQC Coverage"
    Score       int     // 0-100
    Weight      float64 // contribution to Overall
    Signals     []Signal
    Explanation string
}

type Recommendation struct {
    Dimension string
    Action    string  // e.g. "Add X25519MLKEM768 to nginx ssl_ecdh_curve"
    Effort    string  // S/M/L
    Impact    int     // expected dimension-score delta
}
```

**Four dimensions:**

1. **PQC Coverage (weight 0.35)** — % of crypto assets classified SAFE or with `IsHybrid: true`. Easy metric, reuses existing classifier.

2. **Protocol Agility (weight 0.25)** — TLS version range, named-group diversity, hybrid-group presence. Sources: `protocol`, `web_server`, `vpn_config` findings. Higher diversity + TLS 1.3 + hybrid groups = higher score.

3. **Configuration Flexibility (weight 0.20)** — ratio of config-referenced crypto vs hardcoded. Config-referenced = findings from `config.go`/`web_server.go`/`vpn_config.go` (algorithm in editable file). Hardcoded = findings from `binary.go`/`asn1_oid.go`/`java_bytecode.go` (algorithm baked into compiled artifact). Higher ratio = more agile.

4. **Operational Readiness (weight 0.20)** — cert expiry-window distribution (shorter rotations = more agile), HSM detection, automation tool presence (cert-manager, certbot detected via `package.go` or `process.go`). Composite score from these signals.

**Recommendation engine:** for each low-scoring dimension, generate 1-3 actionable next steps using a rules table. Examples:
- PQC Coverage < 20 → "Enable BouncyCastle-PQC provider in Java applications"
- Protocol Agility < 30 + nginx detected → "Add `ssl_ecdh_curve X25519MLKEM768:X25519` to nginx config"
- Config Flexibility < 40 + Java bytecode dominates → "Move JCE provider config to java.security file instead of compile-time pinning"
- Operational < 30 + certs >365d to expire → "Enable cert-manager auto-renewal"

**HTML report panel:** new "Agility Assessment" section above the existing CBOM table. Per-dimension horizontal bar chart (CSS-only, no JS), Overall score badge, recommendations list. Skipped if no findings.

**Tests:**
- Unit tests per dimension (pure-function scoring)
- Synthetic-system scenario tests (high-agility, mixed, low-agility)
- Recommendation generation tests
- HTML rendering test

### Out of scope (deliberate; defer to follow-up PRs)

| Item | Reason for deferral |
|---|---|
| CSV Jadual 3 / CycloneDX metadata / SARIF | Report format expansion is its own PR |
| `GET /api/v1/systems/:hostname/agility` endpoint | API addition is its own PR |
| Web dashboard UI panel | UI work is its own PR |
| Abstraction-layer detection (EVP vs direct API) | Needs library fingerprinting infrastructure |
| Trend tracking over time | Needs schema migration |
| 5th dimension "Implementation Agility" | Depends on abstraction-layer work |

## Estimated effort

~1 day with subagent execution. Similar shape to prior scanner PRs. ~6 tasks across 4 phases:

1. Core types + scorer skeleton + dimension 1 (PQC Coverage)
2. Dimensions 2-4 (Protocol / Config / Operational)
3. Recommendation engine
4. HTML integration + scenario tests + docs

## Decision points before writing implementation plan

- **Weights** (0.35/0.25/0.20/0.20) — defensible? Should one dimension dominate more? User feedback before locking in.
- **Score scale** (0-100 vs A-F vs traffic-light) — 0-100 is clearest for trending, A-F is friendlier for execs. Both?
- **Recommendation format** (1-3 per low dim vs flat list) — affects HTML layout.
- **Where the code lives** — `pkg/agility/` (new) vs extending `pkg/crypto/agility.go`. New package is cleaner separation.

## Resume instructions

When picking this back up:

1. Read this doc + `memory/in-depth-scanners-roadmap.md` for context.
2. Confirm or revise the scope above with the user.
3. Once scope is approved, write a real implementation plan at `docs/plans/2026-04-15-crypto-agility-scanner.md` following the established pattern (TDD steps, code blocks, exact commit messages).
4. Dispatch via `superpowers:subagent-driven-development`, one phase per agent.
5. After implementation: `superpowers:requesting-code-review`, then `pensive:full-review`. Apply fixes, ship.
