# Analytics Phase 2 — Design Spec (Executive Summary)

> **For Claude:** After this spec is approved, invoke `superpowers:writing-plans` to produce the step-by-step implementation plan. Do NOT invoke any other skill.

**Parent plan:** `docs/plans/2026-04-09-analytics-phases.md` — this spec details Phase 2 of the six-phase analytics roadmap.

**Goal:** Extend the existing Overview dashboard (`#/`) with an executive-summary block designed for a CISO/executive audience. A single glance at the Overview now answers: *"How ready am I? Am I trending up or down? When will I finish? What should I fix first? Do I pass compliance?"*

**Effort:** ~2–3 days of focused work. **One new endpoint** (`GET /api/v1/executive`), **one new pure-math package** (`pkg/analytics`), **one small schema migration** (two columns on `organizations`), and an **extended `renderOverview()`** in `app.js`.

---

## 1. Scope

### In scope

- New `pkg/analytics` package containing three pure functions:
  - `ComputeOrgTrend(scans []*ScanResult) TrendSummary` — monthly-bucketed org-wide trend classification
  - `ComputeProjection(trend TrendSummary, targetPercent float64, deadlineYear int) ProjectionSummary` — pace-based projection with per-org settings
  - `ComputeMachineHealth(machines []ScanSummary) MachineHealthTiers` — red/yellow/green tier rollup
- New endpoint `GET /api/v1/executive` returning a single `ExecutiveSummary` payload
- One new store method: `ListScansOrderedByTime(ctx, orgID)` — thin wrapper around `ListScans` with `ORDER BY timestamp ASC`
- Extended `store.Organization` struct with `ExecutiveTargetPercent float64` and `ExecutiveDeadlineYear int` fields
- Migration v9: `ALTER TABLE organizations` adding two columns with sensible defaults (80, 2030)
- Two built-in policy evaluations per request (NACSA-2030 + CNSA-2.0)
- Extended `renderOverview()` in `app.js` with: compact summary bar, upgraded Machines stat card (tier breakdown), top-5 blockers strip
- ~90 lines of new CSS for the new components
- Unit + integration + E2E test coverage per the project pyramid
- Documentation updates: `DEPLOYMENT_GUIDE.md` gets an executive-summary section, `SYSTEM_ARCHITECTURE.md` gets a paragraph on `pkg/analytics`, `MEMORY.md` gets a Phase 2 completion marker

### Out of scope (deferred to later phases or dropped)

- **Admin UI for per-org settings** — Phase 2.5 will add an admin form for `org_admin` to change target/deadline without SQL
- **Server-wide environment variables** for projection config — explicitly NOT used; configuration is per-org, not per-deployment
- **Client-side localStorage preferences** — explicitly NOT used; each org has one canonical configuration, not per-browser
- **Additional policies beyond NACSA-2030 + CNSA-2.0** — the response shape accommodates more via array, but only two built-ins are evaluated in Phase 2
- **Drill-through interactions** — clicking a policy chip, a trend chip, or the Machines tier badges does nothing. Phase 3 (category filters) and Phase 4 (remediation) revisit interactivity.
- **Per-host executive summary** — projection is org-wide only. Per-host projection is a Phase 6 advanced analytics feature.
- **Historical snapshot export** — no "save this dashboard state as of today" feature. Out of Phase 2.
- **Executive summary customization** — no hiding chips, no reordering, no "show extended table mode." Fixed layout.
- **Exponential decay or regression projection math** — rejected in favor of simple pace. Phase 2.5+ could add alternate models if demanded.
- **Sparkline chart inside the summary bar** — the `MonthlyPoints` field is shipped in the response for free (computed anyway), but Phase 2 does not render it. Phase 3+ can add sparkline rendering as a pure UI change.
- **Caching the `/executive` response** — computed per request. If load is a concern, add per-org 30-second TTL cache in Phase 2.5+.
- **Benchmarks / load tests** — not in Phase 2. Add if real deployment shows slowness.

---

## 2. Decision log

Decisions locked in during the 2026-04-10 brainstorming session. Each has a one-line rationale so future-me knows why we made the call.

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Extend existing `renderOverview()`, not a separate `#/exec` route | Maximum visibility — operators who visit the landing page see the exec summary without navigating |
| 2 | Executive/CISO-first layout, ops detail below | CISO audience has 30 seconds; summary bar delivers the answer at a glance; ops drill-down preserved |
| 3 | Compact summary bar (single horizontal row, Option B from layout mockup) | Minimum disruption to existing Overview; fits all five exec elements in one row |
| 4 | Both NACSA-2030 and CNSA-2.0 policy chips side-by-side (Option B) | Covers Triton's Malaysian + US-defense audiences without deploy-time configuration |
| 5 | Upgrade Machines stat card with red/yellow/green tier breakdown (Option B) | Adds machine health to the exec layer without new layout rows |
| 6 | Tier rules: red = any unsafe > 0; yellow = no unsafe, any deprecated; green = only safe/transitional (including zero findings) | Strict: one unsafe finding is a legitimate crisis; magnitude-based weighting lives in the existing "Machines by risk" bar chart |
| 7 | Simple pace math for projection, default 80% target / 2030 deadline | Honest and explainable: "at current pace by year N"; reserves exponential/regression for Phase 2.5+ |
| 8 | Flat threshold 0.1%/month for "insufficient-movement"; 70-year sanity cap; regressing severity red — all hard-coded | Math plumbing, not user preferences — nobody should have to think about these |
| 9 | One new endpoint `GET /api/v1/executive` returning everything in one payload | Single round-trip; server-side computation; cleaner UI code |
| 10 | Monthly-bucket trend aggregation (calendar months, latest scan per host per bucket) | Robust to scan-frequency bias; calendar months map to how humans plan migration work |
| 11 | Reuse `store.ListTopPriorityFindings(ctx, orgID, 5)` for top-5 blockers | Phase 1 gave us exactly this — don't duplicate the query |
| 12 | Per-org config via `organizations` table columns (`executive_target_percent`, `executive_deadline_year`) | Matches "each organization might have their own configuration" — not per-browser, not per-deployment, not per-user |
| 13 | No admin UI for per-org settings in Phase 2 — SQL override only | Keeps Phase 2 tight; admin UI is a 2-hour add-on for Phase 2.5 when a customer asks |
| 14 | UI does NOT do projection math — server computes `projectedYear` and `explanationText` with org settings | UI stays thin; consistent string composition across future UIs (CLI, PDF); no localStorage state |

---

## 3. Architecture

### Data flow

```
UI: renderOverview() (#/)
      │
      │ Promise.all([
      │   GET /api/v1/aggregate      (existing — unchanged)
      │   GET /api/v1/executive      (NEW)
      │ ])
      ▼
┌─────────────────────────────────────────────────────┐
│ pkg/server/handlers_analytics.go                    │
│   handleExecutiveSummary                            │
│     │                                               │
│     ├─► store.GetOrg(orgID)                         │
│     │     reads executive_target_percent + year     │
│     │                                               │
│     ├─► store.ListScansOrderedByTime(orgID)         │
│     │     NEW thin store method, chronological asc  │
│     │                                               │
│     ├─► (for trend) loads each scan's ScanResult    │
│     │     via existing GetScan → decrypts blob      │
│     │                                               │
│     ├─► analytics.ComputeOrgTrend(scans)            │
│     │     monthly buckets, latest per host per bucket│
│     │                                               │
│     ├─► analytics.ComputeProjection(trend, target,  │
│     │                               deadline)       │
│     │     pace + explanationText                    │
│     │                                               │
│     ├─► analytics.ComputeMachineHealth(summaries)   │
│     │     red/yellow/green counts                   │
│     │                                               │
│     ├─► store.ListTopPriorityFindings(orgID, 5)     │
│     │     REUSE Phase 1 method                      │
│     │                                               │
│     ├─► policy.LoadBuiltin("nacsa-2030") + Evaluate │
│     │                                               │
│     └─► policy.LoadBuiltin("cnsa-2.0") + Evaluate   │
└─────────────────────────────────────────────────────┘
      │
      │ ExecutiveSummary JSON
      ▼
UI: renders summary bar + upgraded Machines card +
    top blockers strip + existing charts + machines table
```

### Architectural properties

1. **No new storage** — everything is computed from data Phase 1 already persists (`scans` table + `findings` table).
2. **One new package `pkg/analytics`** — pure math functions, no DB, no HTTP. Trivially unit-testable.
3. **One new store method `ListScansOrderedByTime`** — thin wrapper around existing `ListScans` with ascending sort. The existing method only supports newest-first; trend series needs oldest-first.
4. **Two policy evaluations per request** — both built-in policies loaded via `policy.LoadBuiltin()`, which is an embedded `//go:embed` YAML load. Fast (~1ms) and in-process.
5. **Per-org configuration via DB columns, not env vars** — multi-tenant correct. Each org's `executive_target_percent` and `executive_deadline_year` drive the projection math.
6. **Graceful degradation** — if `/executive` fails, the existing Overview (stat cards, charts, machines table) still renders from `/aggregate`. The new exec block shows an error banner in that case but doesn't break the page.
7. **Backward compatible** — `/aggregate`, `/trend`, `/priority`, `/inventory`, `/certificates/expiring` all unchanged. Existing clients keep working.
8. **Parallel fetch** — `Promise.all([/aggregate, /executive])` runs both GETs concurrently. Total load time ≈ max(both) rather than sum.

---

## 4. API contract

### `GET /api/v1/executive`

- **Query params:** none
- **Auth:** JWT required; tenant-scoped via existing `RequireTenant` middleware
- **Response:** `200 OK` with `store.ExecutiveSummary`
- **Errors:**
  - `401` — no JWT (middleware)
  - `403` — no tenant (middleware)
  - `500` — store, policy, or analytics failures (logged, generic message to client)
- **Headers:** `X-Backfill-In-Progress: true` when `srv.backfillInProgress` is set (consistent with Phase 1)

### Response type (`pkg/store/types.go` additions)

```go
// ExecutiveSummary is the response body for GET /api/v1/executive.
type ExecutiveSummary struct {
    Readiness      ReadinessSummary        `json:"readiness"`
    Trend          TrendSummary            `json:"trend"`
    Projection     ProjectionSummary       `json:"projection"`
    PolicyVerdicts []PolicyVerdictSummary  `json:"policyVerdicts"`
    TopBlockers    []PriorityRow           `json:"topBlockers"` // reuses Phase 1 type
    MachineHealth  MachineHealthTiers      `json:"machineHealth"`
}

type ReadinessSummary struct {
    Percent       float64 `json:"percent"`       // rounded to 1 decimal
    TotalFindings int     `json:"totalFindings"`
    SafeFindings  int     `json:"safeFindings"`
}

type TrendSummary struct {
    Direction     string            `json:"direction"`     // improving|declining|stable|insufficient-history
    DeltaPercent  float64           `json:"deltaPercent"`  // first→last readiness delta
    MonthlyPoints []TrendMonthPoint `json:"monthlyPoints"` // shipped for free; UI may use later
}

type TrendMonthPoint struct {
    Month         string  `json:"month"`         // "2026-04" (YYYY-MM)
    Readiness     float64 `json:"readiness"`
    TotalFindings int     `json:"totalFindings"`
}

type ProjectionSummary struct {
    Status          string  `json:"status"`          // see table below
    TargetPercent   float64 `json:"targetPercent"`   // from org settings, default 80
    DeadlineYear    int     `json:"deadlineYear"`    // from org settings, default 2030
    PacePerMonth    float64 `json:"pacePerMonth"`    // rounded to 1 decimal
    ProjectedYear   int     `json:"projectedYear"`   // 0 when Status is non-computable
    ExplanationText string  `json:"explanationText"` // server-composed
}

type PolicyVerdictSummary struct {
    PolicyName      string `json:"policyName"`      // "nacsa-2030" | "cnsa-2.0"
    PolicyLabel     string `json:"policyLabel"`     // "NACSA-2030" | "CNSA-2.0"
    Verdict         string `json:"verdict"`         // "PASS" | "WARN" | "FAIL"
    ViolationCount  int    `json:"violationCount"`
    FindingsChecked int    `json:"findingsChecked"`
}

type MachineHealthTiers struct {
    Red    int `json:"red"`
    Yellow int `json:"yellow"`
    Green  int `json:"green"`
    Total  int `json:"total"`
}
```

### Projection status enum

| Status | When | UI color | Example `explanationText` |
|--------|------|---------|---------------------------|
| `insufficient-history` | 0 or 1 monthly buckets | grey | *"Insufficient history — run at least two scans across different months."* |
| `already-complete` | `lastReadiness >= targetPercent` | green | *"Already at 87.3% — past the 80% target."* |
| `regressing` | `pace < 0` | red | *"Regressing — net readiness dropping 0.4% per month over the last 6 months."* |
| `insufficient-movement` | `0 ≤ pace < 0.1` | yellow | *"Insufficient movement — readiness nearly flat over the last 4 months."* |
| `capped` | projected > current_year + 70 | red | *"Capped — at 0.05%/month, reaching 80% would take over 70 years."* |
| `on-track` | `projectedYear ≤ deadlineYear` | green | *"On track — 1.2%/month pace projects 80% readiness by 2028."* |
| `behind-schedule` | `projectedYear > deadlineYear` | orange | *"Behind schedule — 0.3%/month pace projects 80% readiness by 2045, past the 2030 deadline."* |

### Empty-org response (fresh org with no scans)

```json
{
  "readiness": {"percent": 0, "totalFindings": 0, "safeFindings": 0},
  "trend": {"direction": "insufficient-history", "deltaPercent": 0, "monthlyPoints": []},
  "projection": {
    "status": "insufficient-history",
    "targetPercent": 80,
    "deadlineYear": 2030,
    "pacePerMonth": 0,
    "projectedYear": 0,
    "explanationText": "Insufficient history — run at least two scans across different months."
  },
  "policyVerdicts": [
    {"policyName": "nacsa-2030", "policyLabel": "NACSA-2030", "verdict": "PASS", "violationCount": 0, "findingsChecked": 0},
    {"policyName": "cnsa-2.0",   "policyLabel": "CNSA-2.0",   "verdict": "PASS", "violationCount": 0, "findingsChecked": 0}
  ],
  "topBlockers": [],
  "machineHealth": {"red": 0, "yellow": 0, "green": 0, "total": 0}
}
```

---

## 5. Core algorithms

### 5.1 `ComputeOrgTrend` — monthly-bucket aggregation

**Input:** `[]*model.ScanResult` for the org, any order
**Output:** `store.TrendSummary`

**Steps:**

1. Empty input → return `{direction: "insufficient-history", monthlyPoints: []}`
2. Group scans by `(month, hostname)`, keep the LATEST scan per key (greatest `Metadata.Timestamp`)
3. Aggregate by month: for each month, sum `safe` and `total` (safe+trans+dep+unsafe) across hosts
4. Compute per-month readiness: `readiness = safe / total * 100`, rounded to 1 decimal
5. Sort months chronologically (`"2026-01" < "2026-02"` lexicographically works)
6. Classify direction:
   - `< 2 points` → `insufficient-history`
   - `delta > +1.0` → `improving`
   - `delta < -1.0` → `declining`
   - otherwise → `stable`
7. Return `TrendSummary{Direction, DeltaPercent, MonthlyPoints}`

**Rationale for "latest scan per host per month":**
- A host that re-scans 20× in one month shouldn't dominate the bucket's readiness.
- The LATEST scan per host per month is the best single snapshot of that host's state at month-end.
- Averaging across a host's many scans in a month would distort readiness if a remediation landed mid-month.

**Rationale for calendar months (vs. sliding 30-day windows):**
- Calendar months map to how humans plan migration work.
- Deterministic boundaries make tests reliable.

### 5.2 `ComputeProjection` — pace-based projection

**Input:** `TrendSummary`, `targetPercent float64`, `deadlineYear int` (both from org settings)
**Output:** `ProjectionSummary`

**Constants (hard-coded):**
- `FlatThresholdPercent = 0.1` — pace floor below which projection is "insufficient-movement"
- `MaxProjectionYears = 70` — sanity cap

**Steps:**

1. Init `out.TargetPercent = targetPercent`, `out.DeadlineYear = deadlineYear`
2. No monthly points → `insufficient-history`, return with explanation
3. `lastReadiness >= targetPercent` → `already-complete`, return
4. Fewer than 2 points → `insufficient-history`, return
5. Compute `monthsBetween = lastMonth - firstMonth` (floor at 1 to avoid div-by-zero)
6. Compute `pacePerMonth = (lastReadiness - firstReadiness) / monthsBetween`, rounded to 1 decimal
7. `pace < 0` → `regressing`, return with "dropping X%/month over last N months"
8. `pace < FlatThresholdPercent` → `insufficient-movement`, return
9. Compute `remaining = targetPercent - lastReadiness`, `monthsNeeded = remaining / pace`
10. Compute `projectedYear = now.Year() + ceil(monthsNeeded / 12)`
11. `yearsNeeded > MaxProjectionYears` → `capped`, return
12. `projectedYear <= deadlineYear` → `on-track`, return
13. Otherwise → `behind-schedule`, return

**Rationale for 0.1%/month flat threshold:**
- Below this, any extrapolation produces absurd year projections (e.g., year 2193).
- Operators should see "nothing is changing" not "we'll be done in 150 years."

**Rationale for 70-year cap:**
- Pure sanity — no operator wants to see "projected completion: year 2400."
- Matches the honest answer: *"at this pace, this will effectively never complete."*

**Rationale for round-up on partial years:**
- Conservative: a projection of 2.3 years rounds to 3, never 2. Promise the LATER date.

### 5.3 `ComputeMachineHealth` — tier classification

**Input:** `[]store.ScanSummary` — the latest scan per hostname (use existing `latestByHostname` helper)
**Output:** `store.MachineHealthTiers`

**Rules:**

- `Unsafe > 0` → **red** (one unsafe finding is a legitimate crisis regardless of magnitude)
- `Deprecated > 0 && Unsafe == 0` → **yellow**
- otherwise → **green** (includes pure-safe, all-transitional, and zero-finding machines)

**Design decisions:**

- **Strict "any unsafe = red"** — no magnitude threshold. One DES key in production is as bad as ten.
- **Zero findings counts as green** — an empty-scan machine (minimal IoT, for example) is not broken; it's fine.
- **No weighted scoring** — that's the existing "Machines by risk" bar chart's job. The tier rollup is a yes/no categorization.
- **No time component** — always uses the latest scan per host. Historical "had unsafe 6 months ago" is outside the mental model.
- **No exceptions table** — operators can't mark "accepted risk; treat as green." That's a Phase 4 remediation feature.

---

## 6. Database schema

### Migration v9 — `organizations` executive config columns

```sql
-- Version 9: Executive summary display preferences per org (Analytics Phase 2).
--
-- Two columns on the existing organizations table carry each org's
-- compliance target and deadline. Defaults are chosen for Triton's
-- primary audience (Malaysian government / NACSA-2030); operators
-- with different needs override per-org.
--
-- No admin UI in Phase 2 — operators override via direct SQL:
--
--   UPDATE organizations
--   SET executive_target_percent = 95,
--       executive_deadline_year  = 2035
--   WHERE name = 'US Defense Contractor';
--
-- Phase 2.5 will add an admin form for org_admin to change these
-- without SQL.
--
-- See docs/plans/2026-04-10-analytics-phase-2-design.md §6.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS executive_target_percent NUMERIC(5,2) NOT NULL DEFAULT 80.0;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS executive_deadline_year INTEGER NOT NULL DEFAULT 2030;
```

### Store changes

**`pkg/store/types.go`** — extend `Organization`:

```go
type Organization struct {
    ID                     string
    Name                   string
    ExecutiveTargetPercent float64  // NEW — default 80
    ExecutiveDeadlineYear  int      // NEW — default 2030
    CreatedAt              time.Time
    UpdatedAt              time.Time
}
```

**`pkg/store/identity_postgres.go`** — extend `GetOrg`:

```sql
SELECT id, name, executive_target_percent, executive_deadline_year, created_at, updated_at
FROM organizations
WHERE id = $1;
```

Scan target adds `&org.ExecutiveTargetPercent, &org.ExecutiveDeadlineYear`.

**`pkg/store/identity_postgres.go`** — extend `CreateOrg` (if it exists — otherwise the DEFAULT clause handles new rows silently):

```sql
INSERT INTO organizations (id, name, executive_target_percent, executive_deadline_year, created_at, updated_at)
VALUES ($1, $2, $3, $4, NOW(), NOW());
```

If Phase 2 finds `CreateOrg` doesn't currently insert those columns, it relies on the DB `DEFAULT` clause — no change needed. If it does, add them.

### New store method

**`pkg/store/findings.go`** — append:

```go
// ListScansOrderedByTime returns all scan summaries for the given org,
// sorted by timestamp ASCENDING (oldest first). This is the
// chronological ordering required by the trend series computation in
// pkg/analytics.ComputeOrgTrend. The existing ListScans returns
// newest-first — that's the right default for dashboards but wrong
// for trend math.
//
// Returns an empty slice (not nil) when the org has no scans yet.
// Analytics Phase 2.
func (s *PostgresStore) ListScansOrderedByTime(ctx context.Context, orgID string) ([]ScanSummary, error) {
    rows, err := s.pool.Query(ctx, `
        SELECT id, hostname, timestamp, profile,
               total_findings, safe, transitional, deprecated, unsafe
        FROM scans
        WHERE org_id = $1
        ORDER BY timestamp ASC
    `, orgID)
    if err != nil {
        return nil, fmt.Errorf("ListScansOrderedByTime: %w", err)
    }
    defer rows.Close()

    out := make([]ScanSummary, 0)
    for rows.Next() {
        var s ScanSummary
        if err := rows.Scan(&s.ID, &s.Hostname, &s.Timestamp, &s.Profile,
            &s.TotalFindings, &s.Safe, &s.Transitional, &s.Deprecated, &s.Unsafe); err != nil {
            return nil, fmt.Errorf("ListScansOrderedByTime scan: %w", err)
        }
        out = append(out, s)
    }
    return out, rows.Err()
}
```

Also on the `Store` interface:

```go
ListScansOrderedByTime(ctx context.Context, orgID string) ([]ScanSummary, error)
```

---

## 7. UI changes

### Extended `renderOverview()` in `app.js`

```js
async function renderOverview() {
  content.innerHTML = '<div class="loading">Loading overview...</div>';
  try {
    // Parallel fetch — both are idempotent GETs.
    const [agg, exec] = await Promise.all([
      api('/aggregate'),
      api('/executive').catch(e => {
        // Graceful degradation: exec failure doesn't break Overview.
        // We log it and render without the new exec block.
        console.warn('executive summary unavailable:', e);
        return null;
      }),
    ]);

    let html = `<h2>Organization Overview</h2>`;
    if (exec) {
      html += renderExecSummaryBar(exec);
    }
    html += renderStatCards(agg, exec ? exec.machineHealth : null);
    html += renderCharts(agg);  // unchanged — placeholder anchors for donut + bar
    if (exec && exec.topBlockers && exec.topBlockers.length > 0) {
      html += renderTopBlockers(exec.topBlockers);
    }
    html += renderMachinesTable(agg.machines);

    content.innerHTML = html;
    wireClickableRows();
    renderDonutChart(agg);
    renderBarChart(agg);
    renderBackfillBanner(content);  // reuse Phase 1 helper
  } catch (e) {
    content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
  }
}
```

### Four new helper functions

**`renderExecSummaryBar(exec)`** — single-row summary bar (CSS grid flex). ~35 lines. Renders readiness, trend chip, two policy chips, projection text with status-specific CSS classes.

**`renderTopBlockers(blockers)`** — horizontal chip strip with label, 5 chips, "See all priorities →" link. ~25 lines.

**`renderStatCards(agg, machineHealth)`** — refactored from inline code in the current `renderOverview`. Takes the aggregate object and the optional tier breakdown. Upgraded Machines card includes `<div class="machine-tiers">` when tiers are present. Falls back to plain count when `machineHealth == null`. ~40 lines (mostly extracted from current inline code).

**`renderCharts(agg)`** / **`renderMachinesTable(agg.machines)`** — extracted helpers, zero behavior change from current inline code. Kept separate for readability.

### New CSS (`pkg/server/ui/dist/style.css`)

```css
/* ============================================================
   Analytics Phase 2 — Executive Summary block on Overview
   ============================================================ */

.exec-summary-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 16px;
  margin-bottom: 16px;
  background: rgba(148, 163, 184, 0.06);
  border: 1px solid rgba(148, 163, 184, 0.12);
  border-radius: 10px;
  flex-wrap: wrap;
}

.exec-readiness {
  flex: 0 0 auto;
  padding-right: 12px;
  border-right: 1px solid rgba(148, 163, 184, 0.12);
}
.exec-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #64748b;
}
.exec-value {
  font-size: 26px;
  font-weight: 700;
  color: #22d3ee;
  line-height: 1.1;
}

.exec-chip {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  background: rgba(148, 163, 184, 0.08);
  color: #e2e8f0;
  white-space: nowrap;
}
.exec-chip--trend-improving { background: rgba(52,211,153,0.12); color: #34d399; }
.exec-chip--trend-declining { background: rgba(248,113,113,0.12); color: #f87171; }
.exec-chip--trend-stable    { background: rgba(148,163,184,0.12); color: #94a3b8; }
.exec-chip--pass { background: rgba(52,211,153,0.12); color: #34d399; }
.exec-chip--warn { background: rgba(251,191,36,0.12); color: #fbbf24; }
.exec-chip--fail { background: rgba(248,113,113,0.12); color: #f87171; }

.exec-projection {
  flex: 1 1 auto;
  text-align: right;
  font-size: 12px;
  color: #94a3b8;
}
.exec-projection--on-track             { color: #34d399; }
.exec-projection--behind-schedule      { color: #fb923c; }
.exec-projection--regressing           { color: #f87171; }
.exec-projection--capped               { color: #f87171; }
.exec-projection--already-complete     { color: #34d399; }
.exec-projection--insufficient-history { color: #64748b; }
.exec-projection--insufficient-movement{ color: #fbbf24; }

.machine-tiers {
  display: flex;
  gap: 6px;
  margin-top: 4px;
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}
.tier {
  padding: 1px 6px;
  border-radius: 3px;
  font-weight: 600;
}
.tier-red    { background: rgba(248,113,113,0.18); color: #f87171; }
.tier-yellow { background: rgba(251,191,36,0.18); color: #fbbf24; }
.tier-green  { background: rgba(52,211,153,0.18); color: #34d399; }

.top-blockers-strip {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 16px;
  background: rgba(148, 163, 184, 0.04);
  border: 1px solid rgba(148, 163, 184, 0.08);
  border-radius: 8px;
  flex-wrap: wrap;
}
.top-blockers-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #64748b;
  white-space: nowrap;
}
.top-blockers-list {
  display: flex;
  gap: 6px;
  flex: 1;
  flex-wrap: wrap;
  align-items: center;
}
.blocker-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 11px;
  background: rgba(248, 113, 113, 0.1);
}
.blocker-score {
  font-weight: 600;
  color: #f87171;
  font-variant-numeric: tabular-nums;
}
.blocker-algo {
  color: #e2e8f0;
}
.top-blockers-more {
  color: #22d3ee;
  font-size: 11px;
  white-space: nowrap;
  text-decoration: none;
}
```

### File growth

| File | Current | After Phase 2 | Growth |
|------|---------|---------------|--------|
| `pkg/server/ui/dist/app.js` | ~1250 | ~1340 | +90 |
| `pkg/server/ui/dist/style.css` | ~1000 | ~1108 | +108 |
| `pkg/server/ui/dist/index.html` | unchanged | unchanged | 0 |

`app.js` stays within the "single-file reasonable" zone. If Phase 3 or 4 pushes it past 1500 lines, flag a split then.

---

## 8. Testing strategy

### Test pyramid

```
            E2E (Playwright)   4 tests on analytics.spec.js
          Integration (Go+PG) ~18 tests, //go:build integration
             Unit (Go)        ~25 tests, no build tag
```

### Unit tests — `pkg/analytics/*_test.go` (no DB, no build tag)

**`trend_test.go`** — ~10 tests covering empty input, single scan, two scans same month, two months improving/declining/stable, multi-host bucketing, host drop-in/out, re-scan in same month (keeps latest), chronological sorting.

**`projection_test.go`** — ~11 tests covering 0/1 points (insufficient-history), already-complete, positive pace on-track, positive pace behind-schedule, negative pace regressing, flat threshold, 70-year cap, custom target (60%), custom deadline (2035), explanation text format.

**`machine_health_test.go`** — ~7 tests covering empty slice, single red (any unsafe), single yellow (deprecated only), single green (safe only), single green (zero findings), mixed tiers, unsafe-wins-over-deprecated precedence.

### Integration tests — `//go:build integration`

**`pkg/store/findings_test.go`** — append 3 tests for `ListScansOrderedByTime` (empty org, sorted ascending, tenant isolation).

**`pkg/store/identity_test.go`** — append 2 tests for the new Organization columns (`TestGetOrg_DefaultsExecutiveConfig` — new org gets 80/2030; `TestUpdateOrg_ExecutiveConfig` — SQL updates roundtrip through GetOrg).

**`pkg/server/handlers_analytics_test.go`** — append 8 tests for `handleExecutiveSummary`:

- `TestHandleExecutive_EmptyOrgReturnsZeroes`
- `TestHandleExecutive_PopulatedReturnsFullSummary`
- `TestHandleExecutive_NoJWTReturns401`
- `TestHandleExecutive_TenantIsolation`
- `TestHandleExecutive_BackfillHeaderWhenInProgress`
- `TestHandleExecutive_UsesOrgTargetPercent` — custom target respected
- `TestHandleExecutive_UsesOrgDeadlineYear` — custom deadline respected
- `TestHandleExecutive_PolicyVerdictsIncludeBothBuiltins`

### E2E tests — `test/e2e/analytics.spec.js` (append)

```js
test.describe('Overview — executive summary block', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/');
    await page.waitForSelector('.exec-summary-bar, .empty-state', { timeout: 10_000 });
  });

  test('renders the summary bar with readiness percent', async ({ page }) => { ... });
  test('renders both NACSA-2030 and CNSA-2.0 policy chips', async ({ page }) => { ... });
  test('upgraded Machines stat card shows red/yellow/green counts', async ({ page }) => { ... });
  test('top priority blockers strip appears above machines table', async ({ page }) => { ... });
});
```

**Note:** E2E tests assert structural presence, not data correctness. Data correctness is covered by the Go integration tests.

### Test fixtures

One new helper in `pkg/analytics/testutil_test.go`:

```go
func scanResultAt(hostname string, ts time.Time, safe, trans, dep, unsafe int) *model.ScanResult
```

Used by the trend and machine-health unit tests. Pure helper, no DB.

### Coverage target

- `pkg/analytics/` — >95% (pure math)
- `pkg/server/handlers_analytics.go` — >90% (thin orchestration)
- Store methods — follow existing project coverage patterns

---

## 9. Operational concerns

### Per-request cost budget

| Operation | Cost |
|-----------|------|
| `GetOrg(orgID)` | 1 indexed SELECT, microseconds |
| `ListScansOrderedByTime(orgID)` | 1 indexed SELECT on `(org_id, timestamp)`, typically <10ms for realistic orgs |
| Decrypt + unmarshal N scan blobs | ~1ms per scan (see Phase 1 measurements) — dominant cost for trend computation |
| `ComputeOrgTrend` + `ComputeProjection` + `ComputeMachineHealth` | pure Go, microseconds |
| `ListTopPriorityFindings(orgID, 5)` | 1 indexed SELECT using Phase 1 partial index, <5ms |
| 2× `policy.LoadBuiltin` + `Evaluate` | ~1ms each, in-process |
| **Total per request** | **~(N × 1ms) + ~20ms baseline** where N = number of scans in history |

For an org with 100 scans, ~120ms per request. Fine for interactive dashboard use. If it ever becomes a concern, add a per-org 30-second TTL cache in Phase 2.5.

### Security

- Tenant isolation enforced by `RequireTenant` middleware and `WHERE org_id = $1` in every query — same pattern as Phase 1.
- Per-org config in the DB is protected by tenant-scoped queries — one org cannot read or write another org's `executive_target_percent`.
- No new user-facing inputs (no forms, no admin UI in Phase 2) — zero new XSS / CSRF attack surface.
- Migration v9 adds columns with non-null `DEFAULT` — no NULL handling required in Go.

### Observability

- Existing Prometheus metrics are sufficient.
- No new metrics in Phase 2. If operators want to track exec summary computation time, add a histogram in Phase 2.5.

### Rollback plan

Migration v9 is purely additive (two `ADD COLUMN IF NOT EXISTS` statements). Rollback:

```sql
ALTER TABLE organizations DROP COLUMN IF EXISTS executive_target_percent;
ALTER TABLE organizations DROP COLUMN IF EXISTS executive_deadline_year;
```

Redeploy a pre-v9 binary. The report server works without analytics Phase 2 until v9 is re-applied. No data loss — these columns hold display preferences only.

---

## 10. Commit plan

Four commits on a new branch `feat/analytics-phase-2` off `main`:

### Commit 1 — `pkg/analytics` package + unit tests

- `pkg/analytics/analytics.go` — package doc
- `pkg/analytics/trend.go` + `trend_test.go` — ComputeOrgTrend + tests
- `pkg/analytics/projection.go` + `projection_test.go` — ComputeProjection + tests
- `pkg/analytics/machine_health.go` + `machine_health_test.go` — ComputeMachineHealth + tests
- `pkg/analytics/testutil_test.go` — shared scanResultAt helper
- Pure-Go, no DB, no HTTP. Self-contained and independently testable.

### Commit 2 — Schema migration + store changes

- `pkg/store/migrations.go` — migration v9 (2 ALTER TABLE)
- `pkg/store/types.go` — extend `Organization` struct with 2 new fields, add `ExecutiveSummary` + related response types
- `pkg/store/identity_postgres.go` — extend `GetOrg` to select the new columns
- `pkg/store/findings.go` — append `ListScansOrderedByTime`
- `pkg/store/store.go` — add `ListScansOrderedByTime` to the Store interface
- `pkg/store/identity_test.go` — append organization tests
- `pkg/store/findings_test.go` — append ListScansOrderedByTime tests

### Commit 3 — Handler + route

- `pkg/server/handlers_analytics.go` — append `handleExecutiveSummary`
- `pkg/server/server.go` — register `GET /api/v1/executive` route
- `pkg/server/handlers_analytics_test.go` — append handler integration tests

### Commit 4 — UI + docs + commit group wrap

- `pkg/server/ui/dist/app.js` — extend `renderOverview`, add 4 helpers
- `pkg/server/ui/dist/style.css` — add exec-summary-bar, machine-tiers, top-blockers-strip styles
- `test/e2e/analytics.spec.js` — append exec summary E2E tests
- `docs/DEPLOYMENT_GUIDE.md` — new §14 "Executive Summary" explaining per-org settings + SQL override
- `docs/SYSTEM_ARCHITECTURE.md` — paragraph on `pkg/analytics` package
- `MEMORY.md` — Phase 2 completion marker

Each commit passes `make fmt + go vet + golangci-lint + unit + integration -p 1` before moving to the next. Follows the same green-per-commit discipline as Phase 1.

---

## 11. Open questions

None at spec-write time. All 14 decisions in §2 are locked in. If implementation surfaces a surprise (e.g., policy evaluation turns out to be slower than expected, or `DISTINCT ON` for scans doesn't play nicely with the existing indexes), revisit this spec and append to §2 rather than change code silently.

---

## 12. References

- **Parent roadmap:** `docs/plans/2026-04-09-analytics-phases.md`
- **Phase 1 spec:** `docs/plans/2026-04-09-analytics-phase-1-design.md`
- **Phase 1 plan:** `docs/plans/2026-04-09-analytics-phase-1-plan.md` (with Appendix A corrections)
- **Phase 1 PR #13:** merged 2026-04-09 as commit `3f36ee1`
- **Phase 1 polish PR #14:** merged 2026-04-09 as commit `6d5c6df`
- **Existing trend code:** `pkg/diff/trend.go`
- **Existing policy engine:** `pkg/policy/builtin.go`, `pkg/policy/engine.go`
- **Key source files Phase 2 touches:**
  - New: `pkg/analytics/{analytics,trend,projection,machine_health}.go` + tests
  - Modified: `pkg/store/{migrations,types,store,findings,identity_postgres}.go`
  - Modified: `pkg/server/{server,handlers_analytics}.go`
  - Modified: `pkg/server/ui/dist/{app.js,style.css}`
  - New: `test/e2e/analytics.spec.js` test blocks
  - Modified: `docs/{DEPLOYMENT_GUIDE,SYSTEM_ARCHITECTURE}.md`
