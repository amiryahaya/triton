# Analytics Phase 4A: Systems & Trends with ETL Pipeline — Design Spec

**Date:** 2026-04-13
**Branch:** `feat/analytics-phase-4a`
**Status:** Approved (CEO review)
**Depends on:** Phase 1-3 (shipped/implemented), findings table (schema v7)

## Problem

With 2M+ findings per 2 scans, the current analytics queries (direct SQL aggregation on the findings table) will timeout at scale. Management needs per-system visibility ("which machine to tackle first") and trend charts ("are we on track for 2030") but the data layer can't deliver these at production volumes.

Additionally, the UI monolith (`app.js`, 1388 lines) needs splitting before adding more views.

## Decisions (from CEO review)

| Decision | Choice | Rationale |
|---|---|---|
| UI framework | Vanilla JS + Chart.js | Consistent with existing, no new toolchain |
| First phase | 4A: Systems & Trends | Directly answers "which system to tackle first" |
| Drill-through | Yes, click hostname to filter | Makes dashboard actionable, not just informational |
| Performance strategy | 3-stage ETL pipeline | Handles 50M+ rows; summary tables are < 50 rows per org |
| Pipeline execution | Background worker with queue | Decoupled from scan submission; staleness visible to user |
| Pipeline timing | Built in Phase 4A | Sets foundation for all future phases |
| UI split | Yes, per-view modules | Done in this phase before monolith grows further |

## Architecture: 3-Stage ETL Pipeline

### Stage Overview

```
STAGE 0              STAGE 1              STAGE 2              STAGE 3
RAW                  PROCESSED            AGGREGATED           PRESENTATION
(source of truth)    (clean, enriched)    (chart-ready)        (report-ready)

┌──────────┐        ┌──────────────┐     ┌───────────────┐    ┌──────────────┐
│ scans    │        │ findings     │     │ host_summary  │    │ org_snapshot  │
│          │──T1───▶│              │──T2─▶│               │─T3─▶│              │
│ result_  │        │ (denormalized│     │ (per-host     │    │ (org-wide    │
│ json     │        │  plaintext)  │     │  aggregates)  │    │  readiness,  │
│ (AES-GCM)│        │              │     │               │    │  trend,      │
└──────────┘        │ EXISTS (v7)  │     │ NEW           │    │  policy,     │
                    └──────────────┘     └───────────────┘    │  projection) │
                                                              │ NEW          │
                                                              └──────────────┘

T1 = Extract (existing backfill)    Trigger: scan arrival
T2 = Aggregate per hostname         Trigger: T1 completes
T3 = Compose org-wide rollup        Trigger: T2 completes
```

### Pipeline Execution: Background Worker

```
SCAN SUBMISSION PATH (fast, unchanged):

  Agent POST /api/v1/scans
       │
       ├──▶ INSERT INTO scans (existing)
       ├──▶ INSERT INTO findings (T1, existing)
       ├──▶ ENQUEUE pipeline job: {org_id, hostname, scan_id}
       └──▶ Return 201 Created

  Latency: same as today (~100-200ms). No T2/T3 in the request path.


BACKGROUND PIPELINE WORKER:

  ┌──────────────────────────────────────────────────────────────┐
  │  Pipeline Worker (goroutine, started with server)             │
  │                                                               │
  │  ┌──────────┐    ┌─────────┐    ┌─────────┐    ┌──────────┐ │
  │  │  Queue    │───▶│   T2    │───▶│   T3    │───▶│  Cache   │ │
  │  │ (buffered │    │ Refresh │    │ Refresh │    │  Bust    │ │
  │  │  channel) │    │ host_   │    │ org_    │    │  (LRU    │ │
  │  │          │    │ summary │    │ snapshot│    │  inval.) │ │
  │  └──────────┘    └─────────┘    └─────────┘    └──────────┘ │
  │                                                               │
  │  Dedup: if hostname already queued, skip (latest scan wins)  │
  │  Graceful shutdown: close channel, drain remaining jobs      │
  └──────────────────────────────────────────────────────────────┘
```

### Queue Design

```go
type PipelineJob struct {
    OrgID    string
    Hostname string
    ScanID   string
}

type Pipeline struct {
    queue   chan PipelineJob  // buffered, capacity 1000
    store   store.Store
    pending map[string]bool  // key: "orgID/hostname", dedup guard
    mu      sync.Mutex
}
```

**Enqueue behavior:**
- If `pending[org/host]` is true, skip (newer scan supersedes)
- Otherwise set `pending[org/host] = true` and send to channel
- If channel is full, log warning (cold-start rebuilder will catch up)

**Worker loop:**
- Read from channel, clear pending entry, run T2 then T3
- On T2/T3 error: log, increment failure metric, continue to next job
- On channel close: drain remaining jobs, return

**Lifecycle:** Started in `server.New()`, drained in `server.Shutdown()`.

### Cold Start Rebuilder

On server start, check if host_summary or org_snapshot are empty or stale (any findings row newer than its host_summary.refreshed_at). If so, enqueue rebuild jobs for all distinct `(org_id, hostname)` pairs into the same pipeline queue. No special code path — reuses T2+T3.

Dashboard shows "Data as of: rebuilding..." until snapshots exist.

## Database Schema

### Migration: `host_summary` table (Stage 2)

```sql
CREATE TABLE IF NOT EXISTS host_summary (
    org_id                UUID NOT NULL,
    hostname              TEXT NOT NULL,

    -- Latest scan reference
    scan_id               UUID NOT NULL,
    scanned_at            TIMESTAMPTZ NOT NULL,

    -- Counts by PQC status (from latest scan)
    total_findings        INT NOT NULL DEFAULT 0,
    safe_findings         INT NOT NULL DEFAULT 0,
    transitional_findings INT NOT NULL DEFAULT 0,
    deprecated_findings   INT NOT NULL DEFAULT 0,
    unsafe_findings       INT NOT NULL DEFAULT 0,

    -- Derived
    readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,

    -- Certificate urgency
    certs_expiring_30d    INT NOT NULL DEFAULT 0,
    certs_expiring_90d    INT NOT NULL DEFAULT 0,
    certs_expired         INT NOT NULL DEFAULT 0,

    -- Top priority
    max_priority          INT NOT NULL DEFAULT 0,

    -- Trend
    trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
    trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,

    -- Sparkline: last 12 months [{month, pct}, ...]
    sparkline             JSONB NOT NULL DEFAULT '[]',

    -- Refresh tracking
    refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, hostname)
);

CREATE INDEX idx_host_summary_readiness
    ON host_summary(org_id, readiness_pct ASC);
CREATE INDEX idx_host_summary_unsafe
    ON host_summary(org_id, unsafe_findings DESC);
```

### Migration: `org_snapshot` table (Stage 3)

```sql
CREATE TABLE IF NOT EXISTS org_snapshot (
    org_id                UUID PRIMARY KEY,

    -- Org-wide aggregates
    readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
    total_findings        INT NOT NULL DEFAULT 0,
    safe_findings         INT NOT NULL DEFAULT 0,

    -- Machine health tiers
    machines_total        INT NOT NULL DEFAULT 0,
    machines_red          INT NOT NULL DEFAULT 0,
    machines_yellow       INT NOT NULL DEFAULT 0,
    machines_green        INT NOT NULL DEFAULT 0,

    -- Trend
    trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
    trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
    monthly_trend         JSONB NOT NULL DEFAULT '[]',

    -- Projection
    projection_status     TEXT NOT NULL DEFAULT 'insufficient-history',
    projected_year        INT,
    target_pct            NUMERIC(5,2) NOT NULL DEFAULT 80.0,
    deadline_year         INT NOT NULL DEFAULT 2030,

    -- Policy verdicts
    policy_verdicts       JSONB NOT NULL DEFAULT '[]',

    -- Top blockers (top 5 by priority)
    top_blockers          JSONB NOT NULL DEFAULT '[]',

    -- Certificate urgency (org-wide)
    certs_expiring_30d    INT NOT NULL DEFAULT 0,
    certs_expiring_90d    INT NOT NULL DEFAULT 0,
    certs_expired         INT NOT NULL DEFAULT 0,

    -- Refresh tracking
    refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## T2: Refresh Host Summary

Triggered per `(org_id, hostname)` when a new scan's findings are inserted.

**Algorithm:**
1. Query `findings` for this org+hostname from the latest scan:
   - `SELECT pqc_status, COUNT(*) FROM findings WHERE org_id=$1 AND hostname=$2 AND scan_id = (SELECT id FROM scans WHERE hostname=$2 ORDER BY created_at DESC LIMIT 1) GROUP BY pqc_status`
2. Count expiring certs: `WHERE not_after IS NOT NULL AND not_after < NOW() + interval '30 days'` (and 90 days, and expired)
3. Get max priority: `SELECT MAX(migration_priority)`
4. Build sparkline: query `findings` joined with `scans` on `scan_id`, grouped by `date_trunc('month', scans.created_at)` for the last 12 months, keeping latest scan per month, compute readiness % per month
5. Compute trend direction from sparkline points (reuse `pkg/analytics` math)
6. `UPSERT INTO host_summary` with all computed values

**Cost:** ~50ms per hostname (single scan's findings, indexed).

## T3: Refresh Org Snapshot

Triggered after T2 completes for any host in the org.

**Algorithm:**
1. `SELECT * FROM host_summary WHERE org_id = $1` (all hosts)
2. Aggregate: `SUM(total_findings)`, `SUM(safe_findings)`, compute readiness %
3. Machine tiers: count hosts where `unsafe_findings > 0` (red), `deprecated_findings > 0 AND unsafe = 0` (yellow), else green
4. Monthly trend: aggregate sparkline points across all hosts by month
5. Projection: reuse `pkg/analytics.ComputeProjection()` with org config (target %, deadline year)
6. Policy verdicts: evaluate NACSA-2030 + CNSA-2.0 against latest findings (reuse existing `computePolicyVerdicts`)
7. Top blockers: `SELECT ... FROM findings WHERE org_id=$1 ORDER BY migration_priority DESC LIMIT 5` (from latest scans)
8. Certificate rollup: `SUM(certs_expiring_30d)`, etc. from host_summary
9. `UPSERT INTO org_snapshot`

**Cost:** ~30ms (reads from host_summary, not findings).

## API Endpoints

### New endpoints

```
GET /api/v1/systems?pqc_status=X
    Reads: host_summary
    Returns: [{hostname, readinessPct, totalFindings, safeFindings,
              unsafeFindings, deprecatedFindings, trendDirection,
              trendDeltaPct, sparkline, lastScannedAt, refreshedAt}]
    Sort: readiness_pct ASC (worst first)

GET /api/v1/trends?hostname=X
    Reads: org_snapshot (org-wide) or host_summary (per-host)
    Returns: {monthlyPoints: [{month, readinessPct, totalFindings}],
             direction, deltaPct}

GET /api/v1/pipeline/status
    Returns: {status: "idle"|"processing", queueDepth, lastProcessedAt,
             jobsProcessedTotal, jobsFailedTotal}
```

### Modified endpoints

All existing analytics endpoints gain a `dataAsOf` field in the response:

```json
{
  "data": [...],
  "dataAsOf": "2026-04-13T14:32:00Z",
  "pipelineLag": 45
}
```

`GET /api/v1/executive` now reads from `org_snapshot` instead of computing from scratch. Falls back to direct computation if org_snapshot is empty (cold start).

## Staleness Transparency

Every analytics API response includes:
- `dataAsOf` (ISO 8601) — the `refreshed_at` timestamp from the summary/snapshot table
- `pipelineLag` (seconds) — `NOW() - refreshed_at`, how stale the data is

The UI renders a persistent header bar on all analytics views:

```
┌────────────────────────────────────────────────────────────────┐
│ Data as of: 13 Apr 2026, 2:32 PM  ·  Pipeline: idle           │  (normal)
│ ⟳ Processing new scan data...      ·  Pipeline: 3 jobs queued  │  (active)
└────────────────────────────────────────────────────────────────┘
```

The UI polls `GET /api/v1/pipeline/status` every 10 seconds when the pipeline is active, stops polling when idle.

## New UI Views

### Systems Health (`#/systems`)

```
┌──────────────────────────────────────────────────────────────┐
│  Systems Health                                    [Filter ▼] │
│                                                               │
│  Summary: 50 systems  🟢 31  🟡 15  🔴 4                    │
│                                                               │
│  ┌──────────┬────────┬──────┬────────────┬──────────────────┐│
│  │ hostname │ ready% │trend │ sparkline  │ last scanned     ││
│  │──────────│────────│──────│────────────│──────────────────││
│  │ legacy-1 │  12%   │  ↓  │ ▇▅▃▁      │ 12 Apr, 9:00 AM  ││  ← click drills
│  │ web-srv1 │  45%   │  ↑  │ ▁▃▅       │ 13 Apr, 2:30 PM  ││     to inventory
│  │ db-main  │  78%   │  ↑  │ ▃▅▇       │ 13 Apr, 1:15 PM  ││     for that host
│  │ k8s-prod │  91%   │  →  │ ▇▇▇       │ 13 Apr, 2:32 PM  ││
│  └──────────┴────────┴──────┴────────────┴──────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

- Default sort: readiness % ascending (worst first)
- Sparklines: Chart.js tiny line charts in table cells (no axes, just shape)
- Click hostname: navigate to `#/inventory?hostname=<host>` (Phase 3 filter)
- Filter: PQC status dropdown (shows only hosts with findings of that status)
- Data source: `GET /api/v1/systems`

### Migration Trends (`#/trends`)

```
┌──────────────────────────────────────────────────────────────┐
│  Migration Trend                                              │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐│
│  │  100% ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ target (80%)  ││
│  │   80% ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─/─ ─ ─ ─ ─ ─ ─  ││
│  │   60% ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─/─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ││
│  │   40% ─ ─ ─ ─ ─ ─ ─ ─ ─/─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ││
│  │   20% ─ ─ ─ ─ ─/─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ││
│  │    0% ─/─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ││
│  │       Jan  Feb  Mar  Apr  May  Jun  Jul  Aug  Sep  Oct  ││
│  └──────────────────────────────────────────────────────────┘│
│                                                               │
│  Monthly Delta                                                │
│  ┌────────┬────────┬──────┬───────┐                          │
│  │ Month  │ Ready% │   Δ  │ Dir.  │                          │
│  │ 2026-01│  52%   │  +3% │  ↑   │                          │
│  │ 2026-02│  58%   │  +6% │  ↑   │                          │
│  │ 2026-03│  55%   │  -3% │  ↓   │                          │
│  │ 2026-04│  61%   │  +6% │  ↑   │                          │
│  └────────┴────────┴──────┴───────┘                          │
└──────────────────────────────────────────────────────────────┘
```

- Chart.js line chart: readiness % over time
- Dashed horizontal line: target % (from org config, default 80%)
- Monthly delta table below the chart
- Data source: `GET /api/v1/trends` (reads from org_snapshot.monthly_trend)

## UI Module Split

Split `pkg/server/ui/dist/app.js` into per-view modules:

```
pkg/server/ui/dist/
├── app.js              (router, shared helpers, ~300 lines)
├── views/
│   ├── overview.js     (dashboard + executive summary)
│   ├── scans.js        (scan list + detail)
│   ├── machines.js     (machine list + detail)
│   ├── inventory.js    (crypto inventory)
│   ├── certificates.js (expiring certs)
│   ├── priority.js     (migration priority)
│   ├── systems.js      (NEW: systems health)
│   └── trends.js       (NEW: migration trends)
└── components/
    ├── filters.js      (shared filter bar)
    ├── sparkline.js    (Chart.js sparkline helper)
    └── staleness.js    (data-as-of bar + pipeline poll)
```

All loaded via `<script>` tags in `index.html` (no bundler). Each view registers itself with the router in `app.js`.

## Observability

### New metrics

```
triton_pipeline_jobs_processed_total     counter   Jobs completed by stage (label: stage=t2|t3)
triton_pipeline_jobs_failed_total        counter   Jobs failed by stage
triton_pipeline_queue_depth              gauge     Current queue depth
triton_pipeline_job_duration_seconds     histogram T2+T3 duration per job
triton_pipeline_last_processed_timestamp gauge     Unix timestamp of last completed job
triton_summary_staleness_seconds         gauge     Age of oldest host_summary row per org
```

### Pipeline status endpoint

`GET /api/v1/pipeline/status` returns queue depth, processing state, and counters. Used by the UI staleness bar and operational monitoring.

## What Each Dashboard View Reads

| View | Reads from | Query cost | Scales to |
|---|---|---|---|
| Executive summary (`#/`) | org_snapshot | < 1ms | Unlimited |
| Systems (`#/systems`) | host_summary | < 5ms | Unlimited |
| Trends (`#/trends`) | org_snapshot.monthly_trend | < 1ms | Unlimited |
| Inventory (`#/inventory`) | findings (Stage 1) | ~200ms | Indexed |
| Certificates (`#/certificates`) | findings (Stage 1) | ~100ms | Indexed |
| Priority (`#/priority`) | findings (Stage 1) | ~50ms | Indexed |
| Drill-through (click host) | findings WHERE hostname=X | ~100ms | Filtered |

## Recovery & Rollback

**Drop Stage 3 only:**
```sql
TRUNCATE org_snapshot;
-- Restart server → cold-start rebuilder recomputes from host_summary
```

**Drop Stage 2+3:**
```sql
TRUNCATE host_summary; TRUNCATE org_snapshot;
-- Restart server → rebuilder recomputes from findings (minutes)
```

**Drop Stage 1+2+3 (full rebuild):**
```sql
TRUNCATE findings; UPDATE scans SET findings_extracted_at = NULL;
TRUNCATE host_summary; TRUNCATE org_snapshot;
-- Restart server → backfill from encrypted blobs (existing, 30-min cap)
```

Each stage rebuilds from the stage below. Source of truth is always Stage 0 (encrypted scans).

## Component Changes

| File | Action | Responsibility |
|---|---|---|
| `pkg/store/migrations.go` | Modify | Add host_summary + org_snapshot table DDL |
| `pkg/store/pipeline.go` | Create | Pipeline struct, queue, worker, T2+T3 logic |
| `pkg/store/pipeline_test.go` | Create | Pipeline unit + integration tests |
| `pkg/store/host_summary.go` | Create | T2 refresh logic, host_summary queries |
| `pkg/store/org_snapshot.go` | Create | T3 refresh logic, org_snapshot queries |
| `pkg/store/store.go` | Modify | Add pipeline/summary methods to Store interface |
| `pkg/store/types.go` | Modify | Add HostSummary, OrgSnapshot types |
| `pkg/server/handlers_analytics.go` | Modify | Add handleSystems, handleTrends, handlePipelineStatus; modify existing handlers for dataAsOf |
| `pkg/server/server.go` | Modify | Wire new routes, start/stop pipeline |
| `pkg/server/ui/dist/app.js` | Modify | Split into modules, add router registration |
| `pkg/server/ui/dist/views/systems.js` | Create | Systems health view |
| `pkg/server/ui/dist/views/trends.js` | Create | Trends chart view |
| `pkg/server/ui/dist/components/staleness.js` | Create | Data-as-of bar + pipeline poll |
| `pkg/server/ui/dist/components/sparkline.js` | Create | Chart.js sparkline helper |
| `pkg/server/ui/dist/index.html` | Modify | Add script tags for new modules |
| `cmd/server.go` | Modify | Wire pipeline start/shutdown |

## Test Plan

### Unit tests
- `pkg/store/pipeline_test.go`: enqueue dedup, worker processes jobs, graceful shutdown drains queue
- `pkg/store/host_summary_test.go`: T2 computes correct counts, sparkline, trend from findings
- `pkg/store/org_snapshot_test.go`: T3 aggregates across host_summaries correctly

### Integration tests
- Submit scan → pipeline job enqueued → host_summary refreshed → org_snapshot refreshed → API returns fresh data with correct dataAsOf
- Cold start with empty summaries → rebuilder enqueues all hosts → summaries populated
- Two scans for same host in quick succession → dedup, only latest processed

### E2E tests
- Systems view renders table with correct data, sparklines visible
- Trends view renders Chart.js chart with monthly points
- Staleness bar shows "Data as of" timestamp
- Click hostname in Systems → navigates to filtered inventory view

## What Does NOT Change

- Stage 0 (scans table) and Stage 1 (findings table) are untouched
- Existing analytics endpoints continue working (enhanced with dataAsOf)
- Scan submission path latency unchanged (pipeline is background)
- Existing tests unaffected
- No new auth boundaries (all endpoints use existing tenant middleware)

## Future Phases (enabled by this pipeline)

- **4B (Remediation):** finding_status table joins with host_summary at T2; exception count reflected in readiness %
- **5 (Export):** PDF/Excel generation reads org_snapshot + host_summary (< 50ms)
- **6 (Alerting):** Alert evaluator reads org_snapshot after T3; fires webhook/email when thresholds breached
