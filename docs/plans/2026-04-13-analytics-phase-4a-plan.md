# Analytics Phase 4A: Systems & Trends with ETL Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a 3-stage ETL pipeline with background worker that pre-computes per-host and org-wide analytics summaries, plus two new dashboard views (Systems Health, Migration Trends) that read from the pre-computed tables for sub-5ms query performance at any scale.

**Architecture:** Scan submissions enqueue a pipeline job. A background worker goroutine runs T2 (refresh host_summary from findings) then T3 (refresh org_snapshot from host_summary). The Systems and Trends views read from these summary tables. A staleness header ("Data as of") makes pipeline lag visible to users. The existing `app.js` monolith is split into per-view modules.

**Tech Stack:** Go 1.25, pgx/v5, vanilla JS, Chart.js 4.x, testify

**Spec:** `docs/plans/2026-04-13-analytics-phase-4a-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `pkg/store/migrations.go` | Modify | v12: host_summary + org_snapshot DDL |
| `pkg/store/types.go` | Modify | HostSummary, OrgSnapshot, SparklinePoint, PipelineStatus types |
| `pkg/store/store.go` | Modify | Add summary store methods to Store interface |
| `pkg/store/host_summary.go` | Create | T2: RefreshHostSummary, ListHostSummaries, GetHostSummary |
| `pkg/store/org_snapshot.go` | Create | T3: RefreshOrgSnapshot, GetOrgSnapshot |
| `pkg/store/pipeline.go` | Create | Pipeline struct, queue, worker, enqueue, cold-start rebuilder |
| `pkg/store/pipeline_test.go` | Create | Pipeline unit tests (dedup, drain, worker) |
| `pkg/store/host_summary_test.go` | Create | T2 integration tests |
| `pkg/store/org_snapshot_test.go` | Create | T3 integration tests |
| `pkg/server/handlers_analytics.go` | Modify | handleSystems, handleTrends, handlePipelineStatus, dataAsOf wrapper |
| `pkg/server/server.go` | Modify | Pipeline field, start/stop lifecycle, new routes |
| `cmd/server.go` | Modify | Start pipeline after backfill, wire shutdown |
| `pkg/server/ui/dist/app.js` | Modify | Extract to module-based router, slim to ~300 lines |
| `pkg/server/ui/dist/views/*.js` | Create | Per-view modules (overview, scans, machines, inventory, certificates, priority, systems, trends) |
| `pkg/server/ui/dist/components/*.js` | Create | Shared components (filters, sparkline, staleness) |
| `pkg/server/ui/dist/index.html` | Modify | Add `<script>` tags for new modules |
| `pkg/server/ui/dist/style.css` | Modify | Systems table, sparkline cells, staleness bar styles |

---

### Task 1: Database migrations — host_summary + org_snapshot tables

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Add migration v12**

In `pkg/store/migrations.go`, append to the `migrations` slice:

```go
// Version 12: Analytics Stage 2+3 summary tables (Phase 4A ETL pipeline).
// host_summary: per-(org, hostname) aggregates, refreshed by pipeline T2.
// org_snapshot: per-org rollup, refreshed by pipeline T3.
// Both are derived read-models — rebuildable from the findings table.
`CREATE TABLE IF NOT EXISTS host_summary (
    org_id                UUID NOT NULL,
    hostname              TEXT NOT NULL,
    scan_id               UUID NOT NULL,
    scanned_at            TIMESTAMPTZ NOT NULL,
    total_findings        INT NOT NULL DEFAULT 0,
    safe_findings         INT NOT NULL DEFAULT 0,
    transitional_findings INT NOT NULL DEFAULT 0,
    deprecated_findings   INT NOT NULL DEFAULT 0,
    unsafe_findings       INT NOT NULL DEFAULT 0,
    readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
    certs_expiring_30d    INT NOT NULL DEFAULT 0,
    certs_expiring_90d    INT NOT NULL DEFAULT 0,
    certs_expired         INT NOT NULL DEFAULT 0,
    max_priority          INT NOT NULL DEFAULT 0,
    trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
    trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
    sparkline             JSONB NOT NULL DEFAULT '[]',
    refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_host_summary_readiness
    ON host_summary(org_id, readiness_pct ASC);
CREATE INDEX IF NOT EXISTS idx_host_summary_unsafe
    ON host_summary(org_id, unsafe_findings DESC);

CREATE TABLE IF NOT EXISTS org_snapshot (
    org_id                UUID PRIMARY KEY,
    readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
    total_findings        INT NOT NULL DEFAULT 0,
    safe_findings         INT NOT NULL DEFAULT 0,
    machines_total        INT NOT NULL DEFAULT 0,
    machines_red          INT NOT NULL DEFAULT 0,
    machines_yellow       INT NOT NULL DEFAULT 0,
    machines_green        INT NOT NULL DEFAULT 0,
    trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
    trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
    monthly_trend         JSONB NOT NULL DEFAULT '[]',
    projection_status     TEXT NOT NULL DEFAULT 'insufficient-history',
    projected_year        INT,
    target_pct            NUMERIC(5,2) NOT NULL DEFAULT 80.0,
    deadline_year         INT NOT NULL DEFAULT 2030,
    policy_verdicts       JSONB NOT NULL DEFAULT '[]',
    top_blockers          JSONB NOT NULL DEFAULT '[]',
    certs_expiring_30d    INT NOT NULL DEFAULT 0,
    certs_expiring_90d    INT NOT NULL DEFAULT 0,
    certs_expired         INT NOT NULL DEFAULT 0,
    refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`,
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/store/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/store/migrations.go
git commit -m "feat(store): add host_summary + org_snapshot tables (migration v12)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Types — HostSummary, OrgSnapshot, SparklinePoint, PipelineStatus

**Files:**
- Modify: `pkg/store/types.go`

- [ ] **Step 1: Add new types**

Append to `pkg/store/types.go`:

```go
// SparklinePoint is one month's readiness snapshot for sparkline charts.
type SparklinePoint struct {
	Month     string  `json:"month"`     // "2026-04" (YYYY-MM)
	Readiness float64 `json:"readiness"` // 0-100
}

// HostSummary is a pre-computed per-(org, hostname) aggregate.
// Refreshed by pipeline T2 when new findings arrive for a hostname.
// Analytics Phase 4A.
type HostSummary struct {
	OrgID                 string           `json:"orgId"`
	Hostname              string           `json:"hostname"`
	ScanID                string           `json:"scanId"`
	ScannedAt             time.Time        `json:"scannedAt"`
	TotalFindings         int              `json:"totalFindings"`
	SafeFindings          int              `json:"safeFindings"`
	TransitionalFindings  int              `json:"transitionalFindings"`
	DeprecatedFindings    int              `json:"deprecatedFindings"`
	UnsafeFindings        int              `json:"unsafeFindings"`
	ReadinessPct          float64          `json:"readinessPct"`
	CertsExpiring30d      int              `json:"certsExpiring30d"`
	CertsExpiring90d      int              `json:"certsExpiring90d"`
	CertsExpired          int              `json:"certsExpired"`
	MaxPriority           int              `json:"maxPriority"`
	TrendDirection        string           `json:"trendDirection"`
	TrendDeltaPct         float64          `json:"trendDeltaPct"`
	Sparkline             []SparklinePoint `json:"sparkline"`
	RefreshedAt           time.Time        `json:"refreshedAt"`
}

// OrgSnapshot is a pre-computed org-wide rollup of all host summaries.
// Refreshed by pipeline T3 after any host summary changes.
// Analytics Phase 4A.
type OrgSnapshot struct {
	OrgID             string                 `json:"orgId"`
	ReadinessPct      float64                `json:"readinessPct"`
	TotalFindings     int                    `json:"totalFindings"`
	SafeFindings      int                    `json:"safeFindings"`
	MachinesTotal     int                    `json:"machinesTotal"`
	MachinesRed       int                    `json:"machinesRed"`
	MachinesYellow    int                    `json:"machinesYellow"`
	MachinesGreen     int                    `json:"machinesGreen"`
	TrendDirection    string                 `json:"trendDirection"`
	TrendDeltaPct     float64                `json:"trendDeltaPct"`
	MonthlyTrend      []SparklinePoint       `json:"monthlyTrend"`
	ProjectionStatus  string                 `json:"projectionStatus"`
	ProjectedYear     int                    `json:"projectedYear,omitempty"`
	TargetPct         float64                `json:"targetPct"`
	DeadlineYear      int                    `json:"deadlineYear"`
	PolicyVerdicts    []PolicyVerdictSummary `json:"policyVerdicts"`
	TopBlockers       []PriorityRow          `json:"topBlockers"`
	CertsExpiring30d  int                    `json:"certsExpiring30d"`
	CertsExpiring90d  int                    `json:"certsExpiring90d"`
	CertsExpired      int                    `json:"certsExpired"`
	RefreshedAt       time.Time              `json:"refreshedAt"`
}

// PipelineStatus is the response for GET /api/v1/pipeline/status.
// Analytics Phase 4A.
type PipelineStatus struct {
	Status             string    `json:"status"`             // "idle" | "processing"
	QueueDepth         int       `json:"queueDepth"`
	LastProcessedAt    time.Time `json:"lastProcessedAt"`
	JobsProcessedTotal int64     `json:"jobsProcessedTotal"`
	JobsFailedTotal    int64     `json:"jobsFailedTotal"`
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/store/...`

- [ ] **Step 3: Commit**

```bash
git add pkg/store/types.go
git commit -m "feat(store): add HostSummary, OrgSnapshot, PipelineStatus types

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Store interface — add summary methods

**Files:**
- Modify: `pkg/store/store.go`

- [ ] **Step 1: Add methods to the Store interface**

Add to the `Store` interface in `pkg/store/store.go`, after the `ListFilterOptions` method:

```go
// --- Analytics Pipeline (Phase 4A) ---

// RefreshHostSummary recomputes the host_summary row for a single
// (org, hostname) pair from the findings table. Called by pipeline T2.
RefreshHostSummary(ctx context.Context, orgID, hostname string) error

// RefreshOrgSnapshot recomputes the org_snapshot row for an org
// from all host_summary rows. Called by pipeline T3.
RefreshOrgSnapshot(ctx context.Context, orgID string) error

// ListHostSummaries returns all host_summary rows for the given org,
// sorted by readiness_pct ASC (worst first). Optionally filtered by
// PQC status (e.g., "UNSAFE" returns only hosts with unsafe > 0).
ListHostSummaries(ctx context.Context, orgID string, pqcStatusFilter string) ([]HostSummary, error)

// GetOrgSnapshot returns the pre-computed org snapshot, or nil if
// the pipeline hasn't run yet for this org.
GetOrgSnapshot(ctx context.Context, orgID string) (*OrgSnapshot, error)

// ListStaleHosts returns distinct (org_id, hostname) pairs from the
// findings table that have no host_summary row or whose host_summary
// is older than the latest finding. Used by the cold-start rebuilder.
ListStaleHosts(ctx context.Context) ([]PipelineJob, error)
```

Also add the `PipelineJob` type (used by `ListStaleHosts` and the pipeline queue):

```go
// PipelineJob identifies a unit of work for the analytics pipeline.
type PipelineJob struct {
	OrgID    string
	Hostname string
	ScanID   string // may be empty for cold-start rebuild jobs
}
```

- [ ] **Step 2: Add stubs to PostgresStore**

Create stub methods in `pkg/store/host_summary.go` and `pkg/store/org_snapshot.go` that return "not implemented" errors. This satisfies the interface so the project compiles while we implement them in subsequent tasks.

`pkg/store/host_summary.go`:
```go
package store

import (
	"context"
	"fmt"
)

func (s *PostgresStore) RefreshHostSummary(ctx context.Context, orgID, hostname string) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListHostSummaries(ctx context.Context, orgID string, pqcStatusFilter string) ([]HostSummary, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListStaleHosts(ctx context.Context) ([]PipelineJob, error) {
	return nil, fmt.Errorf("not implemented")
}
```

`pkg/store/org_snapshot.go`:
```go
package store

import (
	"context"
	"fmt"
)

func (s *PostgresStore) RefreshOrgSnapshot(ctx context.Context, orgID string) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetOrgSnapshot(ctx context.Context, orgID string) (*OrgSnapshot, error) {
	return nil, fmt.Errorf("not implemented")
}
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./...`

- [ ] **Step 4: Commit**

```bash
git add pkg/store/store.go pkg/store/host_summary.go pkg/store/org_snapshot.go
git commit -m "feat(store): add analytics pipeline methods to Store interface (stubs)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Implement T2 — RefreshHostSummary

**Files:**
- Modify: `pkg/store/host_summary.go`
- Create: `pkg/store/host_summary_test.go`

- [ ] **Step 1: Write integration test**

Create `pkg/store/host_summary_test.go` with `//go:build integration` tag. Test that after inserting findings for a host and calling `RefreshHostSummary`, the host_summary row has correct counts, readiness %, and sparkline. Use the existing `openTestStore` helper pattern from the project.

Key test cases:
- `TestRefreshHostSummary_BasicCounts` — insert findings with mixed PQC statuses, verify counts and readiness %
- `TestRefreshHostSummary_CertExpiry` — insert findings with not_after dates, verify cert urgency counts
- `TestRefreshHostSummary_Sparkline` — insert findings across multiple months, verify sparkline JSONB
- `TestListHostSummaries_SortedByReadiness` — verify worst-first ordering
- `TestListHostSummaries_FilterByPQCStatus` — verify UNSAFE filter returns only hosts with unsafe findings

- [ ] **Step 2: Implement RefreshHostSummary**

Replace the stub in `pkg/store/host_summary.go`. The method should:

1. Find the latest scan_id for this hostname from the scans table
2. Count findings by pqc_status from that scan's findings
3. Count expiring certs (30d, 90d, expired) from that scan's findings
4. Get max migration_priority from that scan's findings
5. Compute readiness: `safe / total * 100` (guard against division by zero → 0.0)
6. Build sparkline: query findings joined with scans, group by `date_trunc('month', s.created_at)`, keep latest scan per month per host, compute readiness per month, limit 12 months
7. Compute trend direction from sparkline (reuse `pkg/analytics.ComputeOrgTrend` logic or inline the simple version: compare last two points)
8. UPSERT into host_summary

All in a single transaction for consistency.

- [ ] **Step 3: Implement ListHostSummaries**

Simple SELECT from host_summary with optional WHERE clause for pqc_status filtering:
- `pqcStatusFilter == "UNSAFE"` → `WHERE unsafe_findings > 0`
- `pqcStatusFilter == "DEPRECATED"` → `WHERE deprecated_findings > 0`
- `pqcStatusFilter == "TRANSITIONAL"` → `WHERE transitional_findings > 0`
- `pqcStatusFilter == "SAFE"` → `WHERE unsafe_findings = 0 AND deprecated_findings = 0`
- empty → no filter

ORDER BY `readiness_pct ASC, hostname ASC`.

Parse the sparkline JSONB column into `[]SparklinePoint`.

- [ ] **Step 4: Implement ListStaleHosts**

Query: find all distinct (org_id, hostname) from findings that either have no host_summary row, or whose latest finding's scan has a newer timestamp than host_summary.refreshed_at.

```sql
SELECT DISTINCT f.org_id, f.hostname
FROM findings f
LEFT JOIN host_summary hs ON f.org_id = hs.org_id AND f.hostname = hs.hostname
WHERE hs.org_id IS NULL
   OR hs.refreshed_at < (
       SELECT MAX(s.timestamp)
       FROM scans s
       WHERE s.id = f.scan_id
   )
```

- [ ] **Step 5: Run tests** (if PostgreSQL available)

Run: `go test -v -tags integration -run 'TestRefreshHostSummary|TestListHostSummaries' ./pkg/store/`

- [ ] **Step 6: Verify compilation**

Run: `go build ./...`

- [ ] **Step 7: Commit**

```bash
git add pkg/store/host_summary.go pkg/store/host_summary_test.go
git commit -m "feat(store): implement T2 RefreshHostSummary + ListHostSummaries

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Implement T3 — RefreshOrgSnapshot

**Files:**
- Modify: `pkg/store/org_snapshot.go`
- Create: `pkg/store/org_snapshot_test.go`

- [ ] **Step 1: Write integration test**

Create `pkg/store/org_snapshot_test.go` with `//go:build integration`. Key test cases:
- `TestRefreshOrgSnapshot_Aggregates` — multiple host_summary rows, verify org-wide totals and readiness
- `TestRefreshOrgSnapshot_MachineTiers` — hosts with various PQC status mixes, verify red/yellow/green counts
- `TestRefreshOrgSnapshot_MonthlyTrend` — verify sparkline aggregation across hosts

- [ ] **Step 2: Implement RefreshOrgSnapshot**

Replace the stub. The method should:

1. `SELECT * FROM host_summary WHERE org_id = $1`
2. Aggregate: sum total/safe/transitional/deprecated/unsafe across all hosts
3. Compute org readiness: `SUM(safe) / SUM(total) * 100`
4. Machine tiers: red (unsafe > 0), yellow (deprecated > 0 and unsafe = 0), green (else)
5. Monthly trend: merge sparkline arrays from all hosts by month, compute combined readiness per month
6. Compute trend direction from monthly trend points (compare last two)
7. Get org config (target_pct, deadline_year) from organizations table (with defaults 80.0 / 2030)
8. Projection: reuse `pkg/analytics.ComputeProjection` with trend data
9. Top 5 blockers: `SELECT ... FROM findings WHERE org_id=$1 ORDER BY migration_priority DESC LIMIT 5` filtered to latest scan per host (reuse the CTE from existing ListTopPriorityFindings)
10. Certificate rollup: sum cert counts from host_summary rows
11. Policy verdicts: evaluate NACSA-2030 + CNSA-2.0 (reuse existing `computePolicyVerdicts` logic from `handlers_analytics.go`, or call the existing handler helper)
12. UPSERT into org_snapshot

- [ ] **Step 3: Implement GetOrgSnapshot**

Simple SELECT from org_snapshot by org_id. Parse JSONB columns (monthly_trend, policy_verdicts, top_blockers). Return nil if no row.

- [ ] **Step 4: Run tests** (if PostgreSQL available)

Run: `go test -v -tags integration -run 'TestRefreshOrgSnapshot|TestGetOrgSnapshot' ./pkg/store/`

- [ ] **Step 5: Commit**

```bash
git add pkg/store/org_snapshot.go pkg/store/org_snapshot_test.go
git commit -m "feat(store): implement T3 RefreshOrgSnapshot + GetOrgSnapshot

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Pipeline — background worker with dedup queue

**Files:**
- Create: `pkg/store/pipeline.go`
- Create: `pkg/store/pipeline_test.go`

- [ ] **Step 1: Write unit tests**

Create `pkg/store/pipeline_test.go` (no build tag — these are unit tests using mocks). Key test cases:
- `TestPipeline_EnqueueDedup` — enqueue same org/host twice, verify only one job processed
- `TestPipeline_GracefulShutdown` — close pipeline, verify queued jobs are drained before return
- `TestPipeline_WorkerProcessesJobs` — enqueue a job, verify T2 and T3 are called
- `TestPipeline_WorkerContinuesOnError` — T2 returns error, verify pipeline continues to next job

- [ ] **Step 2: Implement Pipeline**

Create `pkg/store/pipeline.go`:

```go
package store

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const pipelineQueueCapacity = 1000

// Pipeline runs the T2+T3 analytics transforms in a background goroutine.
type Pipeline struct {
	store   Store
	queue   chan PipelineJob
	pending map[string]bool
	mu      sync.Mutex
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Metrics (atomic for lock-free reads from the status endpoint)
	jobsProcessed atomic.Int64
	jobsFailed    atomic.Int64
	lastProcessed atomic.Value // stores time.Time
}

// NewPipeline creates a pipeline. Call Start() to begin processing.
func NewPipeline(s Store) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		store:   s,
		queue:   make(chan PipelineJob, pipelineQueueCapacity),
		pending: make(map[string]bool),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start launches the background worker goroutine.
func (p *Pipeline) Start() {
	p.wg.Add(1)
	go p.worker()
}

// Stop signals the worker to drain and waits for completion.
func (p *Pipeline) Stop() {
	p.cancel()
	close(p.queue)
	p.wg.Wait()
}

// Enqueue adds a pipeline job. Deduplicates by org+hostname: if a job
// for the same host is already pending, the new one is skipped (the
// worker always processes the latest data from the DB, so the older
// job would produce the same result).
func (p *Pipeline) Enqueue(job PipelineJob) {
	key := job.OrgID + "/" + job.Hostname
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[key] {
		return // dedup
	}
	select {
	case p.queue <- job:
		p.pending[key] = true
	default:
		log.Printf("pipeline: queue full (capacity %d), dropping job for %s/%s — cold-start rebuilder will catch up",
			pipelineQueueCapacity, job.OrgID, job.Hostname)
	}
}

// Status returns the current pipeline state for the status endpoint.
func (p *Pipeline) Status() PipelineStatus {
	status := "idle"
	if len(p.queue) > 0 {
		status = "processing"
	}
	var lastProc time.Time
	if v := p.lastProcessed.Load(); v != nil {
		lastProc = v.(time.Time)
	}
	return PipelineStatus{
		Status:             status,
		QueueDepth:         len(p.queue),
		LastProcessedAt:    lastProc,
		JobsProcessedTotal: p.jobsProcessed.Load(),
		JobsFailedTotal:    p.jobsFailed.Load(),
	}
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for job := range p.queue {
		p.clearPending(job)
		p.processJob(job)
	}
}

func (p *Pipeline) clearPending(job PipelineJob) {
	key := job.OrgID + "/" + job.Hostname
	p.mu.Lock()
	delete(p.pending, key)
	p.mu.Unlock()
}

func (p *Pipeline) processJob(job PipelineJob) {
	ctx := p.ctx
	if ctx.Err() != nil {
		return
	}

	// T2: Refresh host summary
	if err := p.store.RefreshHostSummary(ctx, job.OrgID, job.Hostname); err != nil {
		log.Printf("pipeline T2 error (org=%s host=%s): %v", job.OrgID, job.Hostname, err)
		p.jobsFailed.Add(1)
		return
	}

	// T3: Refresh org snapshot
	if err := p.store.RefreshOrgSnapshot(ctx, job.OrgID); err != nil {
		log.Printf("pipeline T3 error (org=%s): %v", job.OrgID, err)
		p.jobsFailed.Add(1)
		return
	}

	p.jobsProcessed.Add(1)
	p.lastProcessed.Store(time.Now().UTC())
}
```

- [ ] **Step 3: Add cold-start rebuilder**

Add to `pkg/store/pipeline.go`:

```go
// RebuildStale enqueues pipeline jobs for all hosts whose summaries
// are missing or stale. Called on server start after the findings
// backfill completes. Non-blocking — jobs are enqueued and the
// background worker processes them.
func (p *Pipeline) RebuildStale(ctx context.Context) error {
	stale, err := p.store.ListStaleHosts(ctx)
	if err != nil {
		return fmt.Errorf("listing stale hosts: %w", err)
	}
	if len(stale) == 0 {
		return nil
	}
	log.Printf("pipeline: rebuilding summaries for %d stale hosts", len(stale))
	for _, job := range stale {
		p.Enqueue(job)
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run 'TestPipeline' ./pkg/store/`

- [ ] **Step 5: Commit**

```bash
git add pkg/store/pipeline.go pkg/store/pipeline_test.go
git commit -m "feat(store): add analytics Pipeline with background worker + dedup queue

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Wire pipeline into server + scan submission

**Files:**
- Modify: `pkg/server/server.go`
- Modify: `cmd/server.go`
- Modify: `pkg/store/findings.go` (enqueue after SaveScanWithFindings)

- [ ] **Step 1: Add pipeline field to Server struct**

In `pkg/server/server.go`, add to the `Server` struct:

```go
// pipeline runs the T2+T3 analytics transforms in the background.
// Started after the findings backfill completes, stopped in Shutdown.
// Analytics Phase 4A.
pipeline *store.Pipeline
```

- [ ] **Step 2: Initialize pipeline in New()**

In `pkg/server/server.go`'s `New()` function, after the server struct is constructed, create the pipeline:

```go
srv.pipeline = store.NewPipeline(db)
```

- [ ] **Step 3: Expose Pipeline() accessor**

Add to `pkg/server/server.go`:

```go
// Pipeline returns the analytics pipeline for wiring in cmd/server.go.
func (s *Server) Pipeline() *store.Pipeline {
	return s.pipeline
}
```

- [ ] **Step 4: Start pipeline in cmd/server.go**

In `cmd/server.go`, after the backfill goroutine block (after `srv.BackfillWG().Add(1)` ... `go func() { ... }()`), add pipeline start + cold-start rebuild:

```go
// Analytics Phase 4A — start the ETL pipeline worker.
// The cold-start rebuild runs after the backfill completes to avoid
// rebuilding summaries from stale findings data.
srv.Pipeline().Start()
go func() {
	// Wait for backfill to finish before checking for stale summaries
	srv.BackfillWG().Wait()
	if err := srv.Pipeline().RebuildStale(srv.Context()); err != nil {
		log.Printf("pipeline cold-start rebuild: %v", err)
	}
}()
```

- [ ] **Step 5: Stop pipeline in Shutdown**

In `pkg/server/server.go`'s `Shutdown` method, add before the HTTP shutdown:

```go
if s.pipeline != nil {
	s.pipeline.Stop()
}
```

- [ ] **Step 6: Enqueue pipeline job after SaveScanWithFindings**

In `pkg/server/handlers.go` (or wherever `handleSubmitScan` calls `SaveScanWithFindings`), after the save succeeds, enqueue a pipeline job. The server needs to expose the pipeline to the handler. Add a method on Server:

```go
// EnqueuePipelineJob queues a T2+T3 refresh for the given org/hostname.
// No-op if the pipeline is nil (testing without pipeline).
func (s *Server) EnqueuePipelineJob(orgID, hostname, scanID string) {
	if s.pipeline == nil {
		return
	}
	s.pipeline.Enqueue(store.PipelineJob{
		OrgID:    orgID,
		Hostname: hostname,
		ScanID:   scanID,
	})
}
```

Then in `handleSubmitScan`, after `s.store.SaveScanWithFindings(...)` succeeds, call:
```go
s.EnqueuePipelineJob(scan.OrgID, scan.Metadata.Hostname, scan.ID)
```

- [ ] **Step 7: Verify compilation**

Run: `go build ./...`

- [ ] **Step 8: Commit**

```bash
git add pkg/server/server.go cmd/server.go pkg/server/handlers.go
git commit -m "feat(server): wire analytics pipeline lifecycle + scan submission enqueue

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: API handlers — systems, trends, pipeline status, dataAsOf

**Files:**
- Modify: `pkg/server/handlers_analytics.go`
- Modify: `pkg/server/server.go` (routes)

- [ ] **Step 1: Add handleSystems**

```go
// GET /api/v1/systems?pqc_status=X
func (s *Server) handleSystems(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	pqcFilter := r.URL.Query().Get("pqc_status")

	rows, err := s.store.ListHostSummaries(r.Context(), orgID, pqcFilter)
	if err != nil {
		log.Printf("systems: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.HostSummary{}
	}

	// Include staleness metadata
	var dataAsOf time.Time
	if len(rows) > 0 {
		dataAsOf = rows[0].RefreshedAt
		for _, row := range rows[1:] {
			if row.RefreshedAt.Before(dataAsOf) {
				dataAsOf = row.RefreshedAt
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":        rows,
		"dataAsOf":    dataAsOf,
		"pipelineLag": int(time.Since(dataAsOf).Seconds()),
	})
}
```

- [ ] **Step 2: Add handleTrends**

```go
// GET /api/v1/trends?hostname=X
func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	hostname := r.URL.Query().Get("hostname")

	if hostname != "" {
		// Per-host trend from host_summary sparkline
		rows, err := s.store.ListHostSummaries(r.Context(), orgID, "")
		if err != nil {
			log.Printf("trends: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		for _, row := range rows {
			if row.Hostname == hostname {
				writeJSON(w, http.StatusOK, map[string]any{
					"monthlyPoints": row.Sparkline,
					"direction":     row.TrendDirection,
					"deltaPct":      row.TrendDeltaPct,
					"dataAsOf":      row.RefreshedAt,
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"monthlyPoints": []store.SparklinePoint{},
			"direction":     "insufficient",
			"deltaPct":      0,
		})
		return
	}

	// Org-wide trend from org_snapshot
	snap, err := s.store.GetOrgSnapshot(r.Context(), orgID)
	if err != nil {
		log.Printf("trends: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if snap == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"monthlyPoints": []store.SparklinePoint{},
			"direction":     "insufficient",
			"deltaPct":      0,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"monthlyPoints": snap.MonthlyTrend,
		"direction":     snap.TrendDirection,
		"deltaPct":      snap.TrendDeltaPct,
		"dataAsOf":      snap.RefreshedAt,
		"pipelineLag":   int(time.Since(snap.RefreshedAt).Seconds()),
	})
}
```

- [ ] **Step 3: Add handlePipelineStatus**

```go
// GET /api/v1/pipeline/status
func (s *Server) handlePipelineStatus(w http.ResponseWriter, r *http.Request) {
	if s.pipeline == nil {
		writeJSON(w, http.StatusOK, store.PipelineStatus{Status: "idle"})
		return
	}
	writeJSON(w, http.StatusOK, s.pipeline.Status())
}
```

- [ ] **Step 4: Register routes**

In `pkg/server/server.go`, add routes in the analytics section:

```go
r.Get("/api/v1/systems", srv.handleSystems)
r.Get("/api/v1/trends", srv.handleTrends)
r.Get("/api/v1/pipeline/status", srv.handlePipelineStatus)
```

- [ ] **Step 5: Verify compilation**

Run: `go build ./...`

- [ ] **Step 6: Commit**

```bash
git add pkg/server/handlers_analytics.go pkg/server/server.go
git commit -m "feat(server): add systems, trends, and pipeline status endpoints

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: UI module split

**Files:**
- Modify: `pkg/server/ui/dist/app.js` (slim to router + shared helpers)
- Create: `pkg/server/ui/dist/views/overview.js`
- Create: `pkg/server/ui/dist/views/scans.js`
- Create: `pkg/server/ui/dist/views/machines.js`
- Create: `pkg/server/ui/dist/views/inventory.js`
- Create: `pkg/server/ui/dist/views/certificates.js`
- Create: `pkg/server/ui/dist/views/priority.js`
- Create: `pkg/server/ui/dist/components/filters.js`
- Create: `pkg/server/ui/dist/components/staleness.js`
- Create: `pkg/server/ui/dist/components/sparkline.js`
- Modify: `pkg/server/ui/dist/index.html`

This is a refactoring task. Read the current `app.js` and extract each view's `render*` function into its own file under `views/`. Extract the shared filter bar into `components/filters.js`. The router and shared helpers (writeJSON, formatDate, etc.) stay in `app.js`.

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p pkg/server/ui/dist/views pkg/server/ui/dist/components
```

- [ ] **Step 2: Extract views**

For each view, move the corresponding `render*` function from `app.js` into a new file. Each file registers itself with the router by calling a global `registerView(name, renderFn)` function that `app.js` provides.

Pattern for each view file:
```js
// views/overview.js
(function() {
  registerView('overview', renderOverview);

  function renderOverview() {
    // ... existing code from app.js ...
  }
})();
```

- [ ] **Step 3: Create staleness component**

Create `pkg/server/ui/dist/components/staleness.js`:
```js
// components/staleness.js — Data-as-of bar + pipeline status polling
(function() {
  window.renderStalenessBar = renderStalenessBar;
  window.startPipelinePoll = startPipelinePoll;
  window.stopPipelinePoll = stopPipelinePoll;

  var pollInterval = null;

  function renderStalenessBar(containerId, dataAsOf, pipelineLag) {
    var container = document.getElementById(containerId);
    if (!container) return;
    var dateStr = dataAsOf ? new Date(dataAsOf).toLocaleString() : 'No data yet';
    var statusText = pipelineLag > 0 ? 'Pipeline: processing' : 'Pipeline: idle';
    container.innerHTML =
      '<div class="staleness-bar">' +
      '<span>Data as of: ' + dateStr + '</span>' +
      '<span class="staleness-status">' + statusText + '</span>' +
      '</div>';
  }

  function startPipelinePoll(callback) {
    if (pollInterval) return;
    pollInterval = setInterval(function() {
      fetch('/api/v1/pipeline/status')
        .then(function(r) { return r.json(); })
        .then(callback)
        .catch(function() {});
    }, 10000);
  }

  function stopPipelinePoll() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }
})();
```

- [ ] **Step 4: Create sparkline component**

Create `pkg/server/ui/dist/components/sparkline.js`:
```js
// components/sparkline.js — Chart.js inline sparkline renderer
(function() {
  window.renderSparkline = renderSparkline;

  function renderSparkline(canvasId, points) {
    var canvas = document.getElementById(canvasId);
    if (!canvas || !points || points.length < 2) return;
    new Chart(canvas, {
      type: 'line',
      data: {
        labels: points.map(function(p) { return p.month; }),
        datasets: [{
          data: points.map(function(p) { return p.readiness; }),
          borderColor: '#3b82f6',
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
          tension: 0.3
        }]
      },
      options: {
        responsive: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } },
        animation: false
      }
    });
  }
})();
```

- [ ] **Step 5: Update index.html with script tags**

Add script tags for all view and component modules after the existing `app.js` tag:

```html
<script src="/ui/components/filters.js"></script>
<script src="/ui/components/staleness.js"></script>
<script src="/ui/components/sparkline.js"></script>
<script src="/ui/views/overview.js"></script>
<script src="/ui/views/scans.js"></script>
<script src="/ui/views/machines.js"></script>
<script src="/ui/views/inventory.js"></script>
<script src="/ui/views/certificates.js"></script>
<script src="/ui/views/priority.js"></script>
<script src="/ui/views/systems.js"></script>
<script src="/ui/views/trends.js"></script>
```

- [ ] **Step 6: Update go:embed directive**

In `pkg/server/ui.go` (or wherever the embed directive lives), ensure the `//go:embed` pattern covers the new subdirectories. The existing pattern `ui/dist/*` may need to become `ui/dist/**` or `all:ui/dist` to capture nested directories. Check the current pattern and update.

- [ ] **Step 7: Verify build**

Run: `go build ./...`

- [ ] **Step 8: Commit**

```bash
git add pkg/server/ui/dist/
git commit -m "refactor(ui): split app.js monolith into per-view modules

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Systems Health view (`#/systems`)

**Files:**
- Create: `pkg/server/ui/dist/views/systems.js`
- Modify: `pkg/server/ui/dist/style.css`
- Modify: `pkg/server/ui/dist/index.html` (sidebar nav link)

- [ ] **Step 1: Add sidebar nav link**

In `index.html`, add a new nav link in the Analytics section:

```html
<a href="#/systems" class="nav-link" data-view="systems">
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="1" width="7" height="7" rx="1"/><rect x="10" y="1" width="7" height="7" rx="1"/><rect x="1" y="10" width="7" height="7" rx="1"/><rect x="10" y="10" width="7" height="7" rx="1"/></svg>
  <span>Systems</span>
</a>
```

- [ ] **Step 2: Implement systems view**

Create `pkg/server/ui/dist/views/systems.js`. The view:
1. Fetches `GET /api/v1/systems`
2. Renders summary bar: total systems, red/yellow/green counts
3. Renders table: hostname (clickable), readiness %, trend arrow, sparkline canvas, last scanned
4. Each sparkline is a 60x20 Chart.js canvas inline in the table cell
5. Click hostname navigates to `#/inventory?hostname=<host>`
6. Renders staleness bar via `renderStalenessBar()`

- [ ] **Step 3: Add styles**

Add to `style.css`:
- `.systems-summary` — flex row for red/yellow/green badges
- `.sparkline-cell` — fixed width cell for inline chart
- `.sparkline-canvas` — small canvas element styling
- `.trend-arrow` — color-coded arrows (green ↑, red ↓, grey →)
- `.hostname-link` — clickable hostname styling

- [ ] **Step 4: Commit**

```bash
git add pkg/server/ui/dist/views/systems.js pkg/server/ui/dist/style.css pkg/server/ui/dist/index.html
git commit -m "feat(ui): add Systems Health view with sparklines and drill-through

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Migration Trends view (`#/trends`)

**Files:**
- Create: `pkg/server/ui/dist/views/trends.js`
- Modify: `pkg/server/ui/dist/index.html` (sidebar nav link)

- [ ] **Step 1: Add sidebar nav link**

Add a "Trends" link in the Analytics nav section.

- [ ] **Step 2: Implement trends view**

Create `pkg/server/ui/dist/views/trends.js`. The view:
1. Fetches `GET /api/v1/trends`
2. Renders Chart.js line chart:
   - X axis: months
   - Y axis: readiness % (0-100)
   - Line: org-wide readiness
   - Dashed horizontal line: target % (from org_snapshot)
3. Renders monthly delta table below the chart:
   - Columns: Month, Readiness %, Delta, Direction arrow
4. Renders staleness bar

- [ ] **Step 3: Commit**

```bash
git add pkg/server/ui/dist/views/trends.js pkg/server/ui/dist/index.html
git commit -m "feat(ui): add Migration Trends view with Chart.js line chart

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Full verification + cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run unit tests**

Run: `make test`
Expected: All PASS

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: 0 issues

- [ ] **Step 3: Build all binaries**

Run: `make build`
Expected: Clean build

- [ ] **Step 4: Run integration tests** (if PostgreSQL available)

Run: `make test-integration`

- [ ] **Step 5: Final commit (if fixups needed)**

```bash
git add -A
git commit -m "fix: address lint/test issues from Phase 4A implementation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Review Checkpoint

After Task 12, pause for code review. Key areas:

1. **Pipeline correctness:** Dedup prevents duplicate work; drain processes remaining jobs on shutdown
2. **T2 SQL:** Latest-scan-per-host CTE is correct; sparkline query limits to 12 months
3. **T3 aggregation:** Machine tier counts match the red/yellow/green rules
4. **Staleness:** Every analytics response includes `dataAsOf` and `pipelineLag`
5. **UI split:** Each view file is self-contained; no global state leaks between views
6. **Backward compatibility:** Existing analytics endpoints still work; executive summary falls back to direct computation if org_snapshot is empty
