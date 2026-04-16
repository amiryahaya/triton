# Onboarding Phase 7 — Audit + Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stabilize the five shipped phases. Extract the 4× duplicated job-queue pattern into a reusable abstraction. Add the audit log UI. Wire gateway-side audit events. Add wire-format contract tests. Fix minor code-quality issues from reviews. Instrument the 20-minute success metric. Ship an end-to-end smoke test.

**Architecture:** Refactor-heavy phase. No new bounded contexts. The `pkg/server/jobqueue` extraction reduces ~1200 lines of duplicated claim/ack/reclaim code across discovery, credentials, and scanjobs into a generic `Queue[Payload]`. Audit UI is a new `/manage/#/audit` page consuming the existing `GET /api/v1/audit` endpoint (already exists from prior multi-tenant work). Gateway audit closes the observability gap on engine-submitted events.

**Tech Stack:** Go generics (1.25), existing pgx v5 pool, existing audit write path, vanilla JS.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §11 (audit), §14 (success metric).

---

## Prerequisites

- [ ] Phase 5 merged (PR #61). Current migration head: v21.

---

## File Map

**Create:**
- `pkg/server/jobqueue/queue.go` — generic `Queue[Payload]` with ClaimNext, Finish, ReclaimStale
- `pkg/server/jobqueue/queue_test.go` — unit tests for generic queue ops
- `pkg/server/jobqueue/reaper.go` — generic StaleReaper
- `pkg/server/jobqueue/reaper_test.go`
- `test/integration/onboarding_wire_test.go` — wire-format contract tests (credentials + scanjobs)
- `test/integration/onboarding_e2e_test.go` — end-to-end journey smoke test

**Modify:**
- `pkg/server/discovery/postgres.go` — replace ClaimNext/FinishJob/ReclaimStale with jobqueue calls
- `pkg/server/discovery/store.go` — narrow interface to delegate queue ops
- `pkg/server/discovery/stale_reaper.go` — replace with jobqueue.StaleReaper
- `pkg/server/credentials/postgres.go` — same refactor for delivery queue + test queue
- `pkg/server/credentials/store.go` — narrow
- `pkg/server/credentials/stale_reaper.go` — replace
- `pkg/server/scanjobs/postgres.go` — same refactor
- `pkg/server/scanjobs/store.go` — narrow
- `pkg/server/scanjobs/stale_reaper.go` — replace
- `pkg/server/discovery/handlers_gateway.go` — add audit to Submit
- `pkg/server/scanjobs/handlers_gateway.go` — add audit to Submit/Finish
- `pkg/engine/scanexec/executor.go` — nil-credential short-circuit + TOCTOU comment
- `pkg/engine/scanexec/worker.go` — goroutine leak check on progress drain
- `pkg/server/ui/dist/manage/app.js` — add `#/audit` route
- `pkg/server/ui/dist/manage/index.html` — add Audit nav link

---

### Task 1: Extract `pkg/server/jobqueue` — generic queue abstraction

The 4 duplicated patterns across discovery, credentials (delivery + test), and scanjobs each implement:
- `ClaimNext(ctx, engineID) (T, bool, error)` — `SELECT ... FOR UPDATE SKIP LOCKED`
- `Finish(ctx, engineID, jobID, status, errMsg) error` — terminal-state guard
- `ReclaimStale(ctx, cutoff) error` — `UPDATE ... WHERE status IN ('claimed','running') AND claimed_at < cutoff`

Each has a different table name, different column set, and different `Payload` enrichment query.

**Design:** A generic helper that takes a table name + column config and generates the SQL at construction time. NOT a full ORM — just three reusable methods. Each consumer wraps the generic with its own type-safe Store methods.

```go
// Package jobqueue provides a generic engine-job-queue backed by a
// PostgreSQL table following the claim/ack/reclaim pattern used by
// discovery, credentials, and scanjobs bounded contexts.
package jobqueue

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

var (
    ErrNotFound       = errors.New("jobqueue: not found")
    ErrNotOwned       = errors.New("jobqueue: not owned by this engine")
    ErrAlreadyTerminal = errors.New("jobqueue: already in terminal state")
    ErrNotCancellable  = errors.New("jobqueue: not cancellable")
)

// Config defines the table and column names for a specific queue.
type Config struct {
    Table            string // e.g. "discovery_jobs", "scan_jobs"
    EngineIDColumn   string // e.g. "engine_id"
    StatusColumn     string // e.g. "status"
    ClaimedAtColumn  string // e.g. "claimed_at"
    RequestedAtColumn string // e.g. "requested_at"
    QueuedStatus     string // e.g. "queued"
    ClaimedStatus    string // e.g. "claimed"
    TerminalStatuses []string // e.g. ["completed", "failed", "cancelled"]
}

type Queue struct {
    pool *pgxpool.Pool
    cfg  Config

    // Pre-built SQL (computed once at construction)
    claimSelectSQL string
    claimUpdateSQL string
    finishSQL      string
    reclaimSQL     string
    cancelSQL      string
}

func New(pool *pgxpool.Pool, cfg Config) *Queue {
    q := &Queue{pool: pool, cfg: cfg}
    q.buildSQL()
    return q
}

func (q *Queue) buildSQL() {
    terminalList := "'" + q.cfg.TerminalStatuses[0] + "'"
    for _, s := range q.cfg.TerminalStatuses[1:] {
        terminalList += ",'" + s + "'"
    }

    q.claimSelectSQL = fmt.Sprintf(
        `SELECT id FROM %s WHERE %s = $1 AND %s = '%s' ORDER BY %s ASC FOR UPDATE SKIP LOCKED LIMIT 1`,
        q.cfg.Table, q.cfg.EngineIDColumn, q.cfg.StatusColumn, q.cfg.QueuedStatus, q.cfg.RequestedAtColumn,
    )
    q.claimUpdateSQL = fmt.Sprintf(
        `UPDATE %s SET %s = '%s', %s = NOW() WHERE id = $1 AND %s = '%s'`,
        q.cfg.Table, q.cfg.StatusColumn, q.cfg.ClaimedStatus, q.cfg.ClaimedAtColumn, q.cfg.StatusColumn, q.cfg.QueuedStatus,
    )
    q.finishSQL = fmt.Sprintf(
        `UPDATE %s SET %s = $1, error = NULLIF($2, ''), completed_at = NOW() WHERE id = $3 AND %s = $4 AND %s NOT IN (%s)`,
        q.cfg.Table, q.cfg.StatusColumn, q.cfg.EngineIDColumn, q.cfg.StatusColumn, terminalList,
    )
    q.reclaimSQL = fmt.Sprintf(
        `UPDATE %s SET %s = '%s', %s = NULL WHERE %s IN ('%s','running') AND %s IS NOT NULL AND %s < $1`,
        q.cfg.Table, q.cfg.StatusColumn, q.cfg.QueuedStatus, q.cfg.ClaimedAtColumn,
        q.cfg.StatusColumn, q.cfg.ClaimedStatus, q.cfg.ClaimedAtColumn, q.cfg.ClaimedAtColumn,
    )
    q.cancelSQL = fmt.Sprintf(
        `UPDATE %s SET %s = 'cancelled', completed_at = NOW() WHERE org_id = $1 AND id = $2 AND %s = '%s'`,
        q.cfg.Table, q.cfg.StatusColumn, q.cfg.StatusColumn, q.cfg.QueuedStatus,
    )
}

// ClaimNextID atomically picks the oldest queued job for this engine
// and flips it to claimed. Returns the job ID + true, or uuid.Nil + false.
// Callers enrich the ID into a typed payload separately.
func (q *Queue) ClaimNextID(ctx context.Context, engineID uuid.UUID) (uuid.UUID, bool, error) {
    tx, err := q.pool.Begin(ctx)
    if err != nil { return uuid.Nil, false, err }
    defer tx.Rollback(ctx) //nolint:errcheck

    var id uuid.UUID
    err = tx.QueryRow(ctx, q.claimSelectSQL, engineID).Scan(&id)
    if errors.Is(err, pgx.ErrNoRows) { return uuid.Nil, false, nil }
    if err != nil { return uuid.Nil, false, err }

    ct, err := tx.Exec(ctx, q.claimUpdateSQL, id)
    if err != nil { return uuid.Nil, false, err }
    if ct.RowsAffected() == 0 {
        return uuid.Nil, false, nil // lost race
    }
    if err := tx.Commit(ctx); err != nil { return uuid.Nil, false, err }
    return id, true, nil
}

// Finish transitions a job to a terminal state. Checks engine ownership +
// rejects if already terminal.
func (q *Queue) Finish(ctx context.Context, engineID, jobID uuid.UUID, status, errMsg string) error {
    ct, err := q.pool.Exec(ctx, q.finishSQL, status, errMsg, jobID, engineID)
    if err != nil { return err }
    if ct.RowsAffected() == 0 {
        return q.disambiguate(ctx, engineID, jobID)
    }
    return nil
}

// ReclaimStale flips claimed/running jobs older than cutoff back to queued.
func (q *Queue) ReclaimStale(ctx context.Context, cutoff time.Time) error {
    _, err := q.pool.Exec(ctx, q.reclaimSQL, cutoff)
    return err
}

// Cancel transitions a queued job to cancelled. Returns ErrNotCancellable
// if the job is not in queued state.
func (q *Queue) Cancel(ctx context.Context, orgID, jobID uuid.UUID) error {
    ct, err := q.pool.Exec(ctx, q.cancelSQL, orgID, jobID)
    if err != nil { return err }
    if ct.RowsAffected() == 0 {
        var status string
        err := q.pool.QueryRow(ctx,
            fmt.Sprintf(`SELECT %s FROM %s WHERE org_id = $1 AND id = $2`, q.cfg.StatusColumn, q.cfg.Table),
            orgID, jobID,
        ).Scan(&status)
        if errors.Is(err, pgx.ErrNoRows) { return ErrNotFound }
        if err != nil { return err }
        return ErrNotCancellable
    }
    return nil
}

func (q *Queue) disambiguate(ctx context.Context, engineID, jobID uuid.UUID) error {
    var curEngineID uuid.UUID
    var curStatus string
    err := q.pool.QueryRow(ctx,
        fmt.Sprintf(`SELECT %s, %s FROM %s WHERE id = $1`, q.cfg.EngineIDColumn, q.cfg.StatusColumn, q.cfg.Table),
        jobID,
    ).Scan(&curEngineID, &curStatus)
    if errors.Is(err, pgx.ErrNoRows) { return ErrNotFound }
    if err != nil { return err }
    if curEngineID != engineID { return ErrNotOwned }
    return ErrAlreadyTerminal
}
```

**Tests (unit — no DB needed for SQL generation; integration for actual queue ops):**

`queue_test.go`:
- `TestQueue_BuildSQL_ProducesExpectedStatements` — construct with known config, assert SQL strings contain expected table names + column refs
- Integration tests in `queue_integration_test.go` (build tag `integration`):
  - `TestQueue_ClaimNextID_SingleUse` — seed row, 5 goroutines, exactly 1 wins
  - `TestQueue_Finish_OwnershipGuard` — claim with engine A, finish with engine B → ErrNotOwned
  - `TestQueue_Finish_TerminalGuard` — finish twice → ErrAlreadyTerminal
  - `TestQueue_ReclaimStale` — claim, set old claimed_at, reclaim, verify queued
  - `TestQueue_Cancel_QueuedOK` / `TestQueue_Cancel_ClaimedNotCancellable`

Use a dedicated test table (create/drop in test setup) rather than polluting the real tables. Or reuse `discovery_jobs` since its schema matches the pattern.

**StaleReaper** in `pkg/server/jobqueue/reaper.go`:

```go
package jobqueue

import (
    "context"
    "log"
    "time"
)

type Reclaimer interface {
    ReclaimStale(ctx context.Context, cutoff time.Time) error
}

type StaleReaper struct {
    Reclaimer Reclaimer
    Label     string        // for log prefix
    Interval  time.Duration // default 5min
    Timeout   time.Duration // default 15min
    Now       func() time.Time
}

func (r *StaleReaper) Run(ctx context.Context) {
    if r.Interval == 0 { r.Interval = 5 * time.Minute }
    if r.Timeout == 0 { r.Timeout = 15 * time.Minute }
    if r.Now == nil { r.Now = time.Now }
    t := time.NewTicker(r.Interval)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done(): return
        case <-t.C:
            if err := r.Reclaimer.ReclaimStale(ctx, r.Now().Add(-r.Timeout)); err != nil {
                log.Printf("%s stale reaper: %v", r.Label, err)
            }
        }
    }
}
```

Commit: `refactor(jobqueue): extract generic Queue + StaleReaper from 4× duplicated pattern`

---

### Task 2: Migrate discovery to jobqueue

**Files:**
- Modify: `pkg/server/discovery/postgres.go` — replace `ClaimNext`, `FinishJob`, `ReclaimStale`, `CancelJob` with `jobqueue.Queue` calls
- Delete: `pkg/server/discovery/stale_reaper.go` + test (replaced by `jobqueue.StaleReaper`)
- Modify: `cmd/server.go` — replace `discovery.StaleReaper` with `jobqueue.StaleReaper`

`ClaimNext` wraps `q.ClaimNextID` then does the enrichment query:

```go
func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (Job, bool, error) {
    id, found, err := s.queue.ClaimNextID(ctx, engineID)
    if !found || err != nil { return Job{}, false, err }
    return s.enrichClaimedJob(ctx, id)
}
```

`FinishJob` delegates: `return s.queue.Finish(ctx, engineID, jobID, status, errMsg)` (add `engineID` parameter if not already present — check Phase 3 review fixes).

Wait — discovery's `FinishJob` currently takes `(ctx, jobID, status, errMsg, candidateCount)` and does NOT have an `engineID` param (Phase 3 added the terminal-state guard but not ownership). Two choices:
- (a) Add `engineID` param to discovery `FinishJob` now → breaking change for discovery gateway handler → update handler
- (b) Keep discovery without ownership guard (it wasn't flagged as a critical issue)

Choose (a) for consistency with the Phase 5 lesson. The gateway handler already has `engine.EngineFromContext(ctx)` available.

All integration tests must still pass. Run: `TRITON_TEST_DB_URL=... go test -tags integration ./pkg/server/discovery/ -p 1`

Commit: `refactor(discovery): delegate to jobqueue.Queue for claim/finish/reclaim/cancel`

---

### Task 3: Migrate credentials to jobqueue

Same pattern — `credential_deliveries` uses the queue for delivery claim/ack, `credential_tests` uses it for test claim/finish. Two `Queue` instances per PostgresStore.

Delete `pkg/server/credentials/stale_reaper.go` + test. Replace with two `jobqueue.StaleReaper` instances in `cmd/server.go`.

Add `engineID` to delivery `AckDelivery` and test `FinishTestJob` if not already present.

Commit: `refactor(credentials): delegate to jobqueue.Queue for delivery + test queues`

---

### Task 4: Migrate scanjobs to jobqueue

Same pattern. `scan_jobs` queue with `ClaimNextID` + enrichment.

Already has `engineID` on all methods (Phase 5 review fix). Should be the cleanest migration.

Delete `pkg/server/scanjobs/stale_reaper.go` + test.

Commit: `refactor(scanjobs): delegate to jobqueue.Queue`

---

### Task 5: Gateway audit wiring

Add `AuditRecorder` to discovery gateway handlers (`handlers_gateway.go`). Emit events:
- `discovery.candidates.submitted` on Submit (with engine_id + job_id + candidate_count)
- Scan submit/finish audit already added in Phase 5 fix `de5a828` — verify it's still wired correctly after refactors.

Wire `server.NewAuditAdapter(srv)` into the discovery `GatewayHandlers` construction in `cmd/server_engine.go`.

Commit: `feat(discovery): gateway audit on candidate submission`

---

### Task 6: Wire-format contract tests

Create `test/integration/onboarding_wire_test.go` (build tag `integration`):

```go
// Wire-format contract tests ensure portal response JSON round-trips
// correctly into engine-client types. Catches drift between portal
// types (with json tags) and engine/client types (independently defined
// wire structs). Phase 4 C1 and Phase 5 I1 both found such drift.

func TestWireFormat_CredentialDelivery_RoundTrips(t *testing.T) {
    // Marshal a credentials.Delivery (portal) → JSON bytes → unmarshal into
    // client.DeliveryPayload (engine). Assert all non-zero fields survive.
}

func TestWireFormat_CredentialTestJobPayload_RoundTrips(t *testing.T) { ... }

func TestWireFormat_ScanJobPayload_RoundTrips(t *testing.T) {
    // Marshal a scanjobs.JobPayload → JSON → unmarshal into client.ScanJobPayload.
    // Specifically verify CredentialSecretRef (uuid.UUID → *string) roundtrips.
}

func TestWireFormat_DiscoveryJob_RoundTrips(t *testing.T) { ... }
```

These tests import BOTH `pkg/server/*` and `pkg/engine/client` — verify no import cycle. Engine client doesn't import server packages, so direction is safe.

Commit: `test(onboarding): wire-format contract tests — credentials + scanjobs + discovery`

---

### Task 7: Error state polish

Minor fixes from Phase 5 third-pass review:

**M1 — Goroutine leak check on scanner progress drain:**
In `pkg/engine/scanexec/executor.go`, the `defaultRunScanner` (or equivalent) spawns a goroutine draining `progressCh`. Verify `scanner.Engine.Scan` always closes `progressCh` via `defer close(progressCh)` (check `pkg/scanner/engine.go` line ~216). If confirmed, add a comment. If NOT confirmed, add `defer close(progressCh)` before calling `Scan`.

**M3 — Nil-credential short-circuit:**
In `pkg/engine/scanexec/worker.go`, when `job.CredentialSecretRef == nil`, short-circuit with a clear error instead of passing empty string to keystore:

```go
if secretRef == "" {
    res = HostResult{HostID: host.ID, Error: "no credential profile configured for this scan job"}
} else {
    res = w.Executor.ScanHost(hctx, target, secretRef, job.CredentialAuthType, job.ScanProfile)
}
```

**M2 — TOCTOU comment:**
In `pkg/server/scanjobs/postgres.go` `RecordScanResult`, add explicit comment noting the gap between pre-check and insert.

Commit: `fix(engine): nil-credential short-circuit + goroutine-leak comment + TOCTOU doc`

---

### Task 8: Audit log UI

Add `#/audit` route to `/manage/` UI.

The existing portal already has `GET /api/v1/audit` (or `/api/v1/audit/events` — check the actual endpoint with `grep -rn "audit" pkg/server/handlers_audit.go`). This returns audit events with fields like `{id, event_type, target_id, user_id, details, created_at, remote_addr}`.

```javascript
routes['/audit'] = renderAudit;

async function renderAudit(el) {
    el.innerHTML = `
        <h1>Audit Log</h1>
        <p class="muted">All actions across inventory, credentials, scans, and engine management.</p>
        <div class="filter-row">
            <input type="text" id="audit_search" placeholder="Search by event or target…">
            <button id="audit_refresh">Refresh</button>
        </div>
        <div id="audit_list">loading…</div>
    `;
    const load = async () => {
        const search = el.querySelector('#audit_search')?.value || '';
        let url = '/api/v1/audit?limit=200';
        if (search) url += '&q=' + encodeURIComponent(search);
        const resp = await authedFetch(url);
        const events = await resp.json();
        const list = el.querySelector('#audit_list');
        if (!events || events.length === 0) {
            list.innerHTML = '<p><em>No events found.</em></p>';
            return;
        }
        list.innerHTML = `<table>
            <thead><tr><th>Time</th><th>Event</th><th>Target</th><th>User</th><th>Details</th></tr></thead>
            <tbody>${events.map(e => `<tr>
                <td>${timeAgo(e.created_at)}</td>
                <td><code>${escapeHTML(e.event_type)}</code></td>
                <td><code class="muted">${escapeHTML(e.target_id || '')}</code></td>
                <td>${escapeHTML(e.user_id || e.remote_addr || '—')}</td>
                <td class="muted">${escapeHTML(JSON.stringify(e.details || {})).slice(0, 120)}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    };
    await load().catch(() => {});
    el.querySelector('#audit_refresh')?.addEventListener('click', load);
    el.querySelector('#audit_search')?.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') load();
    });
}
```

Add nav link "Audit" to `index.html` — place last before the Reports link.

Check the actual audit endpoint path + response shape before implementing. If the endpoint is `/api/v1/audit/events` with pagination, adapt.

Commit: `feat(ui): audit log page under /manage/#/audit`

---

### Task 9: 20-minute success metric instrumentation

The spec §14 says: "Measured via portal audit log timestamps per org's first 24 hours. Target: p50 ≤20min, p90 ≤45min."

Journey milestones (each already emits an audit event):
1. `user.create` — org owner first login
2. `engine.enroll` — engine bundle claimed
3. `inventory.hosts.import` OR `discovery.job.create` — first hosts added
4. `credentials.profile.create` — first credential
5. `scanjobs.job.create` — first scan triggered
6. `scanjobs.job.finished` (status=completed) — first results

Add a portal-side SQL view or query that computes per-org time-to-first-scan:

```sql
CREATE OR REPLACE VIEW onboarding_metrics AS
WITH milestones AS (
    SELECT
        org_id,
        MIN(CASE WHEN event_type = 'user.create' THEN created_at END) AS t_signup,
        MIN(CASE WHEN event_type LIKE 'engine.%' THEN created_at END) AS t_engine,
        MIN(CASE WHEN event_type IN ('inventory.hosts.import', 'discovery.job.create') THEN created_at END) AS t_hosts,
        MIN(CASE WHEN event_type = 'credentials.profile.create' THEN created_at END) AS t_creds,
        MIN(CASE WHEN event_type = 'scanjobs.job.create' THEN created_at END) AS t_scan,
        MIN(CASE WHEN event_type = 'scanjobs.job.finished' THEN created_at END) AS t_results
    FROM audit_events
    GROUP BY org_id
)
SELECT
    org_id,
    t_signup,
    t_results,
    EXTRACT(EPOCH FROM (t_results - t_signup)) / 60.0 AS minutes_to_first_scan
FROM milestones
WHERE t_signup IS NOT NULL AND t_results IS NOT NULL;
```

Add this as migration v22 (a view, not a table — cheap, droppable).

Add an admin-only endpoint `GET /api/v1/admin/onboarding-metrics` that returns the view's data. Gate behind `RequireRole(RoleOwner)`.

Add a card on the `/manage/#/dashboard` showing "Time to first scan: X minutes" for the current org.

Commit: `feat(server): onboarding success-metric view + admin endpoint + dashboard card`

---

### Task 10: End-to-end smoke test

Create `test/integration/onboarding_e2e_test.go` (build tag `integration`).

This test exercises the full customer journey in-process:

```go
func TestOnboarding_EndToEnd_ZeroToFirstScan(t *testing.T) {
    // 1. Start portal (in-process test server like pkg/server test pattern)
    // 2. POST /api/v1/auth/register → owner user
    // 3. POST /api/v1/manage/engines/ → download bundle tar.gz
    // 4. Parse bundle, construct engine mTLS client
    // 5. Engine: POST /api/v1/engine/enroll
    // 6. POST /api/v1/manage/hosts/import → seed 1 host (localhost)
    // 7. POST /api/v1/manage/credentials/ → encrypted secret for SSH (if testing locally)
    // 8. POST /api/v1/manage/scan-jobs/ → trigger scan
    // 9. Poll GET /api/v1/manage/scan-jobs/{id} until completed (timeout 2min)
    // 10. GET /api/v1/scans → verify at least one scan result with engine_id + scan_job_id populated
    //
    // Skip if TRITON_TEST_DB_URL unset. Skip SSH steps if TRITON_SSH_TEST_HOST unset.
    // For non-SSH environments, verify steps 1-8 succeed (scan job created) even if
    // the engine can't actually dial — the job will fail but the pipeline is exercised.
}
```

This is ambitious for an integration test. **Simplified version**: test the portal API path only (steps 1-8), stub the engine side. Verify the job transitions through `queued` → `claimed` (via a fakeEngine that long-polls) → submitted findings → `completed`. This tests the portal pipeline without requiring a real SSH target.

Commit: `test(onboarding): end-to-end portal+engine journey smoke test`

---

### Task 11: Verify + PR + review

- [ ] `go build ./...` clean
- [ ] `make lint` 0 issues
- [ ] All unit tests pass
- [ ] All integration tests pass (including new wire-format + e2e)
- [ ] Push, PR, code-reviewer dispatch

---

## Self-Review Checklist

**Spec coverage (§11 audit, §14 metric):**
- Audit log UI searchable ✓ (Task 8)
- Gateway audit wiring ✓ (Task 5)
- 20-min metric instrumented ✓ (Task 9)
- E2E smoke test ✓ (Task 10)

**Tech debt addressed:**
- TD-A1 (4× job-queue pattern) ✓ (Tasks 1-4)
- TD-A3 (gateway audit gap) ✓ (Task 5)
- Wire-format drift prevention ✓ (Task 6)
- Phase 5 third-pass minors ✓ (Task 7)

**Risks:**
- Jobqueue refactor touches 3 bounded contexts simultaneously — high blast radius. Run integration tests after EACH migration (Task 2, 3, 4) not just at the end.
- Audit endpoint response shape may differ from what the UI expects — verify before implementing Task 8.
- E2E test complexity — if too ambitious, ship the simplified portal-only version.
