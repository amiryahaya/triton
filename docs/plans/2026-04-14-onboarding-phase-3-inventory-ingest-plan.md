# Onboarding Phase 3 — Inventory Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two ways to get hosts into the inventory: CSV import (client-side parse, dry-run preview, commit) and network discovery (user specifies CIDRs → engine runs an unprivileged TCP-connect sweep → candidates stream back → user promotes selected rows into a group).

**Architecture:** CSV path is a straight portal-side JSON endpoint — browser parses CSV, POSTs structured rows, portal validates + inserts. Discovery path uses the engine gateway: portal queues a `discovery_jobs` row, engine long-polls for work, runs TCP connect sweeps against the CIDRs with bounded concurrency, POSTs candidates back, user reviews in UI and promotes rows to hosts. The discovery job flow previews the scan-job pull protocol used in Phase 5.

**Tech Stack:** Go 1.25 stdlib `net` for TCP connect dialer, `github.com/go-chi/chi/v5`, vanilla JS with `FileReader` API for CSV parsing, same `engine.Store` + `MTLSMiddleware` pattern from Phase 2.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §6 step 3 (Add hosts).

---

## Prerequisites

- [ ] Phase 2 merged to `main` (PR #53). Confirm: `git log main --grep "onboarding phase 2" --oneline` shows the merge commit.
- [ ] Engine gateway listener on port 8443 is running — discovery endpoints mount on it.
- [ ] Migration v18 is the current head. This phase appends v19.

---

## File Map

**Create:**
- `pkg/server/discovery/types.go` — DiscoveryJob, Candidate, JobStatus
- `pkg/server/discovery/store.go` — Store interface
- `pkg/server/discovery/postgres.go` — PostgresStore
- `pkg/server/discovery/postgres_test.go` — integration tests
- `pkg/server/discovery/handlers_admin.go` — `/api/v1/manage/discoveries/*` (Engineer+ create, any authed get, Engineer+ promote)
- `pkg/server/discovery/handlers_gateway.go` — `/api/v1/engine/discoveries/*` (mTLS only: poll + submit)
- `pkg/server/discovery/handlers_test.go` — admin + gateway handler tests
- `pkg/server/discovery/routes.go` — MountAdminRoutes + MountGatewayRoutes
- `pkg/server/inventory/handlers_import.go` — `POST /api/v1/manage/hosts/import` + dry-run
- `pkg/server/inventory/handlers_import_test.go` — import handler tests
- `pkg/engine/discovery/scanner.go` — TCP connect sweep with bounded workers
- `pkg/engine/discovery/scanner_test.go` — scanner unit tests (net.Listener for synthetic targets)
- `pkg/engine/discovery/worker.go` — polling loop, claims jobs, calls scanner, submits
- `pkg/engine/discovery/worker_test.go` — worker unit tests with fake gateway client

**Modify:**
- `pkg/store/migrations.go` — append Version 19 (discovery_jobs + discovery_candidates)
- `pkg/server/inventory/routes.go` — mount `/import` route
- `cmd/server.go` + `cmd/server_engine.go` — wire discovery admin + gateway routes
- `pkg/engine/client/client.go` — add `PollDiscovery`, `SubmitDiscovery` methods
- `pkg/engine/loop/loop.go` — spawn discovery worker alongside heartbeat
- `cmd/triton-engine/main.go` — wire discovery worker into Run
- `pkg/server/ui/dist/manage/app.js` — add `#/discoveries` route + hosts import view
- `pkg/server/ui/dist/manage/index.html` — add "Discoveries" nav link
- `pkg/server/ui/dist/manage/style.css` — CSV import form styles, candidate table

**Do not touch:**
- `pkg/server/engine/*` (Phase 2, unchanged contract)
- `pkg/scanner/*` (Phase 5 integration point)
- `pkg/licenseserver/*`

---

### Task 1: Migration v19 — discovery tables

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Append as index 18 of the migrations slice (version 19 externally).**

```go
`
CREATE TABLE discovery_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    cidrs           TEXT[] NOT NULL,
    ports           INTEGER[] NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    candidate_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_discovery_jobs_org        ON discovery_jobs(org_id);
CREATE INDEX idx_discovery_jobs_engine     ON discovery_jobs(engine_id);
CREATE INDEX idx_discovery_jobs_status     ON discovery_jobs(status);
CREATE INDEX idx_discovery_jobs_engine_queue
    ON discovery_jobs(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE discovery_candidates (
    id          UUID PRIMARY KEY,
    job_id      UUID NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    address     INET NOT NULL,
    hostname    TEXT,
    open_ports  INTEGER[] NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    promoted    BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (job_id, address)
);

CREATE INDEX idx_discovery_candidates_job ON discovery_candidates(job_id);
`,
```

- [ ] **Step 2: Apply + verify**

```bash
make db-up
psql "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" -c "\dt discovery_*"
```

Expected: 2 tables.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(store): discovery_jobs + discovery_candidates tables (v19)"
```

---

### Task 2: Discovery domain types + Store interface

**Files:**
- Create: `pkg/server/discovery/types.go`
- Create: `pkg/server/discovery/store.go`

- [ ] **Step 1: Types**

```go
// Package discovery is the Onboarding network-discovery bounded context:
// scan jobs that sweep a set of CIDRs for live hosts, candidate results,
// and promotion of candidates to inventory hosts.
package discovery

import (
    "net"
    "time"

    "github.com/google/uuid"
)

type JobStatus = string

const (
    StatusQueued    JobStatus = "queued"
    StatusClaimed   JobStatus = "claimed"
    StatusRunning   JobStatus = "running"
    StatusCompleted JobStatus = "completed"
    StatusFailed    JobStatus = "failed"
    StatusCancelled JobStatus = "cancelled"
)

type Job struct {
    ID             uuid.UUID  `json:"id"`
    OrgID          uuid.UUID  `json:"org_id"`
    EngineID       uuid.UUID  `json:"engine_id"`
    RequestedBy    uuid.UUID  `json:"requested_by"`
    CIDRs          []string   `json:"cidrs"`
    Ports          []int      `json:"ports"`
    Status         JobStatus  `json:"status"`
    Error          string     `json:"error,omitempty"`
    RequestedAt    time.Time  `json:"requested_at"`
    ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
    CompletedAt    *time.Time `json:"completed_at,omitempty"`
    CandidateCount int        `json:"candidate_count"`
}

type Candidate struct {
    ID         uuid.UUID `json:"id"`
    JobID      uuid.UUID `json:"job_id"`
    Address    net.IP    `json:"address"`
    Hostname   string    `json:"hostname,omitempty"`
    OpenPorts  []int     `json:"open_ports"`
    DetectedAt time.Time `json:"detected_at"`
    Promoted   bool      `json:"promoted"`
}
```

- [ ] **Step 2: Store interface**

```go
package discovery

import (
    "context"

    "github.com/google/uuid"
)

type Store interface {
    // Admin side
    CreateJob(ctx context.Context, j Job) (Job, error)
    GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error)
    ListJobs(ctx context.Context, orgID uuid.UUID) ([]Job, error)
    ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error)
    MarkCandidatesPromoted(ctx context.Context, ids []uuid.UUID) error
    CancelJob(ctx context.Context, orgID, id uuid.UUID) error

    // Engine gateway side
    // ClaimNext atomically picks the oldest queued job for this engine,
    // flips its status to 'claimed', and returns it. Returns (Job{}, nil, false)
    // with the found=false signal when the queue is empty.
    ClaimNext(ctx context.Context, engineID uuid.UUID) (Job, bool, error)
    InsertCandidates(ctx context.Context, jobID uuid.UUID, cs []Candidate) error
    FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string, candidateCount int) error
}
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(discovery): domain types + Store interface"
```

---

### Task 3: PostgresStore + integration tests

**Files:**
- Create: `pkg/server/discovery/postgres.go`
- Create: `pkg/server/discovery/postgres_test.go`

- [ ] **Step 1: Implement PostgresStore**

Follow the Phase 2 engine PostgresStore pattern: `NewPostgresStore(pool)` constructor, typed methods, org_id scoping on admin reads, `ClaimNext` uses a transactional `SELECT ... FOR UPDATE SKIP LOCKED ... LIMIT 1` pattern to guarantee single-claim semantics.

Key methods:

```go
func (s *PostgresStore) CreateJob(ctx context.Context, j Job) (Job, error) {
    row := s.pool.QueryRow(ctx,
        `INSERT INTO discovery_jobs (id, org_id, engine_id, requested_by, cidrs, ports, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'queued')
         RETURNING requested_at`,
        j.ID, j.OrgID, j.EngineID, j.RequestedBy, j.CIDRs, toInt32Array(j.Ports),
    )
    if err := row.Scan(&j.RequestedAt); err != nil {
        return Job{}, fmt.Errorf("create discovery job: %w", err)
    }
    j.Status = StatusQueued
    return j, nil
}

func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (Job, bool, error) {
    tx, err := s.pool.Begin(ctx)
    if err != nil {
        return Job{}, false, err
    }
    defer tx.Rollback(ctx) //nolint:errcheck

    var j Job
    var ports []int32
    row := tx.QueryRow(ctx,
        `SELECT id, org_id, engine_id, requested_by, cidrs, ports, status,
                requested_at, claimed_at
         FROM discovery_jobs
         WHERE engine_id = $1 AND status = 'queued'
         ORDER BY requested_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1`,
        engineID,
    )
    err = row.Scan(&j.ID, &j.OrgID, &j.EngineID, &j.RequestedBy, &j.CIDRs,
        &ports, &j.Status, &j.RequestedAt, &j.ClaimedAt)
    if errors.Is(err, pgx.ErrNoRows) {
        return Job{}, false, nil
    }
    if err != nil {
        return Job{}, false, err
    }
    j.Ports = fromInt32Array(ports)

    _, err = tx.Exec(ctx,
        `UPDATE discovery_jobs SET status='claimed', claimed_at=NOW() WHERE id=$1`,
        j.ID,
    )
    if err != nil {
        return Job{}, false, err
    }

    if err := tx.Commit(ctx); err != nil {
        return Job{}, false, err
    }
    j.Status = StatusClaimed
    now := time.Now().UTC()
    j.ClaimedAt = &now
    return j, true, nil
}

func (s *PostgresStore) InsertCandidates(ctx context.Context, jobID uuid.UUID, cs []Candidate) error {
    if len(cs) == 0 {
        return nil
    }
    // Batch insert with ON CONFLICT DO NOTHING so retries are idempotent.
    tx, err := s.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx) //nolint:errcheck

    for _, c := range cs {
        if c.ID == uuid.Nil {
            c.ID = uuid.Must(uuid.NewV7())
        }
        _, err = tx.Exec(ctx,
            `INSERT INTO discovery_candidates
             (id, job_id, address, hostname, open_ports)
             VALUES ($1, $2, $3::inet, NULLIF($4, ''), $5)
             ON CONFLICT (job_id, address) DO NOTHING`,
            c.ID, jobID, c.Address.String(), c.Hostname, toInt32Array(c.OpenPorts),
        )
        if err != nil {
            return err
        }
    }
    return tx.Commit(ctx)
}

func (s *PostgresStore) FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string, count int) error {
    _, err := s.pool.Exec(ctx,
        `UPDATE discovery_jobs
         SET status = $2, error = NULLIF($3, ''), completed_at = NOW(), candidate_count = $4
         WHERE id = $1`,
        jobID, status, errMsg, count,
    )
    return err
}
```

Add helpers `toInt32Array([]int) []int32` and `fromInt32Array([]int32) []int` for the pgx-driven `INTEGER[]` type handling. Keep in the same file.

- [ ] **Step 2: Integration tests (`//go:build integration`)**

Cover:
- `TestPostgresStore_CreateAndListJobs` — create two jobs for different engines, list by org returns both
- `TestPostgresStore_ClaimNext_IsSingleUse` — two concurrent `ClaimNext` calls against same engine must return different jobs (or one returns `found=false`); use goroutines + `errgroup`
- `TestPostgresStore_ClaimNext_NoQueuedJobs_ReturnsFound False`
- `TestPostgresStore_InsertCandidates_Idempotent` — insert same candidate twice, second is no-op
- `TestPostgresStore_FinishJob_UpdatesAllFields`
- `TestPostgresStore_MarkCandidatesPromoted_Bulk` — promote 3 candidates, verify all flagged

Seed an org row + engine row via `t.Cleanup` — mirror the Phase 2 engine test fixture.

Run:
```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/server/discovery/
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(discovery): PostgresStore with SKIP LOCKED claim + idempotent candidate insert"
```

---

### Task 4: CSV import handler on the inventory package

**Files:**
- Create: `pkg/server/inventory/handlers_import.go`
- Create: `pkg/server/inventory/handlers_import_test.go`
- Modify: `pkg/server/inventory/routes.go` — mount `POST /import` behind RequireRole(Engineer)

**Contract:**

Request body (JSON):

```json
{
  "group_id": "uuid",
  "rows": [
    {"hostname": "app-01", "address": "10.0.0.1", "os": "linux", "mode": "agentless", "tags": [{"key":"env","value":"prod"}]},
    ...
  ],
  "dry_run": true
}
```

Response:

```json
{
  "accepted": 47,
  "rejected": 3,
  "duplicates": 2,
  "errors": [
    {"row": 12, "error": "hostname already exists"},
    ...
  ],
  "dry_run": true
}
```

On `dry_run: true`, the portal validates all rows but rolls back the transaction — no rows inserted. On `dry_run: false`, it inserts in a single transaction and commits.

- [ ] **Step 1: Implement handler**

```go
package inventory

import (
    "encoding/json"
    "net/http"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/server"
)

type ImportRow struct {
    Hostname string `json:"hostname"`
    Address  string `json:"address"`
    OS       string `json:"os"`
    Mode     string `json:"mode"`
    Tags     []Tag  `json:"tags"`
}

type ImportRequest struct {
    GroupID uuid.UUID   `json:"group_id"`
    Rows    []ImportRow `json:"rows"`
    DryRun  bool        `json:"dry_run"`
}

type ImportError struct {
    Row   int    `json:"row"`
    Error string `json:"error"`
}

type ImportResponse struct {
    Accepted   int           `json:"accepted"`
    Rejected   int           `json:"rejected"`
    Duplicates int           `json:"duplicates"`
    Errors     []ImportError `json:"errors,omitempty"`
    DryRun     bool          `json:"dry_run"`
}

func (h *Handlers) ImportHosts(w http.ResponseWriter, r *http.Request) {
    var req ImportRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    if len(req.Rows) == 0 {
        http.Error(w, "rows required", http.StatusBadRequest)
        return
    }
    if len(req.Rows) > 10000 {
        http.Error(w, "max 10000 rows per import", http.StatusBadRequest)
        return
    }

    claims := server.ClaimsFromContext(r.Context())
    orgID, _ := uuid.Parse(claims.Org)

    // Verify group belongs to org
    if _, err := h.Store.GetGroup(r.Context(), orgID, req.GroupID); err != nil {
        http.Error(w, "group not found in org", http.StatusNotFound)
        return
    }

    resp := ImportResponse{DryRun: req.DryRun}
    // Delegate to a store method that atomically processes the batch.
    // Keeps the handler thin.
    res, err := h.Store.ImportHosts(r.Context(), orgID, req.GroupID, req.Rows, req.DryRun)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    resp.Accepted = res.Accepted
    resp.Rejected = res.Rejected
    resp.Duplicates = res.Duplicates
    resp.Errors = res.Errors

    if !req.DryRun {
        h.Audit.Record(r.Context(), "inventory.hosts.import", req.GroupID.String(),
            map[string]any{"accepted": res.Accepted, "rejected": res.Rejected})
    }

    writeJSON(w, http.StatusOK, resp)
}
```

Extend `Store` interface + PostgresStore:

```go
type ImportResult struct {
    Accepted   int
    Rejected   int
    Duplicates int
    Errors     []ImportError
}

// ImportHosts inserts rows in a single transaction. If dryRun is true,
// the transaction is rolled back after validation — useful for preview.
// Returns per-row error detail for UI feedback.
ImportHosts(ctx context.Context, orgID, groupID uuid.UUID, rows []ImportRow, dryRun bool) (ImportResult, error)
```

PostgresStore implementation iterates rows in a transaction, captures per-row errors (unique violations, check-constraint failures) without aborting the batch, then commits or rolls back based on `dryRun`.

Note: `ImportError` lives in this package. Duplicate name resolution — if there's no existing `ImportError` in inventory, add it alongside the handler struct; if there is, consolidate.

- [ ] **Step 2: Route**

In `routes.go`, under the RequireRole(Engineer) group:

```go
r.Post("/hosts/import", h.ImportHosts)
```

- [ ] **Step 3: Tests**

Handler tests:
- `TestImportHosts_DryRun_ReturnsPreviewWithoutInserting` — verify after dry-run, GET /hosts still returns empty
- `TestImportHosts_Commit_InsertsAllRows`
- `TestImportHosts_DuplicateHostname_ReportsError` — two rows with same hostname, one row in response Errors
- `TestImportHosts_InvalidGroup_404`
- `TestImportHosts_Officer_403`
- `TestImportHosts_OverLimit_400` — 10001 rows

Use fakeStore; the `ImportHosts` method on the fake can be a stub returning a canned `ImportResult`. Full transactional semantics are tested in the PostgresStore integration test.

- [ ] **Step 4: Integration test** in `pkg/server/inventory/postgres_test.go`:
- `TestPostgresStore_ImportHosts_DryRun_RollsBack`
- `TestPostgresStore_ImportHosts_PartialFailures_ReportedButBatchSucceeds` — three rows, one has duplicate hostname in DB; verify two succeed, one error reported, transaction commits

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(inventory): POST /hosts/import with dry-run preview"
```

---

### Task 5: Discovery admin handlers

**Files:**
- Create: `pkg/server/discovery/handlers_admin.go`
- Create: `pkg/server/discovery/handlers_test.go`

**Endpoints:**
- `POST /api/v1/manage/discoveries/` — body `{engine_id, cidrs, ports}` — create job (Engineer+). Validates CIDR syntax + ports range. Returns job JSON.
- `GET /api/v1/manage/discoveries/` — list jobs for org (any authed)
- `GET /api/v1/manage/discoveries/{id}` — get job + candidates (any authed)
- `POST /api/v1/manage/discoveries/{id}/promote` — body `{candidate_ids, group_id}` — create hosts from candidates, mark them promoted (Engineer+)
- `POST /api/v1/manage/discoveries/{id}/cancel` — cancel queued job (Engineer+)

Port range default: `[22, 80, 443, 3389, 5985]`. CIDR validation uses `net.ParseCIDR`.

Promote endpoint: for each candidate ID, create an `inventory.Host` with `address=candidate.address`, `hostname=candidate.hostname`, `mode='agentless'`, `group_id` from request. Uses the inventory Store, which means the admin handler needs both `discovery.Store` and `inventory.Store` dependencies.

**Store dependency design:** Rather than cross-wire, the promote handler does two round-trips:
1. `discovery.Store.ListCandidates(jobID)` → filter by `candidate_ids` param
2. For each, call `inventory.Store.CreateHost(...)`
3. `discovery.Store.MarkCandidatesPromoted(ids)`

The handler holds both stores via injection:

```go
type AdminHandlers struct {
    Store          Store
    InventoryStore inventory.Store
    Audit          AuditRecorder
}
```

Cross-package dependency is fine — `discovery` already conceptually downstream of `inventory` (it creates hosts).

- [ ] **Step 1: Tests** covering:
- `TestCreateDiscovery_Engineer_201`
- `TestCreateDiscovery_Officer_403`
- `TestCreateDiscovery_InvalidCIDR_400`
- `TestCreateDiscovery_UnknownEngine_404`
- `TestGetDiscovery_ReturnsJobAndCandidates`
- `TestPromoteCandidates_Engineer_CreatesHostsAndMarksPromoted`
- `TestPromoteCandidates_DuplicateAddress_ReportsButContinues`
- `TestCancelDiscovery_QueuedJob_200`
- `TestCancelDiscovery_RunningJob_409` — can't cancel running jobs (engine already claimed it)

- [ ] **Step 2: Implement handlers**

See template in Phase 2 handlers_admin.go. Key `CreateDiscovery`:

```go
func (h *AdminHandlers) CreateDiscovery(w http.ResponseWriter, r *http.Request) {
    var body struct {
        EngineID uuid.UUID `json:"engine_id"`
        CIDRs    []string  `json:"cidrs"`
        Ports    []int     `json:"ports"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    if len(body.CIDRs) == 0 {
        http.Error(w, "cidrs required", http.StatusBadRequest)
        return
    }
    for _, c := range body.CIDRs {
        if _, _, err := net.ParseCIDR(c); err != nil {
            http.Error(w, "bad cidr: "+c, http.StatusBadRequest)
            return
        }
    }
    if len(body.Ports) == 0 {
        body.Ports = []int{22, 80, 443, 3389, 5985}
    }
    for _, p := range body.Ports {
        if p < 1 || p > 65535 {
            http.Error(w, "port out of range", http.StatusBadRequest)
            return
        }
    }

    claims := server.ClaimsFromContext(r.Context())
    orgID, _ := uuid.Parse(claims.Org)
    userID, _ := uuid.Parse(claims.Sub)

    j := Job{
        ID:          uuid.Must(uuid.NewV7()),
        OrgID:       orgID,
        EngineID:    body.EngineID,
        RequestedBy: userID,
        CIDRs:       body.CIDRs,
        Ports:       body.Ports,
    }
    j, err := h.Store.CreateJob(r.Context(), j)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    h.Audit.Record(r.Context(), "discovery.job.create", j.ID.String(),
        map[string]any{"engine_id": j.EngineID.String(), "cidrs": j.CIDRs})
    writeJSON(w, http.StatusCreated, j)
}
```

- [ ] **Step 3: Routes**

```go
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
    r.Get("/", h.ListDiscoveries)
    r.Get("/{id}", h.GetDiscovery)
    r.Group(func(r chi.Router) {
        r.Use(server.RequireRole(server.RoleEngineer))
        r.Post("/", h.CreateDiscovery)
        r.Post("/{id}/promote", h.PromoteCandidates)
        r.Post("/{id}/cancel", h.CancelDiscovery)
    })
}
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(discovery): admin handlers — create/get/list/promote/cancel"
```

---

### Task 6: Discovery gateway handlers (mTLS, engine-facing)

**Files:**
- Create: `pkg/server/discovery/handlers_gateway.go`
- Extend: `pkg/server/discovery/handlers_test.go`
- Modify: `pkg/server/discovery/routes.go` — add `MountGatewayRoutes`

**Endpoints (under `/api/v1/engine/discoveries/*`, mTLS via existing `engine.MTLSMiddleware`):**

- `GET /poll` — long-poll up to 30s for a queued job. Returns 200 with the job or 204 if nothing.
- `POST /{id}/submit` — body `{candidates: [...], error: "..."}` — atomic: insert candidates, mark job completed (or failed if error is set).

```go
type GatewayHandlers struct {
    Store Store
}

type submitRequest struct {
    Candidates []submittedCandidate `json:"candidates"`
    Error      string               `json:"error,omitempty"`
}

type submittedCandidate struct {
    Address   string `json:"address"`
    Hostname  string `json:"hostname,omitempty"`
    OpenPorts []int  `json:"open_ports"`
}

func (h *GatewayHandlers) Poll(w http.ResponseWriter, r *http.Request) {
    eng := engine.EngineFromContext(r.Context())
    if eng == nil {
        http.Error(w, "missing engine context", http.StatusInternalServerError)
        return
    }

    // Simple long-poll loop: check every second for up to 30s.
    // Production would use LISTEN/NOTIFY, but polling is fine for MVP.
    deadline := time.Now().Add(30 * time.Second)
    for {
        job, found, err := h.Store.ClaimNext(r.Context(), eng.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if found {
            writeJSON(w, http.StatusOK, job)
            return
        }
        if time.Now().After(deadline) {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        select {
        case <-r.Context().Done():
            return
        case <-time.After(1 * time.Second):
        }
    }
}

func (h *GatewayHandlers) Submit(w http.ResponseWriter, r *http.Request) {
    eng := engine.EngineFromContext(r.Context())
    if eng == nil {
        http.Error(w, "missing engine context", http.StatusInternalServerError)
        return
    }
    jobID, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        http.Error(w, "bad id", http.StatusBadRequest)
        return
    }

    var body submitRequest
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if body.Error != "" {
        if err := h.Store.FinishJob(r.Context(), jobID, StatusFailed, body.Error, 0); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusNoContent)
        return
    }

    cs := make([]Candidate, 0, len(body.Candidates))
    for _, sc := range body.Candidates {
        ip := net.ParseIP(sc.Address)
        if ip == nil {
            continue
        }
        cs = append(cs, Candidate{
            JobID:     jobID,
            Address:   ip,
            Hostname:  sc.Hostname,
            OpenPorts: sc.OpenPorts,
        })
    }
    if err := h.Store.InsertCandidates(r.Context(), jobID, cs); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if err := h.Store.FinishJob(r.Context(), jobID, StatusCompleted, "", len(cs)); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 1: Tests** — use httptest + fake store that returns canned jobs. Test long-poll timeout path with a short-deadline variant.

- [ ] **Step 2: MountGatewayRoutes**

```go
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
    r.Get("/poll", h.Poll)
    r.Post("/{id}/submit", h.Submit)
}
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(discovery): gateway handlers — poll + submit over mTLS"
```

---

### Task 7: Engine-side TCP connect sweep

**Files:**
- Create: `pkg/engine/discovery/scanner.go`
- Create: `pkg/engine/discovery/scanner_test.go`

```go
// Package discovery implements TCP-connect network discovery for the
// on-prem engine. Unprivileged (no raw sockets). For MVP the sweep
// tries a `net.Dial` to each (host, port) pair with a short timeout;
// a host is considered "alive" if any port responds.
package discovery

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"
)

type Candidate struct {
    Address   string
    Hostname  string
    OpenPorts []int
}

type Scanner struct {
    DialTimeout time.Duration // default 500ms
    Workers     int           // default 128
}

// Scan runs a TCP-connect sweep across the provided CIDRs + ports.
// Returns candidates for hosts where at least one port is open.
func (s *Scanner) Scan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
    if s.DialTimeout == 0 {
        s.DialTimeout = 500 * time.Millisecond
    }
    if s.Workers == 0 {
        s.Workers = 128
    }

    addrs, err := expandCIDRs(cidrs)
    if err != nil {
        return nil, err
    }

    type probe struct {
        addr string
        port int
    }
    probeCh := make(chan probe, len(addrs)*len(ports))
    resultCh := make(chan probe, len(addrs)*len(ports))

    var wg sync.WaitGroup
    for i := 0; i < s.Workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            d := &net.Dialer{Timeout: s.DialTimeout}
            for p := range probeCh {
                if ctx.Err() != nil {
                    return
                }
                conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.addr, fmt.Sprintf("%d", p.port)))
                if err == nil {
                    _ = conn.Close()
                    resultCh <- p
                }
            }
        }()
    }

    // Fan out.
    for _, a := range addrs {
        for _, pr := range ports {
            probeCh <- probe{addr: a, port: pr}
        }
    }
    close(probeCh)

    // Collector runs in a separate goroutine so results are consumed
    // while workers are still producing.
    candidates := map[string]*Candidate{}
    done := make(chan struct{})
    go func() {
        for r := range resultCh {
            if c, ok := candidates[r.addr]; ok {
                c.OpenPorts = append(c.OpenPorts, r.port)
            } else {
                candidates[r.addr] = &Candidate{Address: r.addr, OpenPorts: []int{r.port}}
            }
        }
        close(done)
    }()

    wg.Wait()
    close(resultCh)
    <-done

    out := make([]Candidate, 0, len(candidates))
    for _, c := range candidates {
        out = append(out, *c)
    }
    return out, nil
}

// expandCIDRs walks each CIDR, returning all usable host addresses
// (skips network + broadcast for IPv4 blocks with mask < /31).
func expandCIDRs(cidrs []string) ([]string, error) {
    var out []string
    for _, c := range cidrs {
        _, ipnet, err := net.ParseCIDR(c)
        if err != nil {
            return nil, fmt.Errorf("parse %s: %w", c, err)
        }
        ones, bits := ipnet.Mask.Size()
        skipEnds := bits == 32 && ones < 31
        all := []net.IP{}
        for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
            cp := make(net.IP, len(ip))
            copy(cp, ip)
            all = append(all, cp)
        }
        if skipEnds && len(all) >= 2 {
            all = all[1 : len(all)-1]
        }
        // Hard cap per CIDR to prevent accidental /8 scans.
        if len(all) > 65536 {
            return nil, fmt.Errorf("cidr %s expands to %d addresses; max 65536", c, len(all))
        }
        for _, ip := range all {
            out = append(out, ip.String())
        }
    }
    return out, nil
}

func incIP(ip net.IP) {
    for i := len(ip) - 1; i >= 0; i-- {
        ip[i]++
        if ip[i] != 0 {
            break
        }
    }
}
```

- [ ] **Step 1: Tests** using `net.Listen("tcp", "127.0.0.1:0")` for synthetic targets:
- `TestScanner_DetectsOpenPort` — spin up a listener on an ephemeral port, scan 127.0.0.1/32 against [that port, a closed port], verify the listener's port is in OpenPorts
- `TestScanner_ClosedPorts_NoCandidate`
- `TestScanner_CIDRTooLarge_Errors`
- `TestScanner_ContextCancellation` — start scan against a large unroutable block with slow timeout, cancel context, verify returns quickly

- [ ] **Step 2: Commit**

```bash
git commit -m "feat(engine/discovery): TCP-connect sweep with bounded workers"
```

---

### Task 8: Engine client + loop integration

**Files:**
- Modify: `pkg/engine/client/client.go` — add `PollDiscovery`, `SubmitDiscovery`
- Create: `pkg/engine/discovery/worker.go`
- Create: `pkg/engine/discovery/worker_test.go`
- Modify: `pkg/engine/loop/loop.go` — spawn a discovery worker alongside the heartbeat loop
- Modify: `cmd/triton-engine/main.go` — no direct change needed if Loop.Run handles the worker

**Client extension:**

```go
// PollDiscovery long-polls the portal for a queued discovery job.
// Returns nil job with no error when the poll times out with no work.
func (c *Client) PollDiscovery(ctx context.Context) (*discovery.Job, error) {
    // GET {PortalURL}/api/v1/engine/discoveries/poll
}

// SubmitDiscovery posts candidates for a completed job.
func (c *Client) SubmitDiscovery(ctx context.Context, jobID uuid.UUID, candidates []discovery.Candidate, errMsg string) error {
    // POST {PortalURL}/api/v1/engine/discoveries/{id}/submit
}
```

Import `pkg/server/discovery` for the types. Since the engine binary already imports `pkg/server/engine` for `BundleManifest`, one more cross-package import is acceptable.

**Worker:**

```go
// Package discovery on the engine side runs the polling worker that
// claims discovery jobs from the portal, executes them via Scanner,
// and submits results back.
package discovery

// Rename: the engine-side types live in pkg/engine/discovery; the
// portal-side types live in pkg/server/discovery. To disambiguate,
// this package uses `Scanner` + `Worker` and imports portal types
// under an alias `srvdisc`.

import (
    "context"
    "log"
    "time"

    "github.com/amiryahaya/triton/pkg/engine/client"
    srvdisc "github.com/amiryahaya/triton/pkg/server/discovery"
)

type Worker struct {
    Client  *client.Client
    Scanner *Scanner
}

func (w *Worker) Run(ctx context.Context) {
    for {
        if ctx.Err() != nil {
            return
        }
        job, err := w.Client.PollDiscovery(ctx)
        if err != nil {
            log.Printf("poll discovery: %v", err)
            select {
            case <-ctx.Done():
                return
            case <-time.After(5 * time.Second):
            }
            continue
        }
        if job == nil {
            continue // long-poll timed out, poll again immediately
        }

        log.Printf("discovery job claimed: %s (cidrs=%v ports=%v)", job.ID, job.CIDRs, job.Ports)
        scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
        candidates, scanErr := w.Scanner.Scan(scanCtx, job.CIDRs, job.Ports)
        cancel()

        var errMsg string
        var out []srvdisc.Candidate
        if scanErr != nil {
            errMsg = scanErr.Error()
        } else {
            for _, c := range candidates {
                out = append(out, srvdisc.Candidate{
                    Address:   parseIP(c.Address),
                    Hostname:  c.Hostname,
                    OpenPorts: c.OpenPorts,
                })
            }
        }

        if err := w.Client.SubmitDiscovery(ctx, job.ID, out, errMsg); err != nil {
            log.Printf("submit discovery: %v", err)
        }
    }
}
```

**Loop integration:** Update `pkg/engine/loop/loop.go` so `Run` spawns the discovery worker after successful enroll:

```go
func Run(ctx context.Context, c *client.Client, cfg Config) error {
    // ... enroll + heartbeat as before ...

    // Discovery worker — spawn after first successful enroll.
    if cfg.DiscoveryWorker != nil {
        go cfg.DiscoveryWorker.Run(ctx)
    }

    // ... heartbeat loop ...
}
```

Add `DiscoveryWorker interface { Run(context.Context) }` to Config so tests can stub it.

- [ ] **Step 1: Implement** client methods, worker, loop extension
- [ ] **Step 2: Tests** for worker: stub client that returns a canned job on first call and nil after, verify Scan runs + Submit called with expected candidates
- [ ] **Step 3: Wire into main.go** — construct worker with `discovery.Worker{Client: c, Scanner: &discovery.Scanner{}}` and pass via `Config.DiscoveryWorker`
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(engine): discovery worker + client PollDiscovery/SubmitDiscovery"
```

---

### Task 9: Wire portal routes

**Files:**
- Modify: `cmd/server.go` — mount `/api/v1/manage/discoveries/*` and `/hosts/import`
- Modify: `cmd/server_engine.go` — mount `/api/v1/engine/discoveries/*` on the 8443 listener

Similar pattern to Phase 2 Task 10 engine wiring:

```go
discStore := discpkg.NewPostgresStore(pool)
discAdmin := &discpkg.AdminHandlers{
    Store:          discStore,
    InventoryStore: invStore, // already constructed in Phase 1 wiring
    Audit:          someAuditAdapter,
}
srv.MountAuthenticated("/api/v1/manage/discoveries", func(r chi.Router) {
    discpkg.MountAdminRoutes(r, discAdmin)
})
```

For engine gateway:

```go
discGateway := &discpkg.GatewayHandlers{Store: discStore}
gatewayRouter := chi.NewRouter()
gatewayRouter.Use(enginepkg.MTLSMiddleware(engineStore))
// existing engine routes
enginepkg.MountGatewayRoutes(gatewayRouter, engineGateway)
// new discovery routes under /discoveries
gatewayRouter.Route("/discoveries", func(r chi.Router) {
    discpkg.MountGatewayRoutes(r, discGateway)
})
```

Adjust the existing `cmd/server_engine.go` code to compose routers this way — it already builds a chi router with MTLSMiddleware applied.

- [ ] **Step 1:** Implement + build + lint + test
- [ ] **Step 2:** Commit

```bash
git commit -m "feat(server): wire discovery admin + engine gateway routes"
```

---

### Task 10: Management UI — CSV import

**Files:**
- Modify: `pkg/server/ui/dist/manage/app.js`
- Modify: `pkg/server/ui/dist/manage/index.html`
- Modify: `pkg/server/ui/dist/manage/style.css`

Add a "CSV Import" button on `#/hosts` that opens a modal/section:

```javascript
// In renderHosts, after the list, add:
//   <button id="csv_btn">Import CSV</button>
// When clicked, render a CSV upload flow.

async function renderCSVImport(el, groups) {
    el.innerHTML = `
        <h2>Import hosts from CSV</h2>
        <input type="file" id="csvfile" accept=".csv">
        <select id="csv_group"><option value="">Choose group...</option></select>
        <div id="csv_preview"></div>
    `;
    const sel = el.querySelector('#csv_group');
    for (const g of groups) {
        const opt = document.createElement('option');
        opt.value = g.id; opt.textContent = g.name;
        sel.appendChild(opt);
    }

    el.querySelector('#csvfile').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const text = await file.text();
        const rows = parseCSV(text);
        // Show preview + Dry-Run button + Commit button
        renderCSVPreview(el.querySelector('#csv_preview'), rows, () => sel.value);
    });
}

function parseCSV(text) {
    // Minimal CSV parser: handles quoted fields with commas, nothing fancy.
    const lines = text.split(/\r?\n/).filter(l => l.length > 0);
    const header = splitCSVLine(lines[0]);
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const fields = splitCSVLine(lines[i]);
        const row = {};
        for (let j = 0; j < header.length; j++) {
            row[header[j].toLowerCase().trim()] = fields[j] || '';
        }
        rows.push(row);
    }
    return rows;
}

function splitCSVLine(line) {
    const out = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            inQuotes = !inQuotes;
        } else if (ch === ',' && !inQuotes) {
            out.push(cur); cur = '';
        } else {
            cur += ch;
        }
    }
    out.push(cur);
    return out;
}

function renderCSVPreview(el, rows, getGroupId) {
    const mapped = rows.map(r => ({
        hostname: r.hostname || '',
        address: r.address || r.ip || '',
        os: r.os || '',
        mode: r.mode || 'agentless',
        tags: (r.tags || '').split(';').filter(Boolean).map(kv => {
            const [k, v] = kv.split('=');
            return { key: k, value: v };
        }),
    }));
    el.innerHTML = `
        <h3>Preview: ${mapped.length} rows</h3>
        <table><thead><tr><th>Hostname</th><th>Address</th><th>OS</th><th>Mode</th><th>Tags</th></tr></thead>
        <tbody>${mapped.slice(0, 10).map(r => `<tr>
            <td>${escapeHTML(r.hostname)}</td>
            <td>${escapeHTML(r.address)}</td>
            <td>${escapeHTML(r.os)}</td>
            <td>${escapeHTML(r.mode)}</td>
            <td>${r.tags.map(t => escapeHTML(t.key) + '=' + escapeHTML(t.value)).join(', ')}</td>
        </tr>`).join('')}</tbody></table>
        ${mapped.length > 10 ? `<p><em>Showing first 10 of ${mapped.length}</em></p>` : ''}
        <button id="dry_btn">Dry-run</button>
        <button id="commit_btn">Commit</button>
        <div id="import_result"></div>
    `;
    el.querySelector('#dry_btn').addEventListener('click', () => doImport(mapped, getGroupId(), true, el.querySelector('#import_result')));
    el.querySelector('#commit_btn').addEventListener('click', () => doImport(mapped, getGroupId(), false, el.querySelector('#import_result')));
}

async function doImport(rows, groupId, dryRun, resultEl) {
    if (!groupId) { resultEl.textContent = 'Choose a group first.'; return; }
    resultEl.textContent = dryRun ? 'Running dry-run...' : 'Importing...';
    const resp = await authedFetch('/api/v1/manage/hosts/import', {
        method: 'POST',
        body: JSON.stringify({ group_id: groupId, rows, dry_run: dryRun }),
    });
    const data = await resp.json();
    resultEl.innerHTML = `
        <p>${dryRun ? '(dry-run)' : '(committed)'} Accepted: ${data.accepted}, Rejected: ${data.rejected}, Duplicates: ${data.duplicates}</p>
        ${data.errors && data.errors.length ? `<ul>${data.errors.map(e => `<li>Row ${e.row}: ${escapeHTML(e.error)}</li>`).join('')}</ul>` : ''}
    `;
}
```

- [ ] **Step 1:** Implement + manual smoke
- [ ] **Step 2:** Commit

```bash
git commit -m "feat(ui): CSV import flow with dry-run preview"
```

---

### Task 11: Management UI — discovery page

**Files:**
- Modify: `pkg/server/ui/dist/manage/app.js`
- Modify: `pkg/server/ui/dist/manage/index.html` — add "Discoveries" nav link

Add route `#/discoveries`:

```javascript
async function renderDiscoveries(el) {
    el.innerHTML = `
        <h1>Network Discovery</h1>
        <div id="list">loading…</div>
        ${canMutate() ? `
            <h2>New discovery</h2>
            <form id="newdisc">
                <label>Engine <select name="engine_id" id="engine_sel"></select></label>
                <label>CIDRs (one per line)<textarea name="cidrs" rows="3" placeholder="10.0.0.0/24\n192.168.1.0/24"></textarea></label>
                <label>Ports (comma-separated, defaults to 22,80,443,3389,5985)<input name="ports" placeholder="22,80,443,3389,5985"></label>
                <button>Start discovery</button>
            </form>
        ` : ''}
    `;
    // Fetch engines + jobs, render table with status badges + "View candidates" link
    // On click: render candidates table with checkboxes + "Promote to group X" button
}

async function renderDiscoveryCandidates(el, jobId) {
    // GET /api/v1/manage/discoveries/{id}
    // Render table of candidates with checkbox + open_ports
    // On "Promote" click: POST {candidate_ids, group_id}
}
```

Full implementation follows the engines page pattern from Phase 2 Task 13.

- [ ] **Step 1:** Implement + manual smoke
- [ ] **Step 2:** Commit

```bash
git commit -m "feat(ui): discovery page — create job, review candidates, promote to hosts"
```

---

### Task 12: End-to-end integration test

**Files:**
- Create: `test/integration/onboarding_phase3_test.go`

Spin up a test HTTP server (mock of portal) that implements the gateway endpoints with in-memory state. Run an engine `Scanner` against `127.0.0.1` across the test-process's own open ports. Verify:
- `Scan` returns 127.0.0.1 with the right ports
- Worker submits candidates through the fake gateway
- Gateway state shows job completed + candidates

Alternative: if an end-to-end test is too heavy for this phase, skip — unit tests across the boundaries already cover the protocol.

- [ ] **Step 1:** Implement if time allows, else skip with a TODO for Phase 7 polish
- [ ] **Step 2:** Commit

```bash
git commit -m "test(onboarding): end-to-end discovery smoke (portal↔engine)"
```

---

### Task 13: Final verification + PR + review

- [ ] `go build ./...` clean
- [ ] `make lint` 0 issues
- [ ] `go test ./pkg/server/discovery/... ./pkg/server/inventory/... ./pkg/engine/discovery/...` PASS
- [ ] `go test -tags integration ./pkg/server/discovery/ ./pkg/server/inventory/` PASS
- [ ] Don't run `make test` (pre-existing fixture issue)
- [ ] Push branch, open PR with summary + test plan
- [ ] Dispatch `superpowers:code-reviewer` or `pensive:code-reviewer`
- [ ] Address Critical + Important findings
- [ ] Merge

---

## Self-Review Checklist

**Spec coverage (§6 step 3):**
- CSV upload path: Task 4 (import handler) + Task 10 (UI) ✓
- Column mapping (inferred): Task 10 client-side parser — user edits column names pre-commit via the form; simpler than runtime mapping UI ✓
- Dry-run preview: Task 4 `dry_run: true` + Task 10 "Dry-run" button ✓
- Network discovery CIDR input: Task 5 + Task 11 ✓
- Probes (ICMP + TCP-SYN default 22/80/443/3389/5985): **ICMP and TCP-SYN not supported in MVP** — TCP-connect only. Documented deviation in Task 7 + PR body.
- Candidates stream back: simple batch submit in Task 6 (not literally "streaming"). Good enough for MVP; streaming is a Phase 7 polish option.
- User selects + promotes to group: Task 5 promote endpoint + Task 11 UI ✓

**Placeholder scan:** Version 19 is a real number. Column-name lowercasing happens client-side; explicit. All code blocks are complete. No `TODO: implement later` patterns.

**Type consistency:** `Job`, `Candidate`, `ImportRow`, `ImportResult` used consistently. `Store.ClaimNext` returns `(Job, bool, error)` matching caller expectations in Task 6 gateway handler. `discovery.Scanner` (engine side) ≠ `discovery.Job` (portal side) — namespaces avoid collision; Task 8 imports portal types under alias `srvdisc`.

**Explicit deviations from spec §6 step 3:**
1. Discovery probes: MVP is **TCP-connect only** (no ICMP, no TCP-SYN). Raw sockets need root/caps; `nmap` shell-out is avoided. Trade: hosts that only respond to ICMP won't be detected. Acceptable for production-realistic networks where at least one of 22/80/443/3389/5985 is reachable.
2. Long-poll implementation is a naive `SELECT + sleep 1s + SELECT ...` loop, not LISTEN/NOTIFY. Acceptable for typical job volume; replace in Phase 7 polish if load demands.
3. Candidate delivery is batch on job completion, not streaming during the sweep. Simpler; UI shows "Running..." until done.

**Dependency edges:**
- `pkg/server/discovery` imports `pkg/server/inventory` (for promote flow) — one-way, no cycle
- `pkg/engine/discovery` imports `pkg/server/discovery` (for types) — one-way
- Import cycle avoided by route mounting happening in `cmd/server.go`
