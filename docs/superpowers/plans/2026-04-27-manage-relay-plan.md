# Manage Server Relay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route all scan results (triton-agent, triton-portscan, triton-sshagent) through the
Manage Server outbox queue before delivery to the Report Server; add source attribution; remove
triton-engine and the old agent CLI.

**Architecture:** Manage Server is the single ingestion point — mTLS gateway for installed
agents, HTTPS worker endpoint for dispatched workers. Existing `manage_scan_results_queue` +
drain delivers to Report Server. triton-sshagent is a new standalone binary migrating SSH scan
logic from `pkg/engine/scanexec`.

**Tech Stack:** Go 1.25, pgx/v5, chi/v5, golang.org/x/crypto/ssh, existing
`pkg/scanner/fsadapter.SshReader`

---

## File Map

**New files:**
- `pkg/sshagent/scanner.go` — SSH scan executor (migrated from `pkg/engine/scanexec/executor.go`)
- `pkg/sshagent/client.go` — HTTP client for Manage Server worker endpoints
- `pkg/sshagent/runner.go` — `RunOne()` orchestration
- `cmd/triton-sshagent/main.go` — binary entry point

**Modified files:**
- `pkg/model/types.go` — add `ScanSource` type + `Source` field on `ScanMetadata`
- `pkg/manageserver/agents/types.go` — add `AgentCommand`, `PendingCommand` on `Agent`
- `pkg/manageserver/agents/store.go` — add `SetCommand` + `PopCommand` to `Store` interface
- `pkg/manageserver/agents/postgres.go` — implement `SetCommand` + `PopCommand`
- `pkg/manageserver/agents/handlers_gateway.go` — add `PollCommand` handler
- `pkg/manageserver/agents/handlers_admin.go` — add `DispatchCommand` handler
- `pkg/manageserver/agents/routes.go` — register two new routes
- `pkg/manageserver/config.go` — add `WorkerKey string`
- `pkg/manageserver/server.go` — wire worker route group with key auth middleware
- `pkg/manageserver/scanjobs/handlers_worker.go` — new file, `WorkerHandlers.Submit`
- `pkg/tritonagent/client.go` — update to Manage Server gateway protocol
- `pkg/tritonagent/loop.go` — update `EngineAPI` interface + remove `Register` step
- `cmd/triton-agent/config.go` — rename `engine_url` → `manage_url`
- `pkg/server/handlers.go` — add `?source` filter to findings endpoint

**DB migration:** one new migration adding `pending_command JSONB` to `manage_agents`

**Deleted (in order):**
1. `cmd/agent.go`, `cmd/agent_scheduler.go`, `cmd/agent_control_test.go`,
   `cmd/agent_resolve_test.go`, `cmd/agent_schedule_test.go`, `cmd/agent_scheduler_test.go`,
   `cmd/agent_seat_test.go`, `cmd/agent_tee_test.go`
2. `cmd/fleet_scan.go`, `cmd/fleet_scan_test.go`, `pkg/scanner/netscan/fleet/` (entire dir)
3. `pkg/engine/` (entire directory), `cmd/triton-engine/`
4. `pkg/server/engine/`, `pkg/server/scanjobs/`, `pkg/server/agentpush/`,
   `pkg/server/credentials/`, `pkg/server/discovery/`, `pkg/server/manage_enrol/`
   (engine-facing gateway packages on Report Server)

---

## Task 1: Add ScanSource to model.ScanMetadata

**Files:**
- Modify: `pkg/model/types.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/model/types_test.go` (create file if absent):

```go
func TestScanMetadata_SourceField(t *testing.T) {
    m := ScanMetadata{Source: ScanSourceAgent}
    b, err := json.Marshal(m)
    if err != nil {
        t.Fatal(err)
    }
    if !strings.Contains(string(b), `"source":"triton-agent"`) {
        t.Errorf("expected source field in JSON, got: %s", b)
    }
    var m2 ScanMetadata
    if err := json.Unmarshal(b, &m2); err != nil {
        t.Fatal(err)
    }
    if m2.Source != ScanSourceAgent {
        t.Errorf("round-trip: got %q, want %q", m2.Source, ScanSourceAgent)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/model/... -run TestScanMetadata_SourceField -v
```

Expected: `ScanSourceAgent undefined`

- [ ] **Step 3: Add ScanSource type and Source field**

In `pkg/model/types.go`, directly after the package imports block add:

```go
// ScanSource identifies which program produced a ScanResult.
type ScanSource string

const (
    ScanSourceAgent    ScanSource = "triton-agent"
    ScanSourcePortscan ScanSource = "triton-portscan"
    ScanSourceSSHAgent ScanSource = "triton-sshagent"
)
```

Then in the `ScanMetadata` struct (around line 144, after `PolicyResult`), add:

```go
    Source             ScanSource     `json:"source,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./pkg/model/... -run TestScanMetadata_SourceField -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/model/types.go pkg/model/types_test.go
git commit -m "feat(model): add ScanSource type and Source field to ScanMetadata"
```

---

## Task 2: DB migration — pending_command on manage_agents

**Files:**
- Create: `pkg/manageserver/internal/migrations/` (find the next migration number and create a new file following the existing naming convention)

- [ ] **Step 1: Find the current highest migration number**

```bash
ls pkg/manageserver/internal/migrations/ | sort | tail -5
```

Note the number (e.g. `007_...sql`). Your new file is `008_agent_pending_command.sql`.

- [ ] **Step 2: Write the migration**

Create `pkg/manageserver/internal/migrations/00N_agent_pending_command.sql`
(replace N with next number):

```sql
-- +migrate Up
ALTER TABLE manage_agents ADD COLUMN IF NOT EXISTS pending_command JSONB;

-- +migrate Down
ALTER TABLE manage_agents DROP COLUMN IF EXISTS pending_command;
```

- [ ] **Step 3: Verify migration file is picked up**

```bash
grep -r "migrations" pkg/manageserver/internal/ | grep -v "_test" | head -10
```

Confirm the migration runner reads from the same directory.

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/internal/migrations/
git commit -m "feat(manageserver): add pending_command column to manage_agents"
```

---

## Task 3: agents.Store — SetCommand + PopCommand

**Files:**
- Modify: `pkg/manageserver/agents/types.go`
- Modify: `pkg/manageserver/agents/store.go`
- Modify: `pkg/manageserver/agents/postgres.go`

- [ ] **Step 1: Write failing tests**

Add to `pkg/manageserver/agents/postgres_test.go` (find the integration test helper pattern
and add the following alongside existing tests — these are integration tests tagged
`//go:build integration`):

```go
func TestAgentStore_CommandRoundTrip(t *testing.T) {
    ctx := context.Background()
    st := newTestStore(t) // use the existing helper that sets up a clean DB

    agent := createTestAgent(t, ctx, st) // use the existing helper

    // Initially no command.
    cmd, err := st.PopCommand(ctx, agent.ID)
    if err != nil {
        t.Fatal(err)
    }
    if cmd != nil {
        t.Fatalf("expected nil command, got %+v", cmd)
    }

    // Set a command.
    want := &agents.AgentCommand{
        ScanProfile: "standard",
        JobID:       "job-abc-123",
    }
    if err := st.SetCommand(ctx, agent.ID, want); err != nil {
        t.Fatal(err)
    }

    // Pop returns the command and clears it.
    got, err := st.PopCommand(ctx, agent.ID)
    if err != nil {
        t.Fatal(err)
    }
    if got == nil {
        t.Fatal("expected command, got nil")
    }
    if got.ScanProfile != want.ScanProfile || got.JobID != want.JobID {
        t.Errorf("got %+v, want %+v", got, want)
    }

    // Second pop returns nil (idempotent clear).
    cmd2, err := st.PopCommand(ctx, agent.ID)
    if err != nil {
        t.Fatal(err)
    }
    if cmd2 != nil {
        t.Fatalf("expected nil after pop, got %+v", cmd2)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
go test -tags integration -run TestAgentStore_CommandRoundTrip ./pkg/manageserver/agents/... -v
```

Expected: `AgentCommand undefined`

- [ ] **Step 3: Add AgentCommand to types.go**

In `pkg/manageserver/agents/types.go`, add after the `Agent` struct:

```go
// AgentCommand is the pending scan command stored on an agent row.
// Set by an admin; atomically popped by the agent on next poll.
type AgentCommand struct {
    ScanProfile string `json:"scan_profile"`
    JobID       string `json:"job_id,omitempty"`
}
```

Also add `PendingCommand *AgentCommand` to the `Agent` struct:

```go
type Agent struct {
    // ... existing fields ...
    PendingCommand *AgentCommand `json:"pending_command,omitempty"`
}
```

- [ ] **Step 4: Add SetCommand + PopCommand to Store interface**

In `pkg/manageserver/agents/store.go`, add to the `Store` interface:

```go
    // SetCommand stores a pending scan command for the agent. Overwrites
    // any existing pending command. Use nil to clear.
    SetCommand(ctx context.Context, id uuid.UUID, cmd *AgentCommand) error

    // PopCommand atomically reads and clears the pending command for the
    // agent. Returns (nil, nil) if no command is pending.
    PopCommand(ctx context.Context, id uuid.UUID) (*AgentCommand, error)
```

- [ ] **Step 5: Implement in postgres.go**

Add to `pkg/manageserver/agents/postgres.go`:

```go
func (s *PostgresStore) SetCommand(ctx context.Context, id uuid.UUID, cmd *AgentCommand) error {
    var raw []byte
    if cmd != nil {
        var err error
        raw, err = json.Marshal(cmd)
        if err != nil {
            return fmt.Errorf("agents: marshal command: %w", err)
        }
    }
    _, err := s.pool.Exec(ctx,
        `UPDATE manage_agents SET pending_command = $1, updated_at = NOW() WHERE id = $2`,
        raw, id,
    )
    return err
}

func (s *PostgresStore) PopCommand(ctx context.Context, id uuid.UUID) (*AgentCommand, error) {
    var raw []byte
    err := s.pool.QueryRow(ctx,
        `UPDATE manage_agents
         SET pending_command = NULL, updated_at = NOW()
         WHERE id = $1
         RETURNING pending_command`,
        id,
    ).Scan(&raw)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, ErrNotFound
        }
        return nil, fmt.Errorf("agents: pop command: %w", err)
    }
    if raw == nil {
        return nil, nil
    }
    var cmd AgentCommand
    if err := json.Unmarshal(raw, &cmd); err != nil {
        return nil, fmt.Errorf("agents: unmarshal command: %w", err)
    }
    return &cmd, nil
}
```

Make sure `encoding/json`, `errors`, `fmt`, and `github.com/jackc/pgx/v5` are imported.

- [ ] **Step 6: Run tests to verify they pass**

```bash
go test -tags integration -run TestAgentStore_CommandRoundTrip ./pkg/manageserver/agents/... -v
```

Expected: PASS

- [ ] **Step 7: Run full agents unit tests**

```bash
go test ./pkg/manageserver/agents/... -v
```

Expected: all pass (non-integration tests use in-memory stub — update stub to add no-op
`SetCommand` and `PopCommand` methods if a fake Store exists in the test helpers).

- [ ] **Step 8: Commit**

```bash
git add pkg/manageserver/agents/
git commit -m "feat(agents): add SetCommand/PopCommand for pending scan dispatch"
```

---

## Task 4: Gateway GET /agents/commands + Admin POST /admin/agents/{id}/commands

**Files:**
- Modify: `pkg/manageserver/agents/handlers_gateway.go`
- Modify: `pkg/manageserver/agents/handlers_admin.go`
- Modify: `pkg/manageserver/agents/routes.go`

- [ ] **Step 1: Write failing tests**

In `pkg/manageserver/agents/handlers_gateway_test.go` (find the existing gateway test file
and add alongside existing tests):

```go
func TestGateway_PollCommand_NoPending(t *testing.T) {
    h, _, agentID := newTestGateway(t) // use existing helper
    w := httptest.NewRecorder()
    r := gatewayRequest(t, agentID, http.MethodGet, "/agents/commands", nil)
    h.PollCommand(w, r)
    if w.Code != http.StatusNoContent {
        t.Errorf("want 204, got %d: %s", w.Code, w.Body.String())
    }
}

func TestGateway_PollCommand_WithPending(t *testing.T) {
    h, store, agentID := newTestGateway(t)
    _ = store.SetCommand(context.Background(), agentID, &AgentCommand{
        ScanProfile: "comprehensive",
        JobID:       "job-xyz",
    })
    w := httptest.NewRecorder()
    r := gatewayRequest(t, agentID, http.MethodGet, "/agents/commands", nil)
    h.PollCommand(w, r)
    if w.Code != http.StatusOK {
        t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
    }
    var got AgentCommand
    if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
        t.Fatal(err)
    }
    if got.ScanProfile != "comprehensive" || got.JobID != "job-xyz" {
        t.Errorf("unexpected command: %+v", got)
    }
    // Verify command was cleared.
    cmd, _ := store.PopCommand(context.Background(), agentID)
    if cmd != nil {
        t.Error("command should be cleared after poll")
    }
}
```

Also add an admin test in `pkg/manageserver/agents/handlers_admin_test.go`:

```go
func TestAdminHandlers_DispatchCommand(t *testing.T) {
    h, store := newTestAdminHandlers(t) // use existing helper
    agent := createTestAgentRow(t, store)

    body := `{"scan_profile":"standard"}`
    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodPost, "/admin/agents/"+agent.ID.String()+"/commands",
        strings.NewReader(body))
    r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, chiCtxWithID(agent.ID)))
    h.DispatchCommand(w, r)
    if w.Code != http.StatusAccepted {
        t.Errorf("want 202, got %d: %s", w.Code, w.Body.String())
    }

    cmd, err := store.PopCommand(context.Background(), agent.ID)
    if err != nil || cmd == nil || cmd.ScanProfile != "standard" {
        t.Errorf("expected stored command, got %v, %v", cmd, err)
    }
}
```

- [ ] **Step 2: Run to verify failures**

```bash
go test ./pkg/manageserver/agents/... -run "TestGateway_PollCommand|TestAdminHandlers_DispatchCommand" -v
```

Expected: `PollCommand undefined` and `DispatchCommand undefined`

- [ ] **Step 3: Add PollCommand to GatewayHandlers**

In `pkg/manageserver/agents/handlers_gateway.go`, add after `IngestFindings`:

```go
// PollCommand handles GET /agents/commands. Returns the pending scan
// command for this agent (200 + JSON body) or 204 if none is queued.
// Atomically clears the command so re-polls return 204.
func (h *GatewayHandlers) PollCommand(w http.ResponseWriter, r *http.Request) {
    agentID, err := agentIDFromCN(r.Context())
    if err != nil {
        http.Error(w, "bad cn", http.StatusUnauthorized)
        return
    }
    cmd, err := h.AgentStore.PopCommand(r.Context(), agentID)
    if err != nil {
        if errors.Is(err, ErrNotFound) {
            http.Error(w, "unknown agent", http.StatusUnauthorized)
            return
        }
        log.Printf("manageserver/agents: poll-command: %v", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    if cmd == nil {
        w.WriteHeader(http.StatusNoContent)
        return
    }
    writeJSON(w, http.StatusOK, cmd)
}
```

- [ ] **Step 4: Add DispatchCommand to AdminHandlers**

In `pkg/manageserver/agents/handlers_admin.go`, add after the `Revoke` handler:

```go
// DispatchCommand handles POST /admin/agents/{id}/commands. Sets a
// pending scan command on the agent row. The agent picks it up on
// its next GET /agents/commands poll.
func (h *AdminHandlers) DispatchCommand(w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        http.Error(w, "bad id", http.StatusBadRequest)
        return
    }
    var cmd AgentCommand
    if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&cmd); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }
    if cmd.ScanProfile == "" {
        http.Error(w, "scan_profile required", http.StatusBadRequest)
        return
    }
    if err := h.AgentStore.SetCommand(r.Context(), id, &cmd); err != nil {
        if errors.Is(err, ErrNotFound) {
            http.Error(w, "agent not found", http.StatusNotFound)
            return
        }
        log.Printf("manageserver/agents: dispatch-command: %v", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusAccepted)
}
```

Ensure `io` is imported in `handlers_admin.go`.

- [ ] **Step 5: Register the two new routes**

In `pkg/manageserver/agents/routes.go`, update `MountGatewayRoutes`:

```go
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
    r.Post("/agents/phone-home", h.PhoneHome)
    r.Get("/agents/commands", h.PollCommand)   // ← new
    r.Post("/agents/scans", h.IngestScan)
    r.Post("/agents/findings", h.IngestFindings)
    r.Post("/agents/rotate-cert", h.RotateCert)
}
```

Update `MountAdminRoutes`:

```go
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
    r.Get("/", h.List)
    r.Get("/{id}", h.Get)
    r.Delete("/{id}", h.Revoke)
    r.Post("/{id}/commands", h.DispatchCommand)  // ← new
}
```

- [ ] **Step 6: Run tests**

```bash
go test ./pkg/manageserver/agents/... -run "TestGateway_PollCommand|TestAdminHandlers_DispatchCommand" -v
```

Expected: PASS

- [ ] **Step 7: Run full agents test suite**

```bash
go test ./pkg/manageserver/agents/... -v
```

Expected: all pass

- [ ] **Step 8: Commit**

```bash
git add pkg/manageserver/agents/
git commit -m "feat(agents): add PollCommand gateway + DispatchCommand admin endpoints"
```

---

## Task 5: Worker auth middleware + job submit endpoint on Manage Server

**Files:**
- Modify: `pkg/manageserver/config.go`
- Modify: `pkg/manageserver/server.go`
- Create: `pkg/manageserver/scanjobs/handlers_worker.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/manageserver/scanjobs/handlers_worker_test.go`:

```go
package scanjobs_test

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
    "github.com/amiryahaya/triton/pkg/model"
)

func TestWorkerHandlers_Submit_OK(t *testing.T) {
    jobID := uuid.New()
    store := &fakeWorkerJobStore{jobs: map[uuid.UUID]bool{jobID: true}}
    enqueuer := &fakeEnqueuer{}
    h := scanjobs.NewWorkerHandlers("secret-key", store, enqueuer)

    scan := &model.ScanResult{
        ID: uuid.NewString(),
        Metadata: model.ScanMetadata{
            Hostname: "host1",
            Source:   model.ScanSourcePortscan,
        },
    }
    body, _ := json.Marshal(scan)

    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodPost, "/worker/jobs/"+jobID.String()+"/submit",
        bytes.NewReader(body))
    r.Header.Set("X-Worker-Key", "secret-key")
    r.Header.Set("Content-Type", "application/json")
    rctx := chi.NewRouteContext()
    rctx.URLParams.Add("id", jobID.String())
    r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

    h.Submit(w, r)

    if w.Code != http.StatusAccepted {
        t.Errorf("want 202, got %d: %s", w.Code, w.Body.String())
    }
    if !store.completed[jobID] {
        t.Error("expected job to be marked complete")
    }
    if len(enqueuer.calls) != 1 {
        t.Errorf("expected 1 enqueue call, got %d", len(enqueuer.calls))
    }
    if enqueuer.calls[0].Scan.Metadata.Source != model.ScanSourcePortscan {
        t.Errorf("source not preserved: %v", enqueuer.calls[0].Scan.Metadata.Source)
    }
}

func TestWorkerHandlers_Submit_WrongKey(t *testing.T) {
    store := &fakeWorkerJobStore{}
    enqueuer := &fakeEnqueuer{}
    h := scanjobs.NewWorkerHandlers("correct-key", store, enqueuer)

    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodPost, "/worker/jobs/"+uuid.NewString()+"/submit",
        bytes.NewReader([]byte(`{}`)))
    r.Header.Set("X-Worker-Key", "wrong-key")

    h.Submit(w, r)

    if w.Code != http.StatusUnauthorized {
        t.Errorf("want 401, got %d", w.Code)
    }
}

// fakeWorkerJobStore implements the WorkerJobCompleter interface.
type fakeWorkerJobStore struct {
    jobs      map[uuid.UUID]bool
    completed map[uuid.UUID]bool
}

func (f *fakeWorkerJobStore) Complete(ctx context.Context, id uuid.UUID) error {
    if f.completed == nil {
        f.completed = make(map[uuid.UUID]bool)
    }
    f.completed[id] = true
    return nil
}

// fakeEnqueuer implements scanresults.ResultEnqueuer.
type fakeEnqueuer struct {
    calls []enqueueCall
}

type enqueueCall struct {
    JobID      uuid.UUID
    SourceType string
    SourceID   uuid.UUID
    Scan       *model.ScanResult
}

func (f *fakeEnqueuer) Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string,
    sourceID uuid.UUID, scan *model.ScanResult) error {
    f.calls = append(f.calls, enqueueCall{JobID: scanJobID, SourceType: sourceType,
        SourceID: sourceID, Scan: scan})
    return nil
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestWorkerHandlers -v
```

Expected: `NewWorkerHandlers undefined`

- [ ] **Step 3: Add WorkerKey to config**

In `pkg/manageserver/config.go`, add to the `Config` struct:

```go
    // WorkerKey is the shared secret dispatched workers (triton-portscan,
    // triton-sshagent) must send in the X-Worker-Key header.
    // Env: TRITON_MANAGE_WORKER_KEY
    WorkerKey string
```

- [ ] **Step 4: Create handlers_worker.go**

Create `pkg/manageserver/scanjobs/handlers_worker.go`:

```go
package scanjobs

import (
    "context"
    "encoding/json"
    "io"
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/model"
)

const maxWorkerBody = 100 << 20 // 100 MB

// WorkerJobCompleter is the subset of Store the worker handler needs.
type WorkerJobCompleter interface {
    Complete(ctx context.Context, id uuid.UUID) error
}

// WorkerResultEnqueuer mirrors scanresults.ResultEnqueuer to avoid import cycles.
type WorkerResultEnqueuer interface {
    Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string,
        sourceID uuid.UUID, scan *model.ScanResult) error
}

// WorkerHandlers serves POST /api/v1/worker/jobs/{id}/submit.
type WorkerHandlers struct {
    workerKey string
    jobs      WorkerJobCompleter
    results   WorkerResultEnqueuer
}

// NewWorkerHandlers returns a WorkerHandlers. workerKey must be non-empty.
func NewWorkerHandlers(workerKey string, jobs WorkerJobCompleter, results WorkerResultEnqueuer) *WorkerHandlers {
    return &WorkerHandlers{workerKey: workerKey, jobs: jobs, results: results}
}

// Submit handles POST /api/v1/worker/jobs/{id}/submit.
// The worker sends a completed ScanResult; the handler marks the job
// done and enqueues the result for the drain → Report Server pipeline.
func (h *WorkerHandlers) Submit(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-Worker-Key") != h.workerKey {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    jobID, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        http.Error(w, "bad job id", http.StatusBadRequest)
        return
    }
    body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWorkerBody))
    if err != nil {
        http.Error(w, "read body", http.StatusBadRequest)
        return
    }
    var scan model.ScanResult
    if err := json.Unmarshal(body, &scan); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }
    if err := h.jobs.Complete(r.Context(), jobID); err != nil {
        log.Printf("scanjobs: worker submit: complete job %s: %v", jobID, err)
        http.Error(w, "complete job failed", http.StatusInternalServerError)
        return
    }
    if err := h.results.Enqueue(r.Context(), jobID, "worker_submit", jobID, &scan); err != nil {
        log.Printf("scanjobs: worker submit: enqueue %s: %v", jobID, err)
        http.Error(w, "enqueue failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusAccepted)
}
```

- [ ] **Step 5: Wire the route in server.go**

In `pkg/manageserver/server.go`, find where the `WorkerKey` is read from env (in `main.go`
or `cmd/manageserver/main.go`) and pass it through `Config`. Then in `buildRouter()` add:

```go
if s.cfg.WorkerKey != "" {
    workerH := scanjobs.NewWorkerHandlers(s.cfg.WorkerKey, s.jobsStore, s.resultsStore)
    r.Route("/api/v1/worker/jobs", func(r chi.Router) {
        r.Post("/{id}/submit", workerH.Submit)
    })
}
```

Place this after the existing `/api/v1/admin` block. Ensure `s.jobsStore` and
`s.resultsStore` are the already-wired stores. Find these by grepping for how
`scanjobs.Store` and `scanresults.Store` are currently wired into the server struct.

Also update `cmd/manageserver/main.go` to read the env var:

```go
cfg.WorkerKey = os.Getenv("TRITON_MANAGE_WORKER_KEY")
```

- [ ] **Step 6: Run tests**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestWorkerHandlers -v
```

Expected: PASS

- [ ] **Step 7: Run full suite**

```bash
go test ./pkg/manageserver/... -v
```

Expected: all pass

- [ ] **Step 8: Commit**

```bash
git add pkg/manageserver/config.go pkg/manageserver/server.go \
        pkg/manageserver/scanjobs/handlers_worker.go \
        pkg/manageserver/scanjobs/handlers_worker_test.go \
        cmd/manageserver/main.go
git commit -m "feat(manageserver): add worker key auth + POST /worker/jobs/{id}/submit"
```

---

## Task 6: pkg/sshagent — SSH scan executor

**Files:**
- Create: `pkg/sshagent/scanner.go`
- Create: `pkg/sshagent/scanner_test.go`

The core logic is migrated from `pkg/engine/scanexec/executor.go`. Read that file before
implementing to understand the SSH dial + SshReader pattern.

- [ ] **Step 1: Read the source to migrate**

```bash
cat pkg/engine/scanexec/executor.go
```

Key pattern to preserve:
1. Dial SSH using `golang.org/x/crypto/ssh`
2. Wrap connection in `fsadapter.SshReader` (via `CommandExecutor`)
3. Call `scanner.New(cfg)` + `eng.RegisterDefaultModules()` + `eng.Scan(ctx, progressCh)`

- [ ] **Step 2: Write failing test**

Create `pkg/sshagent/scanner_test.go`:

```go
package sshagent_test

import (
    "context"
    "testing"

    "github.com/amiryahaya/triton/pkg/sshagent"
)

func TestScanner_Interface(t *testing.T) {
    // Compile-time check: *Scanner implements the Scanner interface.
    var _ sshagent.Scanner = (*sshagent.SSHScanner)(nil)
}
```

- [ ] **Step 3: Run to verify failure**

```bash
go test ./pkg/sshagent/... -run TestScanner_Interface -v
```

Expected: package not found

- [ ] **Step 4: Create pkg/sshagent/scanner.go**

```go
// Package sshagent implements SSH-agentless scanning: it SSHes into a
// remote host and runs the full pkg/scanner engine via fsadapter.SshReader.
package sshagent

import (
    "context"
    "fmt"
    "net"
    "strconv"
    "time"

    "golang.org/x/crypto/ssh"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// Credentials holds SSH authentication material for a target host.
type Credentials struct {
    Username   string
    Password   string // empty if using PrivateKey
    PrivateKey []byte // PEM-encoded; empty if using Password
    Port       int    // default 22
}

// Scanner is the pluggable scan interface. *SSHScanner implements it.
type Scanner interface {
    Scan(ctx context.Context, hostname, address string, creds Credentials, profile string) (*model.ScanResult, error)
}

// SSHScanner dials a remote host over SSH and runs the pkg/scanner
// engine against the remote filesystem via fsadapter.SshReader.
type SSHScanner struct {
    DialTimeout time.Duration
}

// NewSSHScanner returns an SSHScanner with a 30-second dial timeout.
func NewSSHScanner() *SSHScanner {
    return &SSHScanner{DialTimeout: 30 * time.Second}
}

// Scan connects to address via SSH, authenticates with creds, and runs
// a full pkg/scanner scan using the given profile. Returns a ScanResult
// with Source = model.ScanSourceSSHAgent set.
func (s *SSHScanner) Scan(ctx context.Context, hostname, address string, creds Credentials, profile string) (*model.ScanResult, error) {
    cfg, err := buildSSHConfig(creds)
    if err != nil {
        return nil, fmt.Errorf("sshagent: build ssh config: %w", err)
    }

    port := creds.Port
    if port == 0 {
        port = 22
    }
    addr := net.JoinHostPort(address, strconv.Itoa(port))

    dialCtx, cancel := context.WithTimeout(ctx, s.DialTimeout)
    defer cancel()

    conn, err := dialSSH(dialCtx, addr, cfg)
    if err != nil {
        return nil, fmt.Errorf("sshagent: dial %s: %w", addr, err)
    }
    defer conn.Close()

    reader := fsadapter.NewSshReader(sshCommandExecutor{conn})

    result, err := runScanner(ctx, profile, hostname, reader)
    if err != nil {
        return nil, err
    }
    result.Metadata.Source = model.ScanSourceSSHAgent
    return result, nil
}

// dialSSH dials address with cfg. Extracted so tests can stub it.
var dialSSH = func(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
    // ssh.Dial does not respect context cancellation natively; we use a
    // background dial with a timeout baked into cfg.Timeout.
    conn, err := ssh.Dial("tcp", addr, cfg)
    if err != nil {
        return nil, err
    }
    return conn, nil
}

// runScanner builds and runs the scanner engine against reader.
// Extracted so tests can stub it.
var runScanner = func(ctx context.Context, profile, hostname string, reader fsadapter.FileReader) (*model.ScanResult, error) {
    cfg := scannerconfig.Load(profile)
    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()
    eng.SetHostname(hostname)
    eng.SetFileReader(reader)

    progressCh := make(chan scanner.Progress, 32)
    go func() {
        for range progressCh {
        }
    }()

    result := eng.Scan(ctx, progressCh)
    return result, nil
}

func buildSSHConfig(creds Credentials) (*ssh.ClientConfig, error) {
    var authMethods []ssh.AuthMethod
    if len(creds.PrivateKey) > 0 {
        signer, err := ssh.ParsePrivateKey(creds.PrivateKey)
        if err != nil {
            return nil, fmt.Errorf("parse private key: %w", err)
        }
        authMethods = append(authMethods, ssh.PublicKeys(signer))
    } else if creds.Password != "" {
        authMethods = append(authMethods, ssh.Password(creds.Password))
    }
    return &ssh.ClientConfig{
        User:            creds.Username,
        Auth:            authMethods,
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: known_hosts in follow-up
        Timeout:         30 * time.Second,
    }, nil
}

// sshCommandExecutor wraps *ssh.Client to implement fsadapter.CommandExecutor.
type sshCommandExecutor struct{ conn *ssh.Client }

func (e sshCommandExecutor) Run(ctx context.Context, command string) (string, error) {
    sess, err := e.conn.NewSession()
    if err != nil {
        return "", fmt.Errorf("new ssh session: %w", err)
    }
    defer sess.Close()
    out, err := sess.CombinedOutput(command)
    return string(out), err
}

func (e sshCommandExecutor) Close() error { return e.conn.Close() }
```

> **Note:** `eng.SetHostname()` and `eng.SetFileReader()` may not exist on the scanner.Engine
> yet. Check `pkg/scanner/engine.go` — if they don't exist, add them in this task. The engine
> already accepts a `FileReader` via its scan target; verify the exact API by reading
> `pkg/scanner/engine.go` and `pkg/engine/scanexec/executor.go` carefully before implementing.

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/sshagent/... -v
```

Expected: PASS (compile-time interface check passes)

- [ ] **Step 6: Commit**

```bash
git add pkg/sshagent/
git commit -m "feat(sshagent): add SSHScanner wrapping pkg/scanner + fsadapter.SshReader"
```

---

## Task 7: pkg/sshagent — HTTP client + RunOne

**Files:**
- Create: `pkg/sshagent/client.go`
- Create: `pkg/sshagent/runner.go`
- Create: `pkg/sshagent/runner_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/sshagent/runner_test.go`:

```go
package sshagent_test

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/sshagent"
)

func TestRunOne_SubmitsResult(t *testing.T) {
    jobID := uuid.New()

    // Stub Manage Server.
    var submitted []byte
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/v1/worker/jobs/" + jobID.String():
            json.NewEncoder(w).Encode(sshagent.JobPayload{
                ID:          jobID.String(),
                ScanProfile: "standard",
                TargetHost:  "192.168.1.1",
                Hostname:    "server1",
                Credentials: sshagent.CredPayload{Username: "root", Password: "pass"},
            })
        case "/api/v1/worker/jobs/" + jobID.String() + "/submit":
            submitted, _ = io.ReadAll(r.Body)
            w.WriteHeader(http.StatusAccepted)
        default:
            http.NotFound(w, r)
        }
    }))
    defer srv.Close()

    mc := sshagent.NewClient(srv.URL, "worker-key")

    // Stub scanner that returns a fixed result.
    stubScanner := &stubSSHScanner{result: &model.ScanResult{
        ID: uuid.NewString(),
        Metadata: model.ScanMetadata{Hostname: "server1"},
    }}

    err := sshagent.RunOne(context.Background(), jobID, mc, stubScanner)
    if err != nil {
        t.Fatal(err)
    }
    if len(submitted) == 0 {
        t.Error("expected result to be submitted")
    }
    var got model.ScanResult
    if err := json.Unmarshal(submitted, &got); err != nil {
        t.Errorf("submitted body is not valid ScanResult: %v", err)
    }
}

type stubSSHScanner struct{ result *model.ScanResult }

func (s *stubSSHScanner) Scan(_ context.Context, _, _ string, _ sshagent.Credentials, _ string) (*model.ScanResult, error) {
    return s.result, nil
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./pkg/sshagent/... -run TestRunOne -v
```

Expected: `NewClient undefined`, `RunOne undefined`, `JobPayload undefined`

- [ ] **Step 3: Create client.go**

Create `pkg/sshagent/client.go`:

```go
package sshagent

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/model"
)

const maxResponseBody = 1 << 20 // 1 MB

// CredPayload is the credential section of a job response.
type CredPayload struct {
    Username   string `json:"username"`
    Password   string `json:"password,omitempty"`
    PrivateKey []byte `json:"private_key,omitempty"`
    Port       int    `json:"port,omitempty"`
}

// JobPayload is the job description returned by GET /api/v1/worker/jobs/{id}.
type JobPayload struct {
    ID          string      `json:"id"`
    ScanProfile string      `json:"scan_profile"`
    TargetHost  string      `json:"target_host"`
    Hostname    string      `json:"hostname"`
    Credentials CredPayload `json:"credentials"`
}

// Client is the HTTP client for the Manage Server worker API.
type Client struct {
    baseURL   string
    workerKey string
    http      *http.Client
}

// NewClient returns a Client pointed at manageURL with the given worker key.
func NewClient(manageURL, workerKey string) *Client {
    return &Client{
        baseURL:   manageURL,
        workerKey: workerKey,
        http:      &http.Client{Timeout: 60 * time.Second},
    }
}

// GetJob fetches the job description for jobID.
func (c *Client) GetJob(ctx context.Context, jobID uuid.UUID) (*JobPayload, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet,
        c.baseURL+"/api/v1/worker/jobs/"+jobID.String(), http.NoBody)
    if err != nil {
        return nil, err
    }
    req.Header.Set("X-Worker-Key", c.workerKey)
    resp, err := c.http.Do(req)
    if err != nil {
        return nil, err
    }
    defer drainClose(resp)
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("get job: HTTP %d", resp.StatusCode)
    }
    var p JobPayload
    if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&p); err != nil {
        return nil, fmt.Errorf("decode job: %w", err)
    }
    return &p, nil
}

// SubmitResult posts the completed ScanResult to the Manage Server.
func (c *Client) SubmitResult(ctx context.Context, jobID uuid.UUID, result *model.ScanResult) error {
    raw, err := json.Marshal(result)
    if err != nil {
        return fmt.Errorf("marshal result: %w", err)
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        c.baseURL+"/api/v1/worker/jobs/"+jobID.String()+"/submit",
        bytes.NewReader(raw))
    if err != nil {
        return err
    }
    req.Header.Set("X-Worker-Key", c.workerKey)
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.http.Do(req)
    if err != nil {
        return err
    }
    defer drainClose(resp)
    if resp.StatusCode != http.StatusAccepted {
        return fmt.Errorf("submit result: HTTP %d", resp.StatusCode)
    }
    return nil
}

func drainClose(resp *http.Response) {
    _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
    _ = resp.Body.Close()
}
```

- [ ] **Step 4: Create runner.go**

Create `pkg/sshagent/runner.go`:

```go
package sshagent

import (
    "context"
    "fmt"

    "github.com/google/uuid"
)

// ManageClient is the interface RunOne needs from Client.
type ManageClient interface {
    GetJob(ctx context.Context, jobID uuid.UUID) (*JobPayload, error)
    SubmitResult(ctx context.Context, jobID uuid.UUID, result *model.ScanResult) error
}

// RunOne fetches job jobID from the Manage Server, runs the SSH scan,
// and submits the result. It is the entry point for the triton-sshagent binary.
func RunOne(ctx context.Context, jobID uuid.UUID, mc ManageClient, sc Scanner) error {
    job, err := mc.GetJob(ctx, jobID)
    if err != nil {
        return fmt.Errorf("sshagent: get job: %w", err)
    }

    creds := Credentials{
        Username:   job.Credentials.Username,
        Password:   job.Credentials.Password,
        PrivateKey: job.Credentials.PrivateKey,
        Port:       job.Credentials.Port,
    }

    result, err := sc.Scan(ctx, job.Hostname, job.TargetHost, creds, job.ScanProfile)
    if err != nil {
        return fmt.Errorf("sshagent: scan: %w", err)
    }

    if err := mc.SubmitResult(ctx, jobID, result); err != nil {
        return fmt.Errorf("sshagent: submit: %w", err)
    }
    return nil
}
```

Add the missing `model` import to `runner.go`:

```go
import (
    "context"
    "fmt"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/model"
)
```

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/sshagent/... -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/sshagent/
git commit -m "feat(sshagent): add Client + RunOne for Manage Server worker protocol"
```

---

## Task 8: cmd/triton-sshagent binary

**Files:**
- Create: `cmd/triton-sshagent/main.go`

- [ ] **Step 1: Create main.go**

```go
// Command triton-sshagent is a dispatched worker binary. It claims one
// SSH agentless scan job from the Manage Server, SSHes into the target
// host, runs the full Triton scanner via fsadapter.SshReader, and
// submits the result back to the Manage Server. Exits 0 on success.
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/sshagent"
)

func main() {
    if err := run(); err != nil {
        log.Printf("triton-sshagent: %v", err)
        os.Exit(1)
    }
}

func run() error {
    manageURL := flag.String("manage-url", "", "Manage Server base URL (required)")
    jobIDStr := flag.String("job-id", "", "Job UUID to execute (required)")
    flag.Parse()

    workerKey := os.Getenv("TRITON_WORKER_KEY")

    if *manageURL == "" {
        log.Fatal("--manage-url is required")
    }
    if workerKey == "" {
        log.Fatal("TRITON_WORKER_KEY env var is required")
    }
    jobID, err := uuid.Parse(*jobIDStr)
    if err != nil {
        log.Fatalf("invalid --job-id: %v", err)
    }

    mc := sshagent.NewClient(*manageURL, workerKey)
    sc := sshagent.NewSSHScanner()

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
    defer stop()

    return sshagent.RunOne(ctx, jobID, mc, sc)
}
```

- [ ] **Step 2: Build to verify compilation**

```bash
go build ./cmd/triton-sshagent/
```

Expected: no errors, binary created

- [ ] **Step 3: Commit**

```bash
git add cmd/triton-sshagent/
git commit -m "feat(triton-sshagent): add standalone SSH agentless scan worker binary"
```

---

## Task 9: Update triton-agent protocol to Manage Server

**Files:**
- Modify: `pkg/tritonagent/client.go`
- Modify: `pkg/tritonagent/loop.go`
- Modify: `cmd/triton-agent/config.go`

- [ ] **Step 1: Read current loop tests**

```bash
cat pkg/tritonagent/loop_test.go
```

Note which methods are stubbed via the `EngineAPI` interface — you will rename/update them.

- [ ] **Step 2: Update client.go**

Replace the contents of `pkg/tritonagent/client.go` with the updated version below. Key
changes: remove `Register`, change endpoint paths, add `JobID` to scan command, update
`SubmitFindings` to include `job_id` + `source` in the body:

```go
package tritonagent

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)

// ErrUnauthorized is returned when the Manage Server responds HTTP 401.
var ErrUnauthorized = errors.New("unauthorized")

// AgentCommand describes a scan the agent should execute, received from
// the Manage Server gateway via GET /agents/commands.
type AgentCommand struct {
    ScanProfile string `json:"scan_profile"`
    JobID       string `json:"job_id,omitempty"`
    Paths       []string `json:"paths,omitempty"`
}

// Client is the mTLS HTTP client that talks to the Manage Server agent gateway.
type Client struct {
    ManageURL string
    HostID    string
    HTTP      *http.Client
}

// NewClient creates a Client configured with mTLS credentials.
// certPath/keyPath: agent's per-host cert+key.
// caPath: Manage Server's CA cert (used as trust root).
func NewClient(manageURL, certPath, keyPath, caPath, hostID string) (*Client, error) {
    // mTLS setup — identical to before, only variable names change.
    cert, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        return nil, fmt.Errorf("load agent cert: %w", err)
    }
    caCert, err := os.ReadFile(caPath)
    if err != nil {
        return nil, fmt.Errorf("load manage CA: %w", err)
    }
    pool := x509.NewCertPool()
    if !pool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("no valid certificates in CA file %s", caPath)
    }
    tlsCfg := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      pool,
        MinVersion:   tls.VersionTLS12,
    }
    return &Client{
        ManageURL: manageURL,
        HostID:    hostID,
        HTTP: &http.Client{
            Transport: &http.Transport{TLSClientConfig: tlsCfg},
            Timeout:   45 * time.Second,
        },
    }, nil
}

// Heartbeat calls POST /agents/phone-home on the Manage Server gateway.
func (c *Client) Heartbeat(ctx context.Context) error {
    return c.postJSON(ctx, "/agents/phone-home", nil)
}

// PollCommand calls GET /agents/commands. Returns nil if no command is
// pending (204). Returns an AgentCommand on 200.
func (c *Client) PollCommand(ctx context.Context) (*AgentCommand, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", c.ManageURL+"/agents/commands", http.NoBody)
    if err != nil {
        return nil, err
    }
    resp, err := c.HTTP.Do(req)
    if err != nil {
        return nil, err
    }
    defer func() { _ = resp.Body.Close() }()
    switch resp.StatusCode {
    case http.StatusNoContent:
        return nil, nil
    case http.StatusOK:
        var cmd AgentCommand
        if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
            return nil, err
        }
        return &cmd, nil
    case http.StatusUnauthorized:
        return nil, ErrUnauthorized
    default:
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
        return nil, fmt.Errorf("poll command: HTTP %d: %s", resp.StatusCode, b)
    }
}

// SubmitScan calls POST /agents/scans with the scan result JSON.
// jobID is included in the body so the server can correlate results
// with the originating command (empty string is fine for unscheduled scans).
func (c *Client) SubmitScan(ctx context.Context, jobID string, scanResult []byte) error {
    // Wrap the raw ScanResult JSON in an envelope with the job ID.
    type envelope struct {
        JobID      string          `json:"job_id,omitempty"`
        ScanResult json.RawMessage `json:"scan_result"`
    }
    raw, err := json.Marshal(envelope{JobID: jobID, ScanResult: json.RawMessage(scanResult)})
    if err != nil {
        return err
    }
    req, err := http.NewRequestWithContext(ctx, "POST", c.ManageURL+"/agents/scans",
        bytes.NewReader(raw))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.HTTP.Do(req)
    if err != nil {
        return err
    }
    defer func() { _ = resp.Body.Close() }()
    _, _ = io.Copy(io.Discard, resp.Body)
    if resp.StatusCode != http.StatusAccepted {
        return fmt.Errorf("submit scan: HTTP %d", resp.StatusCode)
    }
    return nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any) error {
    var bodyReader io.Reader
    if body != nil {
        data, err := json.Marshal(body)
        if err != nil {
            return err
        }
        bodyReader = bytes.NewReader(data)
    }
    req, err := http.NewRequestWithContext(ctx, "POST", c.ManageURL+path, bodyReader)
    if err != nil {
        return err
    }
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    resp, err := c.HTTP.Do(req)
    if err != nil {
        return err
    }
    defer func() { _ = resp.Body.Close() }()
    _, _ = io.Copy(io.Discard, resp.Body)
    if resp.StatusCode == http.StatusUnauthorized {
        return fmt.Errorf("%s: %w", path, ErrUnauthorized)
    }
    if resp.StatusCode >= 400 {
        return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
    }
    return nil
}
```

Add missing imports `crypto/tls`, `crypto/x509` at the top.

- [ ] **Step 3: Update loop.go interface**

In `pkg/tritonagent/loop.go`, update `EngineAPI` → `ManageAPI`:

```go
// ManageAPI is the interface the agent loop uses to communicate with the
// Manage Server gateway. Implemented by *Client; stubbed in tests.
type ManageAPI interface {
    Heartbeat(ctx context.Context) error
    PollCommand(ctx context.Context) (*AgentCommand, error)
    SubmitScan(ctx context.Context, jobID string, scanResult []byte) error
}
```

Update `Run` signature: `func Run(ctx context.Context, c ManageAPI, cfg Config) error`

Remove the `Register` retry loop at the top of `Run` entirely.

Update the scan poll section to use `PollCommand`:

```go
cmd, err := c.PollCommand(ctx)
if err != nil {
    // handle same as before
    continue
}
if cmd == nil {
    // wait + continue
    continue
}

profile := cmd.ScanProfile
if profile == "" {
    profile = cfg.DefaultProfile
}

result, err := cfg.Scanner.RunScan(ctx, profile)
// ...

resultJSON, err := json.Marshal(result)
// ...

if err := c.SubmitScan(ctx, cmd.JobID, resultJSON); err != nil {
    log.Printf("submit scan: %v", err)
} else {
    log.Printf("scan submitted (%d bytes)", len(resultJSON))
}
```

Also: before marshaling the scan result, stamp the source field:

```go
if sr, ok := result.(*model.ScanResult); ok {
    sr.Metadata.Source = model.ScanSourceAgent
}
```

Import `github.com/amiryahaya/triton/pkg/model` in loop.go.

- [ ] **Step 4: Update cmd/triton-agent/config.go**

Rename `EngineURL` → `ManageURL` and `engine_url` → `manage_url`:

```go
type agentConfig struct {
    ManageURL   string `yaml:"manage_url"`
    CertPath    string `yaml:"cert_path"`
    KeyPath     string `yaml:"key_path"`
    CAPath      string `yaml:"ca_path"`
    ScanProfile string `yaml:"scan_profile"`
    HostID      string `yaml:"host_id"`
}
```

Update `cmd/triton-agent/main.go` to pass `cfg.ManageURL` to `tritonagent.NewClient`.

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/tritonagent/... -v
```

Fix any test stubs that reference `EngineAPI`, `Register`, `SubmitFindings`, or `PollScan`
— update them to match `ManageAPI`, `PollCommand`, `SubmitScan`.

- [ ] **Step 6: Build to verify compilation**

```bash
go build ./cmd/triton-agent/ && go build ./...
```

Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add pkg/tritonagent/ cmd/triton-agent/
git commit -m "feat(triton-agent): update protocol to Manage Server gateway (remove engine dependency)"
```

---

## Task 10: Add ?source filter to Report Server findings

**Files:**
- Modify: `pkg/server/handlers.go`

- [ ] **Step 1: Find the existing ?module filter**

```bash
grep -n "module\|filterByModule" pkg/server/handlers.go | head -10
```

Note the line numbers. The `?source` filter follows the same pattern.

- [ ] **Step 2: Write failing test**

In `pkg/server/handlers_test.go` (or the file containing scan handler tests), add:

```go
func TestHandleGetScanFindings_SourceFilter(t *testing.T) {
    // seed a scan with two findings from different sources
    // then filter by source and verify only the right one comes back
    // follow the existing pattern in the test file for seeding and querying
}
```

Read the existing `?module` filter test to understand the exact test helper pattern used,
then write a parallel test for `?source`.

- [ ] **Step 3: Add filterBySource function**

In `pkg/server/handlers.go`, add after `filterByModule`:

```go
func filterBySource(findings []model.Finding, source string) []model.Finding {
    out := findings[:0]
    for i := range findings {
        if strings.EqualFold(string(findings[i].Source.Type), source) {
            out = append(out, findings[i])
        }
    }
    return out
}
```

Wait — `Finding.Source` is a `FindingSource` struct, not a `ScanSource`. The `ScanSource`
is on `ScanMetadata`, not on individual findings. Re-read `pkg/model/types.go` to confirm
the right field to filter on. The `?source` filter for findings should filter on
`ScanResult.Metadata.Source` (the program that submitted), not per-finding.

Since findings are returned in the context of a scan, and the scan has one `Source`, the
correct approach is: if `?source` is provided, check `scan.Metadata.Source` and return
all findings or none (the entire scan is from one source). Alternatively, stamp
`source_program` on each queue row and surface it in the scan list API rather than the
findings API.

> **Decision:** add `?source` to `GET /api/v1/scans` (the scan list), not to the per-scan
> findings endpoint. Filter scans by `metadata.source` field. Follow the existing filter
> pattern in `handleListScans`.

Adjust the implementation accordingly.

- [ ] **Step 4: Run tests and commit**

```bash
go test ./pkg/server/... -run TestSource -v
```

```bash
git add pkg/server/handlers.go pkg/server/handlers_test.go
git commit -m "feat(server): add ?source filter to GET /api/v1/scans"
```

---

## Task 11: Remove old triton agent (cmd/agent.go)

**Files:**
- Delete: `cmd/agent.go`, `cmd/agent_scheduler.go`
- Delete: `cmd/agent_control_test.go`, `cmd/agent_resolve_test.go`,
  `cmd/agent_schedule_test.go`, `cmd/agent_scheduler_test.go`,
  `cmd/agent_seat_test.go`, `cmd/agent_tee_test.go`
- Modify: `cmd/root.go` — remove `rootCmd.AddCommand(agentCmd)`

- [ ] **Step 1: Delete the files**

```bash
rm cmd/agent.go cmd/agent_scheduler.go
rm cmd/agent_control_test.go cmd/agent_resolve_test.go cmd/agent_schedule_test.go
rm cmd/agent_scheduler_test.go cmd/agent_seat_test.go cmd/agent_tee_test.go
```

- [ ] **Step 2: Fix compilation errors**

```bash
go build ./cmd/... 2>&1 | head -30
```

Remove `rootCmd.AddCommand(agentCmd)` from `cmd/root.go` init() or wherever it's registered.
Remove any other references to `agentCmd` in `cmd/root.go`.

- [ ] **Step 3: Remove `pkg/agent/` if only used by old agent**

```bash
grep -r "pkg/agent" cmd/ pkg/ --include="*.go" | grep -v "_test.go" | grep -v "cmd/agent.go"
```

If `pkg/agent/` is only used by `cmd/agent.go` and `pkg/scanner/netscan/fleet/`, it can be
removed in Task 12 (fleet-scan removal). Otherwise keep it.

- [ ] **Step 4: Build and test**

```bash
go build ./... && go test ./cmd/... -v
```

Expected: all pass (no agent tests remain)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "remove: old triton agent CLI subcommand (superseded by triton-agent OS service)"
```

---

## Task 12: Remove triton fleet-scan

**Files:**
- Delete: `cmd/fleet_scan.go`, `cmd/fleet_scan_test.go`
- Delete: `pkg/scanner/netscan/fleet/` (entire directory)
- Modify: `cmd/root.go` — remove `rootCmd.AddCommand(fleetScanCmd)`

- [ ] **Step 1: Delete files**

```bash
rm cmd/fleet_scan.go cmd/fleet_scan_test.go
rm -rf pkg/scanner/netscan/fleet/
```

- [ ] **Step 2: Fix compilation errors**

```bash
go build ./... 2>&1 | head -30
```

Remove `rootCmd.AddCommand(fleetScanCmd)` from `cmd/root.go`. Remove any
`pkg/scanner/netscan/fleet` import references.

- [ ] **Step 3: Remove pkg/agent/ now if no longer needed**

```bash
grep -r "\"github.com/amiryahaya/triton/pkg/agent\"" --include="*.go" | grep -v "_test.go"
```

If nothing outside fleet-scan + old agent uses it, delete `pkg/agent/`.

- [ ] **Step 4: Build and test**

```bash
go build ./... && go test ./... -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "remove: triton fleet-scan (replaced by triton-sshagent + Manage Server orchestration)"
```

---

## Task 13: Remove pkg/engine and cmd/triton-engine

**Files:**
- Delete: `pkg/engine/` (entire directory)
- Delete: `cmd/triton-engine/`

- [ ] **Step 1: Check for remaining references**

```bash
grep -rn "\"github.com/amiryahaya/triton/pkg/engine" --include="*.go" | grep -v "_test.go" | grep -v "pkg/engine/"
```

List every file that imports from `pkg/engine`. These imports must be removed before deleting.

- [ ] **Step 2: Remove imports from Report Server**

The Report Server (`pkg/server/`) may import `pkg/engine/crypto` or `pkg/engine/client`.
For each file returned above, remove the import and any code that uses it. Run
`go build ./...` after each file to stay green.

- [ ] **Step 3: Delete the packages**

```bash
rm -rf pkg/engine/ cmd/triton-engine/
```

- [ ] **Step 4: Build clean**

```bash
go build ./...
```

Expected: no errors. Fix any remaining import errors.

- [ ] **Step 5: Run tests**

```bash
go test ./... -v
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "remove: pkg/engine and cmd/triton-engine (Manage Server absorbs all responsibilities)"
```

---

## Task 14: Remove Report Server engine gateway packages

These packages served the triton-engine ↔ Report Server protocol. With triton-engine gone,
they are dead code.

**Files to remove:**
- `pkg/server/engine/`
- `pkg/server/scanjobs/`
- `pkg/server/agentpush/`
- `pkg/server/credentials/`
- `pkg/server/discovery/`
- Routes wiring them in `pkg/server/server.go`

> **CAUTION:** Read `pkg/server/server.go` before deleting anything. Some of these packages
> may also serve non-engine paths. Delete only the engine-specific gateway routes
> (`/api/v1/engine/*`) and the packages that are exclusively for those routes.
> `pkg/server/manage_enrol/` handles Manage Server → Report Server enrollment — keep it.

- [ ] **Step 1: Audit all engine gateway route mounts**

```bash
grep -n "engine\|agentpush\|MountGateway" pkg/server/server.go | head -30
```

List every `MountGatewayRoutes` call that mounts under `/api/v1/engine/`.

- [ ] **Step 2: Remove route registrations**

In `pkg/server/server.go`, remove the lines that mount:
- `engine.MountGatewayRoutes`
- `scanjobs.MountGatewayRoutes` (the engine scan jobs one, not the manage scan jobs)
- `agentpush.MountGatewayRoutes`
- `credentials.MountGatewayRoutes`
- `discovery.MountGatewayRoutes` (engine-facing one)

- [ ] **Step 3: Delete packages**

```bash
rm -rf pkg/server/engine/ pkg/server/scanjobs/ pkg/server/agentpush/
rm -rf pkg/server/credentials/ pkg/server/discovery/
```

Only delete after confirming they have no non-engine consumers:

```bash
grep -rn "pkg/server/engine\|pkg/server/scanjobs\|pkg/server/agentpush\|pkg/server/credentials\|pkg/server/discovery" --include="*.go" | grep -v "_test.go" | grep -v "pkg/server/"
```

- [ ] **Step 4: Build and test**

```bash
go build ./... && go test ./... -v
```

Fix any remaining broken imports in `pkg/server/server.go`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "remove: Report Server engine gateway packages (/api/v1/engine/* routes)"
```

---

## Task 15: Update triton-portscan (depends on PR #102 merge)

> **Prerequisite:** This task requires `feat/network-discovery` to be merged into
> `feat/manage-relay` first. The `pkg/scanrunner/` and `cmd/triton-portscan/` directories
> do not exist on main yet.

Once PR #102 is merged:

**Files:**
- Modify: `pkg/scanrunner/scanner.go` — remove `ReportClient` type
- Modify: `pkg/scanrunner/mapper.go` — set `Source = model.ScanSourcePortscan` in `ToScanResult`
- Modify: `cmd/triton-portscan/main.go` — remove `--report-url` and `--license-token` flags

- [ ] **Step 1: Remove ReportClient from scanrunner**

In `pkg/scanrunner/scanner.go`, delete the `ReportClient` struct, `NewReportClient` function,
and the `rc *ReportClient` parameter from `RunOne`. Update `RunOne` to call
`mc.SubmitResult(ctx, jobID, scanResult)` instead of `rc.Submit(...)`.

The `ManageClient.SubmitResult` equivalent must exist on the manage client used by portscan.
Add `SubmitResult(ctx, jobID uuid.UUID, result *model.ScanResult) error` to `ManageClient`
if not present.

- [ ] **Step 2: Set source in mapper**

In `pkg/scanrunner/mapper.go`, in `ToScanResult()`, set:

```go
result.Metadata.Source = model.ScanSourcePortscan
```

- [ ] **Step 3: Update cmd/triton-portscan/main.go**

Remove:
```go
reportURL := flag.String("report-url", "", "...")
licenseToken := flag.String("license-token", "", "...")
```

Remove `scanrunner.NewReportClient(...)` call. Remove `rc` parameter from `scanrunner.RunOne`.

- [ ] **Step 4: Build, test, commit**

```bash
go build ./cmd/triton-portscan/ && go test ./pkg/scanrunner/... -v
git add pkg/scanrunner/ cmd/triton-portscan/
git commit -m "feat(triton-portscan): submit results to Manage Server only (remove direct Report Server path)"
```

---

## Self-Review Checklist

- [x] **Spec coverage:**
  - D1 ScanSource → Task 1
  - D2 GET /agents/commands → Task 4
  - D3 Worker key auth → Task 5
  - D4 Worker job submit → Task 5
  - D5 ScanSource field → Task 1 + Task 9 (stamp in loop)
  - D6 scanexec migration → Task 6
  - D7 Outbox queue → Task 5 (enqueuer call)
  - D8 Removals → Tasks 11–14
  - D9 ?source filter → Task 10

- [x] **No placeholders:** All steps have concrete code.

- [x] **Type consistency:**
  - `AgentCommand` defined in Task 3, used in Tasks 4 and 9
  - `ManageAPI` interface defined in Task 9, implemented by `Client` from Task 9
  - `WorkerHandlers.Submit` defined in Task 5, wired in Task 5
  - `sshagent.Scanner` interface defined in Task 6, used in Task 7 runner
  - `sshagent.ManageClient` interface defined in Task 7, implemented by `Client` from Task 7

- [x] **Task 6 caveat noted:** `eng.SetHostname()` / `eng.SetFileReader()` may not exist —
  implementer must read `pkg/scanner/engine.go` + `pkg/engine/scanexec/executor.go` to verify
  the correct API before writing scanner.go.

- [x] **Task 10 corrected:** `?source` filter applies to scan list, not per-finding (since
  source is a scan-level attribute).

- [x] **Task 15 dependency flagged:** depends on PR #102 (feat/network-discovery) merge.
