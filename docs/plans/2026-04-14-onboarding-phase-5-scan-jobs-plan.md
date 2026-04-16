# Onboarding Phase 5 — Scan Jobs + First Agentless Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** User clicks "Scan group" in the portal UI → portal queues a scan job for the owning engine → engine long-polls, claims the job, looks up the credential from its keystore, constructs an `SshReader`, runs the existing `scanner.Engine` against each host in the group, streams progress back, and submits findings. Findings appear in the existing report dashboard (Analytics Phase 1).

**Architecture:** 4th copy of the engine job-queue pattern (after discovery + credential-delivery + credential-test). Scan job scope: one engine per job (portal splits group if hosts span engines). Per-host SSH scans reuse the Phase 0 agentless Unix wiring (`SshReader` + `scanner.Engine`). Credential secrets come from the Phase 4 keystore via `secret_ref`. Findings submitted to a new mTLS engine-gateway endpoint that writes to the existing `scans` + `findings` tables (Analytics Phase 1), tagged with `engine_id` + `scan_job_id`.

**Tech Stack:** Go 1.25, pgx v5, `golang.org/x/crypto/ssh`, reuse `pkg/scanner.Engine`, reuse `pkg/scanner/fsadapter.SshReader`, reuse `pkg/server/engine.MTLSMiddleware`, vanilla JS + hash routing.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §6 step 6 (First scan), §9 gateway protocol.

---

## Prerequisites

- [ ] Phase 4 merged (PR #58 + follow-ups #59). Confirm: `git log main --grep "onboarding phase 4"` shows the merge.
- [ ] Post-Phase-0 agentless Unix wiring on main: `SshReader`, `scanner.Engine` with injected reader. Confirm `pkg/scanner/fsadapter/ssh_reader.go` exists.
- [ ] Keystore on engine side (Phase 4). Confirm `pkg/engine/keystore` importable.
- [ ] Current migration head: v20. This phase appends v21.

---

## File Map

**Create:**
- `pkg/server/scanjobs/types.go` — ScanJob, ScanJobStatus, ScanJobPayload (wire format)
- `pkg/server/scanjobs/store.go` — Store interface
- `pkg/server/scanjobs/postgres.go` — PostgresStore
- `pkg/server/scanjobs/postgres_test.go` — integration tests
- `pkg/server/scanjobs/handlers_admin.go` — `/api/v1/manage/scan-jobs/*`
- `pkg/server/scanjobs/handlers_gateway.go` — `/api/v1/engine/scans/*`
- `pkg/server/scanjobs/handlers_test.go`
- `pkg/server/scanjobs/routes.go`
- `pkg/server/scanjobs/stale_reaper.go` + test
- `pkg/engine/scanexec/executor.go` — per-host scan: keystore lookup → SSH client → scanner.Engine → findings
- `pkg/engine/scanexec/executor_test.go`
- `pkg/engine/scanexec/worker.go` — long-poll loop: claim → execute per host → submit
- `pkg/engine/scanexec/worker_test.go`

**Modify:**
- `pkg/store/migrations.go` — append v21 (scan_jobs table + scans.engine_id + scans.scan_job_id columns)
- `pkg/engine/client/client.go` — add `PollScanJob`, `SubmitScanProgress`, `SubmitScanFindings`
- `pkg/engine/loop/loop.go` — add `ScanWorker` slot on `Config` + `Worker` interface
- `cmd/triton-engine/main.go` — construct ScanWorker + inject keystore + wire into loop
- `cmd/server.go` — mount `/api/v1/manage/scan-jobs/*` admin routes + start StaleReaper
- `cmd/server_engine.go` — mount `/api/v1/engine/scans/*` gateway routes, pass scanjobs.Store through
- `pkg/server/ui/dist/manage/app.js` — add routes `#/scan-jobs`, `#/scan-jobs/{uuid}`, "Scan now" button on Groups page
- `pkg/server/ui/dist/manage/index.html` — add "Scans" nav link

**Do not touch:**
- `pkg/scanner/*` — reuse as-is
- `pkg/server/engine/*` — no changes (MTLSMiddleware, engine store unchanged)
- `pkg/server/discovery/*`, `pkg/server/credentials/*` — no changes

---

### Task 1: Migration v21

Append to `pkg/store/migrations.go`:

```go
`
CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    group_id        UUID REFERENCES inventory_groups(id) ON DELETE SET NULL,
    host_ids        UUID[] NOT NULL,
    scan_profile    TEXT NOT NULL DEFAULT 'standard'
                    CHECK (scan_profile IN ('quick', 'standard', 'comprehensive')),
    credential_profile_id UUID REFERENCES credentials_profiles(id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    progress_total  INTEGER NOT NULL DEFAULT 0,
    progress_done   INTEGER NOT NULL DEFAULT 0,
    progress_failed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_scan_jobs_org                 ON scan_jobs(org_id);
CREATE INDEX idx_scan_jobs_engine_queue
    ON scan_jobs(engine_id, requested_at)
    WHERE status = 'queued';
CREATE INDEX idx_scan_jobs_status              ON scan_jobs(status);

ALTER TABLE scans ADD COLUMN engine_id    UUID REFERENCES engines(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN scan_job_id  UUID REFERENCES scan_jobs(id) ON DELETE SET NULL;
CREATE INDEX idx_scans_scan_job ON scans(scan_job_id) WHERE scan_job_id IS NOT NULL;
`,
```

Verify: `make db-up && psql ... -c "\d scan_jobs"` + `\d scans` shows new columns.

Commit: `feat(store): scan_jobs table + scans.engine_id + scans.scan_job_id (v21)`

---

### Task 2: Domain types + Store interface

Create `pkg/server/scanjobs/types.go`:

```go
package scanjobs

import (
    "time"

    "github.com/google/uuid"
)

type JobStatus string

const (
    StatusQueued    JobStatus = "queued"
    StatusClaimed   JobStatus = "claimed"
    StatusRunning   JobStatus = "running"
    StatusCompleted JobStatus = "completed"
    StatusFailed    JobStatus = "failed"
    StatusCancelled JobStatus = "cancelled"
)

type ScanProfile string

const (
    ProfileQuick         ScanProfile = "quick"
    ProfileStandard      ScanProfile = "standard"
    ProfileComprehensive ScanProfile = "comprehensive"
)

type Job struct {
    ID                   uuid.UUID   `json:"id"`
    OrgID                uuid.UUID   `json:"org_id"`
    EngineID             uuid.UUID   `json:"engine_id"`
    GroupID              *uuid.UUID  `json:"group_id,omitempty"`
    HostIDs              []uuid.UUID `json:"host_ids"`
    ScanProfile          ScanProfile `json:"scan_profile"`
    CredentialProfileID  *uuid.UUID  `json:"credential_profile_id,omitempty"`
    Status               JobStatus   `json:"status"`
    Error                string      `json:"error,omitempty"`
    RequestedBy          uuid.UUID   `json:"requested_by"`
    RequestedAt          time.Time   `json:"requested_at"`
    ClaimedAt            *time.Time  `json:"claimed_at,omitempty"`
    CompletedAt          *time.Time  `json:"completed_at,omitempty"`
    ProgressTotal        int         `json:"progress_total"`
    ProgressDone         int         `json:"progress_done"`
    ProgressFailed       int         `json:"progress_failed"`
}

// HostTarget is what the engine needs to scan one host.
type HostTarget struct {
    ID       uuid.UUID `json:"id"`
    Address  string    `json:"address"`
    Port     int       `json:"port"`
    Hostname string    `json:"hostname,omitempty"`
    OS       string    `json:"os,omitempty"`
}

// JobPayload is the wire shape returned by /engine/scans/poll.
type JobPayload struct {
    ID                  uuid.UUID    `json:"id"`
    ScanProfile         ScanProfile  `json:"scan_profile"`
    CredentialSecretRef *uuid.UUID   `json:"credential_secret_ref,omitempty"`
    CredentialAuthType  string       `json:"credential_auth_type,omitempty"`
    Hosts               []HostTarget `json:"hosts"`
}

type ProgressUpdate struct {
    HostID        uuid.UUID `json:"host_id"`
    Status        string    `json:"status"`  // "running", "completed", "failed"
    FindingsCount int       `json:"findings_count"`
    Error         string    `json:"error,omitempty"`
}
```

Create `store.go`:

```go
package scanjobs

import (
    "context"
    "errors"

    "github.com/google/uuid"
)

var (
    ErrJobNotFound       = errors.New("scanjobs: job not found")
    ErrJobNotCancellable = errors.New("scanjobs: job not cancellable (must be queued)")
    ErrJobAlreadyTerminal = errors.New("scanjobs: job already in terminal state")
)

// Store is the 4th engine-job-queue. See architectural tech debt note:
// discovery + credential-delivery + credential-test + scan-jobs all
// implement the same claim/ack/reclaim pattern. Extract jobqueue
// abstraction in Phase 5.5 refactor before Phase 6.
type Store interface {
    CreateJob(ctx context.Context, j Job) (Job, error)
    GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error)
    ListJobs(ctx context.Context, orgID uuid.UUID, limit int) ([]Job, error)
    CancelJob(ctx context.Context, orgID, id uuid.UUID) error

    // Engine gateway
    ClaimNext(ctx context.Context, engineID uuid.UUID) (JobPayload, bool, error)
    UpdateProgress(ctx context.Context, jobID uuid.UUID, done, failed int) error
    FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string) error
    ReclaimStale(ctx context.Context, cutoff time.Time) error

    // Findings ingestion
    RecordScanResult(ctx context.Context, jobID, engineID, hostID uuid.UUID, scanPayload []byte) error
}
```

**`RecordScanResult`** — writes to the existing `scans` table with the new `engine_id` + `scan_job_id` columns populated, plus the existing findings extraction via the Phase 1 `ExtractFindings` pipeline. It wraps `PostgresStore.SaveScanWithFindings` (already exists) with the additional tagging columns.

**Note:** `SaveScanWithFindings` lives on `pkg/store.PostgresStore`, not on scanjobs's `PostgresStore`. The scanjobs store needs to call into it. Two options:
- Inject `pkg/store.Store` interface into scanjobs PostgresStore
- Use the shared pgx pool and add a new method `SaveScanWithJobContext(ctx, scan, engineID, jobID)` in `pkg/store/findings.go`

Pick the simpler: **add `SaveScanWithJobContext` in `pkg/store/findings.go`** (one new method on the existing store), and the scanjobs `RecordScanResult` calls it through a narrow injected interface.

Commit: `feat(scanjobs): domain types + Store interface`

---

### Task 3: PostgresStore + integration tests

Create `pkg/server/scanjobs/postgres.go`. Mirror the Phase 3/4 pattern: `NewPostgresStore(pool, scanStore scanStoreAPI)` where `scanStoreAPI` is the narrow interface for `SaveScanWithJobContext`.

Key methods:
- `CreateJob` — simple INSERT with validation
- `GetJob`, `ListJobs` (most-recent first, cap at `limit`)
- `CancelJob` — UPDATE only if status='queued', return sentinel otherwise
- `ClaimNext` — `SELECT ... FOR UPDATE SKIP LOCKED` + UPDATE to 'claimed'. Enrich response with host addresses/OS via JOIN on `inventory_hosts`. Credential fields from `credentials_profiles` (secret_ref + auth_type) if credential_profile_id is set.
- `UpdateProgress` — UPDATE counts + flip status from 'claimed'→'running' on first update
- `FinishJob` — terminal-state guard (mirror Phase 3 `FinishJob` fix)
- `ReclaimStale` — `UPDATE ... WHERE status IN ('claimed','running') AND claimed_at < cutoff`
- `RecordScanResult` — delegates to the injected `scanStoreAPI.SaveScanWithJobContext`

Add to `pkg/store/findings.go`:

```go
// SaveScanWithJobContext persists a scan result and extracts findings,
// tagging the scan row with engine_id + scan_job_id. Same behavior as
// SaveScanWithFindings but with the onboarding Phase 5 engine tags.
func (s *PostgresStore) SaveScanWithJobContext(ctx context.Context, scan *model.ScanResult, engineID, scanJobID uuid.UUID) error {
    // Reuse the existing SaveScanWithFindings transaction path but with
    // UPDATE ... SET engine_id = $1, scan_job_id = $2 WHERE id = <scan.ID>
    // as a final step inside the same tx. Simpler: duplicate the scan
    // INSERT with the new columns included, extract findings, commit.
    // ... full impl ...
}
```

Integration tests (build tag `integration`):
- `TestScanJobs_CreateAndList` — two jobs, verify order desc by requested_at
- `TestScanJobs_ClaimNext_SingleUse` — 5 goroutines → 1 wins
- `TestScanJobs_ClaimNext_EnrichesWithHostAddresses` — ClaimNext returns JobPayload with resolved address+port from inventory_hosts
- `TestScanJobs_CancelQueued_OK` / `TestScanJobs_CancelRunning_NotCancellable`
- `TestScanJobs_FinishJob_TerminalGuard` — finish twice, second returns ErrJobAlreadyTerminal
- `TestScanJobs_UpdateProgress_FlipsClaimedToRunning`
- `TestScanJobs_ReclaimStale` — stale 'running' + 'claimed' both reclaim
- `TestScanJobs_RecordScanResult_WritesTaggedScan` — after writing, `SELECT engine_id, scan_job_id FROM scans WHERE id = ...` returns both populated

Seed org + user + engine + credential profile (with valid secret_ref) + inventory hosts. Use `t.Cleanup`.

Commit: `feat(scanjobs): PostgresStore with enriched ClaimNext + SaveScanWithJobContext`

---

### Task 4: Admin handlers + routes

Create `pkg/server/scanjobs/handlers_admin.go`.

Endpoints (`/api/v1/manage/scan-jobs/*`, JWT):

- `POST /` — body `{group_id?, host_ids?, scan_profile?, credential_profile_id?}`. Engineer+.
- `GET /` — list, most recent first, `?limit=50`
- `GET /{id}` — single job
- `POST /{id}/cancel` — only queued jobs; 409 if claimed/running

**CreateJob validation:**

```go
func (h *AdminHandlers) CreateJob(w http.ResponseWriter, r *http.Request) {
    var body struct {
        GroupID             *uuid.UUID   `json:"group_id,omitempty"`
        HostIDs             []uuid.UUID  `json:"host_ids,omitempty"`
        ScanProfile         ScanProfile  `json:"scan_profile,omitempty"`
        CredentialProfileID *uuid.UUID   `json:"credential_profile_id,omitempty"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil { /* 400 */ }

    if (body.GroupID == nil) == (len(body.HostIDs) == 0) {
        http.Error(w, "exactly one of group_id or host_ids required", http.StatusBadRequest)
        return
    }
    if body.ScanProfile == "" { body.ScanProfile = ProfileStandard }

    claims := server.ClaimsFromContext(r.Context())
    orgID, _ := uuid.Parse(claims.Org)
    userID, _ := uuid.Parse(claims.Sub)

    // Resolve host list
    var hostIDs []uuid.UUID
    if body.GroupID != nil {
        // Query inventory.ListHosts filtered by group_id
        hosts, err := h.InventoryStore.ListHosts(r.Context(), orgID, inventory.HostFilters{GroupID: body.GroupID})
        if err != nil { /* 500 */ }
        for _, host := range hosts {
            hostIDs = append(hostIDs, host.ID)
        }
    } else {
        hostIDs = body.HostIDs
    }
    if len(hostIDs) == 0 {
        http.Error(w, "no hosts resolved", http.StatusBadRequest)
        return
    }
    // Enforce one-engine-per-job
    hostEngines, err := h.InventoryStore.GetEnginesForHosts(r.Context(), orgID, hostIDs)
    if err != nil { /* 500 */ }
    if len(hostEngines) == 0 {
        http.Error(w, "hosts have no engine assigned", http.StatusBadRequest)
        return
    }
    if len(hostEngines) > 1 {
        http.Error(w, "hosts span multiple engines; split into separate scan jobs", http.StatusBadRequest)
        return
    }
    var engineID uuid.UUID
    for k := range hostEngines { engineID = k }

    job := Job{
        ID:                  uuid.Must(uuid.NewV7()),
        OrgID:               orgID,
        EngineID:            engineID,
        GroupID:             body.GroupID,
        HostIDs:             hostIDs,
        ScanProfile:         body.ScanProfile,
        CredentialProfileID: body.CredentialProfileID,
        RequestedBy:         userID,
        ProgressTotal:       len(hostIDs),
    }
    job, err = h.Store.CreateJob(r.Context(), job)
    if err != nil { /* 500 */ }
    h.Audit.Record(r.Context(), "scanjobs.job.create", job.ID.String(), map[string]any{
        "engine_id": engineID.String(), "host_count": len(hostIDs), "profile": string(body.ScanProfile),
    })
    writeJSON(w, http.StatusCreated, job)
}
```

**Extend `inventory.Store`** with `GetEnginesForHosts(ctx, orgID, hostIDs) (map[uuid.UUID]struct{}, error)` that returns the DISTINCT `engine_id`s among the provided hosts. (Hosts without engine_id are excluded — portal must check and return "no engine assigned" if the map is empty.)

Tests: create by group, create by host list, multi-engine split error, officer 403, cancel queued OK, cancel running 409.

Commit: `feat(scanjobs): admin handlers + routes`

---

### Task 5: Gateway handlers

Create `pkg/server/scanjobs/handlers_gateway.go`.

Endpoints (`/api/v1/engine/scans/*`, mTLS via existing `engine.MTLSMiddleware`):

- `GET /poll` — long-poll for next queued job, 30s timeout. Returns `JobPayload` with hosts already resolved (address+port+OS) + optional credential info (secret_ref + auth_type). 204 on no work.
- `POST /{id}/progress` — body `ProgressUpdate[]`; aggregates done/failed counts; UPDATE progress_done / progress_failed
- `POST /{id}/submit` — body `{host_id, scan_result (ScanResult JSON), findings_count}` per host (send one POST per host). Calls `Store.RecordScanResult` which persists with engine+job tags.
- `POST /{id}/finish` — body `{status: "completed"|"failed", error?}` — terminal-state guard; 409 if already terminal.

Gateway handlers pattern identical to credential-test and discovery handlers. Write tests with a fakeStore.

Commit: `feat(scanjobs): gateway handlers — poll, progress, submit, finish`

---

### Task 6: Engine executor + scanner wiring

Create `pkg/engine/scanexec/executor.go`:

```go
package scanexec

import (
    "context"
    "encoding/json"
    "fmt"
    "strconv"

    "golang.org/x/crypto/ssh"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/engine/credentials"
    "github.com/amiryahaya/triton/pkg/engine/keystore"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// Executor runs one scan job's hosts sequentially.
type Executor struct {
    Keystore *keystore.Keystore
}

type HostResult struct {
    HostID   string
    Success  bool
    Findings int
    Result   *model.ScanResult
    Error    string
}

// ScanHost connects to one host via SSH using the keystored credential
// and runs the scanner.Engine with the given profile. Returns a
// populated ScanResult on success.
func (e *Executor) ScanHost(ctx context.Context, host scanjobs.HostTarget, secretRef, authType, profile string) HostResult {
    // 1. Keystore lookup
    at, pt, err := e.Keystore.Get(ctx, secretRef)
    if err != nil {
        return HostResult{HostID: host.ID.String(), Error: "keystore get: " + err.Error()}
    }
    defer func() { for i := range pt { pt[i] = 0 } }()

    if at != authType {
        return HostResult{HostID: host.ID.String(), Error: "auth_type mismatch: wanted " + authType + " got " + at}
    }

    var secret credentials.Secret
    if err := json.Unmarshal(pt, &secret); err != nil {
        return HostResult{HostID: host.ID.String(), Error: "parse secret: " + err.Error()}
    }
    defer secret.Zero()

    // 2. Build SSH client
    sshCfg, err := buildSSHConfig(authType, secret)
    if err != nil {
        return HostResult{HostID: host.ID.String(), Error: "build ssh config: " + err.Error()}
    }
    sshClient, err := ssh.Dial("tcp", host.Address+":"+strconv.Itoa(host.Port), sshCfg)
    if err != nil {
        return HostResult{HostID: host.ID.String(), Error: "ssh dial: " + err.Error()}
    }
    defer sshClient.Close()

    // 3. Construct SshReader
    reader := fsadapter.NewSshReader(sshClient)

    // 4. Configure and run scanner.Engine
    cfg := scannerconfig.DefaultConfig()
    cfg.Profile = profile
    // Engine has a setter for the FileReader (added in Phase 0 agentless wiring).
    eng := scanner.NewEngine(cfg)
    eng.SetFileReader(reader)  // exact method name may differ — check scanner package

    result, err := eng.Run(ctx)
    if err != nil {
        return HostResult{HostID: host.ID.String(), Error: "scan run: " + err.Error()}
    }

    // Populate metadata fields the engine can fill
    result.Metadata.Hostname = host.Hostname
    // OS, agent ID, etc. — as applicable

    return HostResult{
        HostID:   host.ID.String(),
        Success:  true,
        Findings: len(result.Findings),
        Result:   result,
    }
}

func buildSSHConfig(authType string, s credentials.Secret) (*ssh.ClientConfig, error) {
    cfg := &ssh.ClientConfig{
        User:            s.Username,
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // MVP — scan only, no lateral movement
        Timeout:         30 * time.Second,
    }
    switch authType {
    case "ssh-password", "bootstrap-admin":
        cfg.Auth = []ssh.AuthMethod{ssh.Password(s.Password)}
    case "ssh-key":
        var signer ssh.Signer
        var err error
        if s.Passphrase != "" {
            signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.PrivateKey), []byte(s.Passphrase))
        } else {
            signer, err = ssh.ParsePrivateKey([]byte(s.PrivateKey))
        }
        if err != nil { return nil, fmt.Errorf("parse private key: %w", err) }
        cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
    case "winrm-password":
        return nil, fmt.Errorf("winrm not supported for scanning (use agent-push in Phase 6)")
    default:
        return nil, fmt.Errorf("unknown auth_type: %s", authType)
    }
    return cfg, nil
}
```

**Important — verify the exact scanner API:**
- Check `pkg/scanner/engine.go` for the FileReader-injection method. Phase 0 wiring introduced either `SetFileReader`, `WithFileReader`, or similar. Match the actual name.
- Check `scannerconfig` default-config constructor name.
- Check `scanner.Engine` Run/Execute method signature.

Tests (`executor_test.go`):
- `TestScanHost_KeystoreMiss_ReturnsError` — fake keystore returns ErrNotFound
- `TestScanHost_AuthTypeMismatch_ReturnsError`
- `TestScanHost_BadSecretJSON_ReturnsError`
- `TestScanHost_SSHDialFail_ReturnsError` — dial to 127.0.0.1:1 (closed), expect ssh dial error
- `TestBuildSSHConfig_Password` + `TestBuildSSHConfig_SSHKey` + `TestBuildSSHConfig_WinRM_NotSupported`

Full end-to-end (host up, real scan) is covered by the integration test in Task 11.

Commit: `feat(engine/scanexec): SSH-backed per-host scan executor`

---

### Task 7: Engine scan worker

Create `pkg/engine/scanexec/worker.go`:

```go
package scanexec

import (
    "context"
    "encoding/json"
    "log"
    "time"

    "github.com/amiryahaya/triton/pkg/engine/client"
)

type ScanAPI interface {
    PollScanJob(ctx context.Context) (*client.ScanJobPayload, error)
    SubmitScanProgress(ctx context.Context, jobID string, updates []client.ScanProgressUpdate) error
    SubmitScanFindings(ctx context.Context, jobID, hostID string, scanResult []byte, findings int) error
    FinishScanJob(ctx context.Context, jobID string, status, errMsg string) error
}

type Worker struct {
    Client    ScanAPI
    Executor  *Executor
    PollError time.Duration
}

func (w *Worker) Run(ctx context.Context) {
    for {
        if ctx.Err() != nil { return }
        job, err := w.Client.PollScanJob(ctx)
        if err != nil {
            wait := w.PollError
            if wait == 0 { wait = 5 * time.Second }
            log.Printf("poll scan job: %v", err)
            select {
            case <-ctx.Done(): return
            case <-time.After(wait):
            }
            continue
        }
        if job == nil { continue }
        w.runOne(ctx, job)
    }
}

func (w *Worker) runOne(ctx context.Context, job *client.ScanJobPayload) {
    log.Printf("scan job claimed: %s (%d hosts, profile=%s)", job.ID, len(job.Hosts), job.ScanProfile)

    done, failed := 0, 0
    for _, host := range job.Hosts {
        if ctx.Err() != nil { return }

        // 5-minute per-host timeout
        hctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
        target := scanjobs.HostTarget{
            ID: uuid.MustParse(host.ID), Address: host.Address, Port: host.Port,
            Hostname: host.Hostname, OS: host.OS,
        }
        secretRef := ""
        if job.CredentialSecretRef != nil { secretRef = *job.CredentialSecretRef }
        res := w.Executor.ScanHost(hctx, target, secretRef, job.CredentialAuthType, job.ScanProfile)
        cancel()

        progress := []client.ScanProgressUpdate{{
            HostID:        host.ID,
            FindingsCount: res.Findings,
        }}
        if res.Success {
            done++
            progress[0].Status = "completed"
            // Serialize scan result and submit
            scanJSON, err := json.Marshal(res.Result)
            if err == nil {
                if err := w.Client.SubmitScanFindings(ctx, job.ID, host.ID, scanJSON, res.Findings); err != nil {
                    log.Printf("submit findings for %s: %v", host.ID, err)
                }
            }
        } else {
            failed++
            progress[0].Status = "failed"
            progress[0].Error = res.Error
        }

        if err := w.Client.SubmitScanProgress(ctx, job.ID, progress); err != nil {
            log.Printf("submit progress: %v", err)
        }
    }

    finalStatus := "completed"
    if done == 0 { finalStatus = "failed" }
    errMsg := ""
    if failed > 0 && done > 0 { errMsg = fmt.Sprintf("%d of %d hosts failed", failed, len(job.Hosts)) }
    if err := w.Client.FinishScanJob(ctx, job.ID, finalStatus, errMsg); err != nil {
        log.Printf("finish scan job: %v", err)
    }
}
```

Tests: stub ScanAPI + stub Executor (inject interface), verify correct progress/finish calls.

Commit: `feat(engine/scanexec): scan job worker — claim, execute, submit, finish`

---

### Task 8: Client extensions

Add to `pkg/engine/client/client.go`:

```go
type ScanJobPayload struct {
    ID                  string            `json:"id"`
    ScanProfile         string            `json:"scan_profile"`
    CredentialSecretRef *string           `json:"credential_secret_ref,omitempty"`
    CredentialAuthType  string            `json:"credential_auth_type,omitempty"`
    Hosts               []ScanHostTarget  `json:"hosts"`
}

type ScanHostTarget struct {
    ID       string `json:"id"`
    Address  string `json:"address"`
    Port     int    `json:"port"`
    Hostname string `json:"hostname,omitempty"`
    OS       string `json:"os,omitempty"`
}

type ScanProgressUpdate struct {
    HostID        string `json:"host_id"`
    Status        string `json:"status"`
    FindingsCount int    `json:"findings_count"`
    Error         string `json:"error,omitempty"`
}

func (c *Client) PollScanJob(ctx context.Context) (*ScanJobPayload, error) { /* long-poll 45s */ }
func (c *Client) SubmitScanProgress(ctx context.Context, jobID string, updates []ScanProgressUpdate) error { /* POST */ }
func (c *Client) SubmitScanFindings(ctx context.Context, jobID, hostID string, scanResult []byte, findings int) error { /* POST with multipart or base64 scan result */ }
func (c *Client) FinishScanJob(ctx context.Context, jobID, status, errMsg string) error { /* POST */ }
```

For findings submit: body = `{host_id, findings_count, scan_result (base64 or raw JSON)}`. Simpler to use raw JSON (no base64) — wire format is:

```json
{
  "host_id": "uuid",
  "findings_count": 42,
  "scan_result": { ... the entire model.ScanResult ... }
}
```

Portal deserializes `scan_result` into `model.ScanResult`, calls `RecordScanResult` which calls `SaveScanWithJobContext`.

Tests: httptest roundtrip per endpoint.

Commit: `feat(engine/client): scan job methods (poll, progress, findings, finish)`

---

### Task 9: Loop + main wiring

Extend `pkg/engine/loop/loop.go` `Config` with `ScanWorker Worker` slot. Start after enroll.

Extend `cmd/triton-engine/main.go`:

```go
scanExec := &scanexec.Executor{Keystore: ks}
scanWorker := &scanexec.Worker{Client: c, Executor: scanExec}
cfg := loop.Config{
    DiscoveryWorker:      discoveryWorker,
    CredentialHandler:    credHandler,
    CredentialTestWorker: credTestWorker,
    ScanWorker:           scanWorker,  // NEW
    OnEnrolled:           ...,
}
```

Commit: `feat(engine): wire scan worker into loop and main`

---

### Task 10: Portal server wiring + stale reaper

Create `pkg/server/scanjobs/stale_reaper.go` (mirror Phase 3/4 pattern). 5min interval, 30min timeout (scan jobs run longer than credential tests).

Wire in `cmd/server.go` + `cmd/server_engine.go`. Thread `scanJobsStore` to `startEngineGateway`. Start reaper goroutine.

Commit: `feat(server): wire scan-jobs admin + gateway + stale reaper`

---

### Task 11: Management UI — scan jobs

Changes to `pkg/server/ui/dist/manage/app.js`:

- Add `#/scan-jobs` route (list) + `#/scan-jobs/{uuid}` route (detail with progress + per-host status + findings count)
- Add "Scan now" button on `#/groups/{id}` (need to add group-detail route if not present — else add on the main Groups list row)
- On click: prompt for scan profile (dropdown) + optional credential profile → POST to `/api/v1/manage/scan-jobs/` with `group_id` → navigate to detail page
- Detail page auto-refreshes every 5s while status ∈ {queued, claimed, running}
- "Cancel" button on queued jobs (Engineer+)
- Link to "View findings →" when job completed → goes to existing reports dashboard filtered by `scan_job_id`

Add "Scans" nav link to `index.html`.

Commit: `feat(ui): scan jobs page + "Scan now" action on groups`

---

### Task 12: End-to-end smoke + verification + PR + review

- [ ] `go build ./...` clean
- [ ] `make lint` 0 issues
- [ ] Unit tests: all new packages
- [ ] Integration: `TRITON_TEST_DB_URL=... go test -tags integration ./pkg/server/scanjobs/`
- [ ] Push branch, open PR, dispatch pensive:code-reviewer + pensive:architecture-reviewer
- [ ] Address Critical + Important findings
- [ ] Merge

---

## Self-Review Checklist

**Spec coverage (§6 step 6):**
- Portal-triggered scan produces findings visible in existing dashboard ✓ (via scans+findings table tags)
- Scan profile selection ✓
- Credential profile binding ✓
- Progress feedback ✓ (5s auto-refresh)

**Placeholder scan:** Version 21 is a real number. Scanner API method names (`SetFileReader`, `scannerconfig.DefaultConfig`) flagged for verification at Task 6 Step 1.

**Type consistency:** `Job`, `JobPayload`, `HostTarget`, `ProgressUpdate` consistent across store/handlers/client. `ScanProfile` type used uniformly.

**Explicit deviations from spec:**
1. One-engine-per-job rule — if a group spans two engines, user must split manually. Alternative (auto-fan-out into N jobs) is more complex; deferred.
2. Per-host scan is sequential, not parallel, within one job. Simpler; can parallelize in a follow-up if latency becomes a bottleneck.
3. SSH host-key verification uses `InsecureIgnoreHostKey` for MVP. Production deployment should pin known_hosts (follow-up).
4. Windows hosts (WinRM) not supported in Phase 5 — agent-push in Phase 6.
5. `SubmitScanFindings` sends the full `ScanResult` JSON over mTLS. For very large result sets this may be slow — acceptable for MVP.

**Architectural tech debt (flagged):**
- **TD-A1 still open**: 4 copies of the engine job-queue pattern (discovery + cred-delivery + cred-test + scan-jobs). Extract in Phase 5.5 refactor PR.
- **TD-A3 still open**: gateway audit on scan submits/finishes. Add alongside the job-queue refactor.

**Risks implementer might miss:**
- `scanner.Engine` API name — verify before Task 6 Step 3 coding.
- `SaveScanWithFindings` transaction semantics — must preserve incremental scanning support (Phase 1 added findings_extracted_at marker).
- `RecordScanResult` must NOT conflict with the existing scan-submit path used by the CLI (`/api/v1/scans` accepting a full scan payload). Different endpoint, different auth (JWT vs mTLS), different table writes (same underlying columns with the new tags populated).
