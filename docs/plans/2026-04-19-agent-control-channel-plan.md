# Agent Remote Control Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a long-poll control channel from Report Server to in-host agents carrying persistent pause state + transient `cancel` / `force_run` commands, tenant-scoped and machine-identified via `X-Triton-Machine-ID`.

**Architecture:** Extends the existing 30s-long-poll / 1s-check pattern used by engines (`pkg/server/{discovery,scanjobs,agentpush,credentials}/handlers_gateway.go`). Two new tables (`agents`, `agent_commands`) on the Report Server store. Agent grows one `commandPollLoop` goroutine that coordinates with the scan loop via a mutex-guarded state struct + a 1-slot `forceRunCh`. Admin UI is **out of scope** — this PR ships the backend only.

**Tech Stack:** Go 1.25, PostgreSQL 18 (pgx/v5), `go-chi/chi/v5`. Reuses existing `pkg/server/tenant_context.go::UnifiedAuth` for licence-token auth; adds a minimal middleware to extract `X-Triton-Machine-ID`.

**Spec:** `docs/plans/2026-04-19-agent-control-channel-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `pkg/store/migrations.go` | New migration adding `agents` + `agent_commands` tables (next slot in the slice — currently 24 entries, so #25). |
| `pkg/store/agents.go` (new) | `AgentRecord`, `AgentCommand` types + `AgentStore` interface extension + Postgres impls: `UpsertAgent`, `GetAgent`, `ListAgentsByTenant`, `SetAgentPausedUntil`, `ClearAgentPausedUntil`, `EnqueueAgentCommand`, `ClaimPendingCommandsForAgent`, `SetAgentCommandResult`, `ListAgentCommands`, `ExpireStaleAgentCommands`. |
| `pkg/store/agents_test.go` (new) | Unit tests for CRUD + invariants. |
| `pkg/store/store.go` | Extend `Store` interface to compose `AgentStore`. |
| `pkg/server/agent_control.go` (new) | Shared types: request/response JSON shapes for both agent-facing and admin-facing endpoints. Keeps wire shapes DRY across handlers. |
| `pkg/server/handlers_agent_commands.go` (new) | `handleAgentCommandsPoll` (long-poll) + `handleAgentCommandResult` (agent-side ack). |
| `pkg/server/handlers_admin_agents.go` (new) | Admin list/detail + enqueue + pause/unpause handlers. |
| `pkg/server/machineid_middleware.go` (new) | Small middleware that reads `X-Triton-Machine-ID` (required on agent-facing endpoints), validates shape (64 hex chars = sha3-256 hex), and stashes in context. |
| `pkg/server/server.go` | Register new routes + middleware wiring. |
| `pkg/agent/control.go` (new) | `CommandPoller` struct + `Poll` + `PostResult` methods on the `agent.Client` (or new dedicated client — see Task 6 for shape decision). |
| `pkg/agent/control_test.go` (new) | Unit tests for the poll client with `httptest`. |
| `cmd/agent.go` | Add `agentControlState`, spawn `commandPollLoop` goroutine when `reportServer != ""`, extend main scan loop to honour `pausedUntil` + receive on `forceRunCh` + publish `scanCancel`. |
| `cmd/agent_control_test.go` (new) | Unit tests for the integration glue (fake `CommandPoller`, verify cancel path + force-run path + pause path). |
| `test/integration/agent_control_channel_test.go` (new) | Full-lifecycle integration test. |
| `docs/DEPLOYMENT_GUIDE.md` | New §7c-quater "Remote control channel". |
| `CLAUDE.md` | One paragraph under Agent scheduling referencing the poll loop. |

Rough size: ~900 LOC production, ~1200 LOC tests, ~80 LOC docs.

---

## Task 1: Migration — agents + agent_commands tables

**Files:**
- Modify: `pkg/store/migrations.go`
- Test: `pkg/store/agents_test.go` (new)

- [ ] **Step 1: Read current migration count**

Run:
```bash
grep -c "^	\`" pkg/store/migrations.go
```

Expected: 24. Confirm your new migration becomes slice index 24 (0-based), i.e. the 25th entry.

- [ ] **Step 2: Write the failing column-existence test**

Create `pkg/store/agents_test.go`:

```go
//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigration_AgentControlTables(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for _, tc := range []struct {
		table, column, wantType string
	}{
		{"agents", "tenant_id", "uuid"},
		{"agents", "machine_id", "text"},
		{"agents", "paused_until", "timestamp with time zone"},
		{"agent_commands", "id", "uuid"},
		{"agent_commands", "type", "text"},
		{"agent_commands", "dispatched_at", "timestamp with time zone"},
		{"agent_commands", "args", "jsonb"},
	} {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			got, err := columnDataType(ctx, s, tc.table, tc.column)
			require.NoError(t, err)
			assert.Equal(t, tc.wantType, got)
		})
	}
}

// columnDataType is a small introspection helper. Add it at the bottom
// of the file if it doesn't already exist; otherwise skip.
func columnDataType(ctx context.Context, s interface {
	QueryRow(ctx context.Context, sql string, args ...any) interface {
		Scan(dest ...any) error
	}
}, table, column string) (string, error) {
	panic("replace me — see Step 2b")
}
```

Before step 3, check whether an introspection helper already exists:

```bash
grep -n "information_schema.columns\|QueryRowForTest\|func (s \*PostgresStore) Pool" pkg/store/*.go
```

If there's no existing accessor, add one minimal helper to `pkg/store/postgres.go`:

```go
// QueryColumnTestOnly returns the data_type of (table, column) or empty
// string if not found. Exported for integration tests only; not part
// of the Store interface.
func (s *PostgresStore) QueryColumnTestOnly(ctx context.Context, table, column string) (string, error) {
	var dt string
	err := s.pool.QueryRow(ctx, `
		SELECT data_type FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = $1 AND column_name = $2`, table, column).Scan(&dt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return dt, err
}
```

Then replace the `columnDataType` test helper to use it:

```go
func columnDataType(ctx context.Context, s *store.PostgresStore, table, column string) (string, error) {
	return s.QueryColumnTestOnly(ctx, table, column)
}
```

Adjust the test signature to match the real `*store.PostgresStore`.

- [ ] **Step 3: Run tests to verify they fail**

Run:
```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestMigration_AgentControlTables ./pkg/store/ -v
```

Expected: FAIL — `agents` table doesn't exist yet.

- [ ] **Step 4: Add the migration**

In `pkg/store/migrations.go`, append a new string entry to the `migrations` slice (preserve trailing-comma style):

```go
	`-- Agent remote control channel (step 6).
	-- Adds per-agent registry + pending/completed command queue for the
	-- Report Server long-poll control plane. See
	-- docs/plans/2026-04-19-agent-control-channel-design.md.
	CREATE TABLE IF NOT EXISTS agents (
		tenant_id     UUID        NOT NULL,
		machine_id    TEXT        NOT NULL,
		hostname      TEXT        NOT NULL DEFAULT '',
		os            TEXT        NOT NULL DEFAULT '',
		arch          TEXT        NOT NULL DEFAULT '',
		first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		paused_until  TIMESTAMPTZ,
		PRIMARY KEY (tenant_id, machine_id)
	);

	CREATE INDEX IF NOT EXISTS agents_last_seen_idx
		ON agents (tenant_id, last_seen_at);

	CREATE TABLE IF NOT EXISTS agent_commands (
		id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id     UUID        NOT NULL,
		machine_id    TEXT        NOT NULL,
		type          TEXT        NOT NULL CHECK (type IN ('cancel', 'force_run')),
		args          JSONB       NOT NULL DEFAULT '{}',
		issued_by     TEXT        NOT NULL,
		issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at    TIMESTAMPTZ NOT NULL,
		dispatched_at TIMESTAMPTZ,
		result_status TEXT,
		result_meta   JSONB,
		resulted_at   TIMESTAMPTZ,
		FOREIGN KEY (tenant_id, machine_id) REFERENCES agents(tenant_id, machine_id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS agent_commands_pending_idx
		ON agent_commands (tenant_id, machine_id, issued_at)
		WHERE dispatched_at IS NULL;

	CREATE INDEX IF NOT EXISTS agent_commands_history_idx
		ON agent_commands (tenant_id, machine_id, issued_at DESC);`,
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestMigration_AgentControlTables ./pkg/store/ -v
```

Expected: all 7 subtests PASS.

- [ ] **Step 6: Run full store suite to confirm no regression**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/store/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/store/migrations.go pkg/store/postgres.go pkg/store/agents_test.go
git commit -m "store: migration adds agents + agent_commands tables

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Only stage `postgres.go` if you added the `QueryColumnTestOnly` helper.

---

## Task 2: AgentRecord + AgentCommand types + AgentStore interface

**Files:**
- Create: `pkg/store/agents.go`
- Modify: `pkg/store/store.go`
- Test: `pkg/store/agents_test.go` (append)

- [ ] **Step 1: Write the failing struct-shape test**

Append to `pkg/store/agents_test.go`:

```go
func TestAgentRecord_ZeroValues(t *testing.T) {
	var a store.AgentRecord
	assert.Empty(t, a.TenantID)
	assert.Empty(t, a.MachineID)
	assert.True(t, a.PausedUntil.IsZero())
}

func TestAgentCommand_ZeroValues(t *testing.T) {
	var c store.AgentCommand
	assert.Empty(t, c.ID)
	assert.Empty(t, c.Type)
	assert.Nil(t, c.DispatchedAt)
}
```

Add `"github.com/amiryahaya/triton/pkg/store"` to imports.

- [ ] **Step 2: Run test to verify it fails**

```bash
go build ./pkg/store/...
```

Expected: FAIL — `store.AgentRecord` / `store.AgentCommand` undefined.

- [ ] **Step 3: Create types + interface**

Create `pkg/store/agents.go`:

```go
package store

import (
	"context"
	"encoding/json"
	"time"
)

// AgentRecord is the per-machine control row on the Report Server.
// See docs/plans/2026-04-19-agent-control-channel-design.md.
type AgentRecord struct {
	TenantID    string    `json:"tenantID"`
	MachineID   string    `json:"machineID"`   // sha3-256 hex from license.MachineFingerprint()
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	PausedUntil time.Time `json:"pausedUntil,omitempty"` // zero = not paused
}

// AgentCommandType enumerates the transient commands admin can issue.
// Persistent state (pause) uses a separate field on AgentRecord.
type AgentCommandType string

const (
	AgentCommandCancel   AgentCommandType = "cancel"
	AgentCommandForceRun AgentCommandType = "force_run"
)

// AgentCommand is a single queued or historical command for an agent.
// DispatchedAt is nil while the command is pending; set when the poll
// handler returns it on the wire (inside the same transaction as the
// claim). ResultStatus is nil while still pending or dispatched-but-
// unacknowledged; set by the agent's result POST.
type AgentCommand struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenantID"`
	MachineID    string           `json:"machineID"`
	Type         AgentCommandType `json:"type"`
	Args         json.RawMessage  `json:"args"`
	IssuedBy     string           `json:"issuedBy"`
	IssuedAt     time.Time        `json:"issuedAt"`
	ExpiresAt    time.Time        `json:"expiresAt"`
	DispatchedAt *time.Time       `json:"dispatchedAt,omitempty"`
	ResultStatus *string          `json:"resultStatus,omitempty"` // executed | rejected | expired
	ResultMeta   json.RawMessage  `json:"resultMeta,omitempty"`
	ResultedAt   *time.Time       `json:"resultedAt,omitempty"`
}

// AgentStore is the persistence surface for the remote control channel.
// See individual method docs for semantics.
type AgentStore interface {
	// UpsertAgent creates the row on first-seen or updates hostname/os/arch
	// + last_seen_at on subsequent polls. Paused_until is never written
	// here — admin endpoints own that field.
	UpsertAgent(ctx context.Context, a *AgentRecord) error

	// GetAgent returns the row for (tenantID, machineID) or ErrNotFound
	// when the agent has never polled.
	GetAgent(ctx context.Context, tenantID, machineID string) (*AgentRecord, error)

	// ListAgentsByTenant returns all agents for a tenant, newest-last-seen
	// first. limit <= 0 means no limit.
	ListAgentsByTenant(ctx context.Context, tenantID string, limit int) ([]AgentRecord, error)

	// SetAgentPausedUntil writes paused_until. Caller validates the 90-day
	// cap at the admin-API layer; the store only enforces the existence of
	// the (tenantID, machineID) row. Returns ErrNotFound for unknown agents.
	SetAgentPausedUntil(ctx context.Context, tenantID, machineID string, until time.Time) error

	// ClearAgentPausedUntil sets paused_until to NULL. ErrNotFound for
	// unknown agents.
	ClearAgentPausedUntil(ctx context.Context, tenantID, machineID string) error

	// EnqueueAgentCommand inserts a pending command. Returns the created
	// record with server-assigned ID and IssuedAt.
	EnqueueAgentCommand(ctx context.Context, cmd *AgentCommand) (*AgentCommand, error)

	// ClaimPendingCommandsForAgent atomically marks all pending, unexpired
	// commands for (tenantID, machineID) as dispatched (dispatched_at = NOW())
	// and returns them. Commands already dispatched are not re-claimed.
	// Expired-but-not-yet-dispatched commands are skipped and NOT returned.
	ClaimPendingCommandsForAgent(ctx context.Context, tenantID, machineID string) ([]AgentCommand, error)

	// SetAgentCommandResult records the agent's executed/rejected outcome.
	// Returns ErrNotFound when the command ID does not exist for this
	// (tenantID, machineID) pair — prevents cross-agent result injection.
	SetAgentCommandResult(ctx context.Context, tenantID, machineID, commandID, status string, meta json.RawMessage) error

	// ListAgentCommands returns up to `limit` most-recent commands for
	// (tenantID, machineID), newest-first. Used by admin detail view.
	ListAgentCommands(ctx context.Context, tenantID, machineID string, limit int) ([]AgentCommand, error)

	// ExpireStaleAgentCommands marks dispatched-but-unacked commands with
	// expires_at < now as result_status = 'expired'. Returns the number
	// updated. Intended for a background sweep; no-op if nothing matches.
	ExpireStaleAgentCommands(ctx context.Context) (int, error)
}
```

- [ ] **Step 4: Extend `Store` interface**

In `pkg/store/store.go`, the existing `type Store interface { ScanStore; HashStore; OrgStore; UserStore; SessionStore; AuditStore; ... }` — add `AgentStore` to the embedded list:

```go
type Store interface {
	ScanStore
	HashStore
	OrgStore
	UserStore
	SessionStore
	AuditStore
	AgentStore
	// ...existing methods
}
```

- [ ] **Step 5: Run test to verify struct tests pass**

```bash
go test ./pkg/store/ -run "TestAgentRecord_ZeroValues|TestAgentCommand_ZeroValues" -v
```

Expected: PASS.

- [ ] **Step 6: Build fails because PostgresStore doesn't implement the methods yet — but that's Task 3's job**

```bash
go build ./pkg/store/...
```

Expected: build error because `*PostgresStore` doesn't satisfy `AgentStore` yet. That's fine — Task 3 implements it.

- [ ] **Step 7: Commit (broken build is OK at this point — Task 3 fixes it)**

Actually, to avoid a broken-build commit, defer step 4's interface change until Task 3 so that interface + impl land together. Skip step 4 here and only stage the types.

```bash
git add pkg/store/agents.go pkg/store/agents_test.go
git commit -m "store: add AgentRecord, AgentCommand types + AgentStore interface

Interface is declared but not yet wired into Store composition; that
lands in the next commit alongside the PostgresStore impl.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: PostgresStore AgentStore implementations

**Files:**
- Modify: `pkg/store/postgres.go` (add new methods; grows the file)
- Modify: `pkg/store/store.go` (add `AgentStore` to `Store` composition — deferred from Task 2)
- Test: `pkg/store/agents_test.go` (append round-trip tests)

- [ ] **Step 1: Write the failing round-trip test**

Append to `pkg/store/agents_test.go`:

```go
func TestAgentStore_UpsertGetList(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant := newTestTenant(t, s) // existing helper in package test files — search for it

	// Upsert creates on first call.
	r := &store.AgentRecord{
		TenantID:  tenant,
		MachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Hostname:  "host-1",
		OS:        "linux",
		Arch:      "amd64",
	}
	require.NoError(t, s.UpsertAgent(ctx, r))

	got, err := s.GetAgent(ctx, tenant, r.MachineID)
	require.NoError(t, err)
	assert.Equal(t, "host-1", got.Hostname)
	assert.False(t, got.FirstSeenAt.IsZero())

	// Upsert updates on second call with different hostname.
	r.Hostname = "host-1-renamed"
	require.NoError(t, s.UpsertAgent(ctx, r))
	got, _ = s.GetAgent(ctx, tenant, r.MachineID)
	assert.Equal(t, "host-1-renamed", got.Hostname)

	// List returns it.
	rows, err := s.ListAgentsByTenant(ctx, tenant, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, r.MachineID, rows[0].MachineID)
}

func TestAgentStore_PausedUntilRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant := newTestTenant(t, s)
	mid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.NoError(t, s.UpsertAgent(ctx, &store.AgentRecord{TenantID: tenant, MachineID: mid}))

	until := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, s.SetAgentPausedUntil(ctx, tenant, mid, until))

	got, _ := s.GetAgent(ctx, tenant, mid)
	assert.WithinDuration(t, until, got.PausedUntil, time.Second)

	require.NoError(t, s.ClearAgentPausedUntil(ctx, tenant, mid))
	got, _ = s.GetAgent(ctx, tenant, mid)
	assert.True(t, got.PausedUntil.IsZero(), "cleared paused_until should surface as zero")
}

func TestAgentStore_CommandLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant := newTestTenant(t, s)
	mid := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	require.NoError(t, s.UpsertAgent(ctx, &store.AgentRecord{TenantID: tenant, MachineID: mid}))

	// Enqueue.
	cmd, err := s.EnqueueAgentCommand(ctx, &store.AgentCommand{
		TenantID:  tenant,
		MachineID: mid,
		Type:      store.AgentCommandCancel,
		Args:      []byte(`{}`),
		IssuedBy:  "admin-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cmd.ID)
	assert.Nil(t, cmd.DispatchedAt)

	// Claim dispatches and returns it.
	claimed, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	assert.NotNil(t, claimed[0].DispatchedAt)

	// Re-claim returns nothing (already dispatched).
	claimed2, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	assert.Empty(t, claimed2)

	// Result POST.
	require.NoError(t, s.SetAgentCommandResult(ctx, tenant, mid, cmd.ID, "executed", []byte(`{"findings":0}`)))

	// List history.
	history, err := s.ListAgentCommands(ctx, tenant, mid, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.NotNil(t, history[0].ResultStatus)
	assert.Equal(t, "executed", *history[0].ResultStatus)
}

func TestAgentStore_ExpiredCommandsNotClaimed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant := newTestTenant(t, s)
	mid := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	require.NoError(t, s.UpsertAgent(ctx, &store.AgentRecord{TenantID: tenant, MachineID: mid}))

	_, err := s.EnqueueAgentCommand(ctx, &store.AgentCommand{
		TenantID:  tenant,
		MachineID: mid,
		Type:      store.AgentCommandForceRun,
		Args:      []byte(`{}`),
		IssuedBy:  "admin-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
	})
	require.NoError(t, err)

	claimed, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	assert.Empty(t, claimed, "expired commands should not be claimed")
}

func TestAgentStore_ResultRejectsCrossAgent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant := newTestTenant(t, s)
	midA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	midB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.NoError(t, s.UpsertAgent(ctx, &store.AgentRecord{TenantID: tenant, MachineID: midA}))
	require.NoError(t, s.UpsertAgent(ctx, &store.AgentRecord{TenantID: tenant, MachineID: midB}))

	cmd, _ := s.EnqueueAgentCommand(ctx, &store.AgentCommand{
		TenantID: tenant, MachineID: midA, Type: store.AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "admin-1", ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// Attempting to ack as midB should fail (ErrNotFound).
	err := s.SetAgentCommandResult(ctx, tenant, midB, cmd.ID, "executed", nil)
	require.Error(t, err)
}
```

`newTestTenant` likely exists; search with:
```bash
grep -rn "func newTestTenant\|createTestOrg" pkg/store/*_test.go | head
```

If it doesn't, add a tiny local helper at the bottom of `agents_test.go`:

```go
func newTestTenant(t *testing.T, s *store.PostgresStore) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	require.NoError(t, s.UpsertOrganization(context.Background(), &store.Organization{ID: id, Name: "TenantAgentCtl-" + id[:8]}))
	return id
}
```

Adjust to the actual Org type/method name used in the package.

- [ ] **Step 2: Run tests to verify they fail**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestAgentStore_" ./pkg/store/ -v
```

Expected: build fails (methods don't exist on `*PostgresStore`).

- [ ] **Step 3: Implement the methods on `*PostgresStore`**

Append to `pkg/store/postgres.go` (keep the file's existing import block tidy — `encoding/json`, `time`, `errors`, `pgx/v5` should all already be imported; add any that aren't):

```go
// UpsertAgent creates or updates the agent row; touches last_seen_at
// on every call. paused_until is never written here.
func (s *PostgresStore) UpsertAgent(ctx context.Context, a *AgentRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (tenant_id, machine_id, hostname, os, arch)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, machine_id) DO UPDATE SET
			hostname     = EXCLUDED.hostname,
			os           = EXCLUDED.os,
			arch         = EXCLUDED.arch,
			last_seen_at = NOW()
	`, a.TenantID, a.MachineID, a.Hostname, a.OS, a.Arch)
	if err != nil {
		return fmt.Errorf("upserting agent: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAgent(ctx context.Context, tenantID, machineID string) (*AgentRecord, error) {
	var a AgentRecord
	var paused pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, machine_id, hostname, os, arch,
		       first_seen_at, last_seen_at, paused_until
		FROM agents
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID,
	).Scan(&a.TenantID, &a.MachineID, &a.Hostname, &a.OS, &a.Arch,
		&a.FirstSeenAt, &a.LastSeenAt, &paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "agent", ID: machineID}
	}
	if err != nil {
		return nil, fmt.Errorf("getting agent: %w", err)
	}
	if paused.Valid {
		a.PausedUntil = paused.Time
	}
	return &a, nil
}

func (s *PostgresStore) ListAgentsByTenant(ctx context.Context, tenantID string, limit int) ([]AgentRecord, error) {
	q := `
		SELECT tenant_id, machine_id, hostname, os, arch,
		       first_seen_at, last_seen_at, paused_until
		FROM agents
		WHERE tenant_id = $1
		ORDER BY last_seen_at DESC`
	args := []any{tenantID}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer rows.Close()
	var out []AgentRecord
	for rows.Next() {
		var a AgentRecord
		var paused pgtype.Timestamptz
		if err := rows.Scan(&a.TenantID, &a.MachineID, &a.Hostname, &a.OS, &a.Arch,
			&a.FirstSeenAt, &a.LastSeenAt, &paused); err != nil {
			return nil, fmt.Errorf("scanning agent: %w", err)
		}
		if paused.Valid {
			a.PausedUntil = paused.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetAgentPausedUntil(ctx context.Context, tenantID, machineID string, until time.Time) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE agents SET paused_until = $3
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID, until)
	if err != nil {
		return fmt.Errorf("setting paused_until: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent", ID: machineID}
	}
	return nil
}

func (s *PostgresStore) ClearAgentPausedUntil(ctx context.Context, tenantID, machineID string) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE agents SET paused_until = NULL
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID)
	if err != nil {
		return fmt.Errorf("clearing paused_until: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent", ID: machineID}
	}
	return nil
}

func (s *PostgresStore) EnqueueAgentCommand(ctx context.Context, cmd *AgentCommand) (*AgentCommand, error) {
	if cmd.Args == nil {
		cmd.Args = []byte(`{}`)
	}
	var out AgentCommand
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_commands (tenant_id, machine_id, type, args, issued_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, tenant_id, machine_id, type, args, issued_by, issued_at, expires_at`,
		cmd.TenantID, cmd.MachineID, string(cmd.Type), cmd.Args, cmd.IssuedBy, cmd.ExpiresAt,
	).Scan(&out.ID, &out.TenantID, &out.MachineID, &out.Type,
		&out.Args, &out.IssuedBy, &out.IssuedAt, &out.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("enqueuing agent command: %w", err)
	}
	return &out, nil
}

func (s *PostgresStore) ClaimPendingCommandsForAgent(ctx context.Context, tenantID, machineID string) ([]AgentCommand, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE agent_commands
		SET dispatched_at = NOW()
		WHERE id IN (
			SELECT id FROM agent_commands
			WHERE tenant_id = $1 AND machine_id = $2
			  AND dispatched_at IS NULL
			  AND expires_at > NOW()
			ORDER BY issued_at ASC
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, machine_id, type, args, issued_by,
		          issued_at, expires_at, dispatched_at`,
		tenantID, machineID)
	if err != nil {
		return nil, fmt.Errorf("claiming agent commands: %w", err)
	}
	defer rows.Close()
	var out []AgentCommand
	for rows.Next() {
		var c AgentCommand
		var dispatched pgtype.Timestamptz
		if err := rows.Scan(&c.ID, &c.TenantID, &c.MachineID, &c.Type,
			&c.Args, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt, &dispatched); err != nil {
			return nil, fmt.Errorf("scanning command: %w", err)
		}
		if dispatched.Valid {
			t := dispatched.Time
			c.DispatchedAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetAgentCommandResult(ctx context.Context, tenantID, machineID, commandID, status string, meta json.RawMessage) error {
	if meta == nil {
		meta = []byte(`{}`)
	}
	res, err := s.pool.Exec(ctx, `
		UPDATE agent_commands
		SET result_status = $4, result_meta = $5, resulted_at = NOW()
		WHERE id = $3 AND tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID, commandID, status, meta)
	if err != nil {
		return fmt.Errorf("setting command result: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent_command", ID: commandID}
	}
	return nil
}

func (s *PostgresStore) ListAgentCommands(ctx context.Context, tenantID, machineID string, limit int) ([]AgentCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, machine_id, type, args, issued_by,
		       issued_at, expires_at, dispatched_at, result_status, result_meta, resulted_at
		FROM agent_commands
		WHERE tenant_id = $1 AND machine_id = $2
		ORDER BY issued_at DESC
		LIMIT $3`, tenantID, machineID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing commands: %w", err)
	}
	defer rows.Close()
	var out []AgentCommand
	for rows.Next() {
		var c AgentCommand
		var dispatched, resulted pgtype.Timestamptz
		var status pgtype.Text
		var meta []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.MachineID, &c.Type,
			&c.Args, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt,
			&dispatched, &status, &meta, &resulted); err != nil {
			return nil, fmt.Errorf("scanning command: %w", err)
		}
		if dispatched.Valid {
			t := dispatched.Time
			c.DispatchedAt = &t
		}
		if status.Valid {
			st := status.String
			c.ResultStatus = &st
		}
		if resulted.Valid {
			t := resulted.Time
			c.ResultedAt = &t
		}
		if len(meta) > 0 {
			c.ResultMeta = meta
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ExpireStaleAgentCommands(ctx context.Context) (int, error) {
	res, err := s.pool.Exec(ctx, `
		UPDATE agent_commands
		SET result_status = 'expired', resulted_at = NOW()
		WHERE dispatched_at IS NOT NULL
		  AND result_status IS NULL
		  AND expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("expiring stale commands: %w", err)
	}
	return int(res.RowsAffected()), nil
}
```

Add to the top imports of `postgres.go` if not already present: `"github.com/jackc/pgx/v5/pgtype"` (likely already imported — grep first).

- [ ] **Step 4: Add `AgentStore` to the `Store` interface**

In `pkg/store/store.go`, extend the composition:

```go
type Store interface {
	ScanStore
	HashStore
	OrgStore
	UserStore
	SessionStore
	AuditStore
	AgentStore
	// ...existing methods below
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestAgentStore_" ./pkg/store/ -v
```

Expected: all 5 subtests PASS.

- [ ] **Step 6: Verify no build breakage across the repo**

```bash
go build ./...
```

Expected: clean. If any mocks implementing `Store` exist outside `pkg/store/`, they need `UpsertAgent` + 8 other stub methods. Find them:

```bash
grep -rln "var _ store.Store\|implements store.Store" pkg/ --include="*.go"
```

For each, add minimal stub methods returning `nil, nil` or `nil` — most mocks are in tests and are already tolerant of interface growth via embedding a `store.PostgresStore` directly.

- [ ] **Step 7: Run full store suite**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/store/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/store/postgres.go pkg/store/store.go
git commit -m "store: PostgresStore AgentStore impl + interface composition

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Machine-ID middleware + wire shape types

**Files:**
- Create: `pkg/server/machineid_middleware.go`
- Create: `pkg/server/agent_control.go`
- Test: `pkg/server/machineid_middleware_test.go` (new)

- [ ] **Step 1: Write the failing middleware test**

Create `pkg/server/machineid_middleware_test.go`:

```go
package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineIDMiddleware_Valid(t *testing.T) {
	var captured string
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = MachineIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	valid := strings.Repeat("a", 64)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", valid)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, valid, captured)
}

func TestMachineIDMiddleware_Missing(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMachineIDMiddleware_InvalidLength(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", "too-short")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMachineIDMiddleware_NonHex(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", strings.Repeat("z", 64))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "hex")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/server/ -run TestMachineIDMiddleware -v
```

Expected: FAIL — `RequireMachineID` undefined.

- [ ] **Step 3: Implement the middleware**

Create `pkg/server/machineid_middleware.go`:

```go
package server

import (
	"context"
	"encoding/hex"
	"net/http"
)

const machineIDHeader = "X-Triton-Machine-ID"

type machineIDCtxKey struct{}

// MachineIDFromContext returns the SHA3-256-hex machine fingerprint
// that RequireMachineID stashed in context, or empty string if the
// middleware hasn't run.
func MachineIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(machineIDCtxKey{}).(string)
	return v
}

// RequireMachineID validates the X-Triton-Machine-ID header as a
// 64-character lowercase-hex string (SHA3-256 digest from
// license.MachineFingerprint()) and stashes it in the request context.
// Missing header → 401. Malformed value → 400.
func RequireMachineID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(machineIDHeader)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "missing "+machineIDHeader+" header")
			return
		}
		if len(raw) != 64 {
			writeError(w, http.StatusBadRequest, machineIDHeader+" must be 64 hex characters")
			return
		}
		if _, err := hex.DecodeString(raw); err != nil {
			writeError(w, http.StatusBadRequest, machineIDHeader+" must be hex: "+err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), machineIDCtxKey{}, raw)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

- [ ] **Step 4: Create wire-shape types**

Create `pkg/server/agent_control.go`:

```go
package server

import (
	"encoding/json"
	"time"
)

// agentPollResponse is the payload returned by GET /api/v1/agent/commands/poll.
// Empty response → HTTP 204; handlers return this struct only when state
// or commands are non-empty.
type agentPollResponse struct {
	State    agentPollState      `json:"state"`
	Commands []agentPollCommand  `json:"commands,omitempty"`
}

type agentPollState struct {
	// PausedUntil is the UTC time until which the agent should pause.
	// Zero value serializes as an omitted field, which the agent reads
	// as "not paused" — same semantics as a past value.
	PausedUntil time.Time `json:"pausedUntil,omitempty"`
}

type agentPollCommand struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

// agentResultRequest is the body of POST /api/v1/agent/commands/{id}/result.
// Status is one of "executed", "rejected". Meta is opaque — whatever the
// agent wants to report back for this command type.
type agentResultRequest struct {
	Status string          `json:"status"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

// adminAgentCommandRequest is the admin enqueue-command body.
type adminAgentCommandRequest struct {
	Type             string          `json:"type"`
	Args             json.RawMessage `json:"args,omitempty"`
	ExpiresInMinutes int             `json:"expiresInMinutes,omitempty"` // default 60
}

// adminPauseRequest body. Exactly one of Until / DurationSeconds must be set.
type adminPauseRequest struct {
	Until           *time.Time `json:"until,omitempty"`
	DurationSeconds int        `json:"durationSeconds,omitempty"`
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./pkg/server/ -run TestMachineIDMiddleware -v
```

Expected: all 4 subtests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/server/machineid_middleware.go pkg/server/machineid_middleware_test.go pkg/server/agent_control.go
git commit -m "server: machine-id middleware + agent-control wire types

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Agent-facing handlers (poll + result)

**Files:**
- Create: `pkg/server/handlers_agent_commands.go`
- Test: `pkg/server/handlers_agent_commands_test.go` (new)

- [ ] **Step 1: Write failing tests**

Create `pkg/server/handlers_agent_commands_test.go`:

```go
//go:build integration

package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

func TestAgentPoll_EmptyReturns204(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()

	mid := strings.Repeat("a", 64)
	// Agent first-seen: server creates row.
	code, _ := pollAgent(t, ts.URL, licenseToken, mid, "host-1", "linux", "amd64")
	assert.Equal(t, http.StatusNoContent, code)

	// Row now exists.
	a, err := s.GetAgent(testCtx(t), tenant, mid)
	require.NoError(t, err)
	assert.Equal(t, "host-1", a.Hostname)
}

func TestAgentPoll_ReturnsPausedUntil(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()

	mid := strings.Repeat("b", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "host-b", "linux", "amd64")

	until := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, s.SetAgentPausedUntil(testCtx(t), tenant, mid, until))

	code, body := pollAgent(t, ts.URL, licenseToken, mid, "host-b", "linux", "amd64")
	assert.Equal(t, http.StatusOK, code)
	gotUntil, err := time.Parse(time.RFC3339, body["state"].(map[string]any)["pausedUntil"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, until, gotUntil, time.Second)
}

func TestAgentPoll_ClaimsAndDispatchesCommand(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()

	mid := strings.Repeat("c", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "host-c", "linux", "amd64")

	cmd, err := s.EnqueueAgentCommand(testCtx(t), &store.AgentCommand{
		TenantID: tenant, MachineID: mid, Type: store.AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "test", ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	code, body := pollAgent(t, ts.URL, licenseToken, mid, "host-c", "linux", "amd64")
	assert.Equal(t, http.StatusOK, code)
	cmds := body["commands"].([]any)
	require.Len(t, cmds, 1)
	assert.Equal(t, cmd.ID, cmds[0].(map[string]any)["id"])

	// Second poll returns 204 — command was dispatched.
	code2, _ := pollAgent(t, ts.URL, licenseToken, mid, "host-c", "linux", "amd64")
	assert.Equal(t, http.StatusNoContent, code2)
}

func TestAgentResult_Success(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()

	mid := strings.Repeat("d", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "host-d", "linux", "amd64")
	cmd, _ := s.EnqueueAgentCommand(testCtx(t), &store.AgentCommand{
		TenantID: tenant, MachineID: mid, Type: store.AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "test", ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "host-d", "linux", "amd64")

	code := postResult(t, ts.URL, licenseToken, mid, cmd.ID, "executed", map[string]any{"findings": 42})
	assert.Equal(t, http.StatusOK, code)

	history, _ := s.ListAgentCommands(testCtx(t), tenant, mid, 10)
	require.Len(t, history, 1)
	require.NotNil(t, history[0].ResultStatus)
	assert.Equal(t, "executed", *history[0].ResultStatus)
}

func TestAgentResult_CrossAgentRejected(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()

	midA := strings.Repeat("a", 64)
	midB := strings.Repeat("b", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, midA, "a", "linux", "amd64")
	_, _ = pollAgent(t, ts.URL, licenseToken, midB, "b", "linux", "amd64")
	cmd, _ := s.EnqueueAgentCommand(testCtx(t), &store.AgentCommand{
		TenantID: tenant, MachineID: midA, Type: store.AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "test", ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// midB tries to ack midA's command.
	code := postResult(t, ts.URL, licenseToken, midB, cmd.ID, "executed", nil)
	assert.Equal(t, http.StatusNotFound, code)
}

// Helpers — add these at the bottom of the file.

func pollAgent(t *testing.T, baseURL, token, machineID, hostname, os_, arch string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/commands/poll", nil)
	req.Header.Set("X-Triton-License-Token", token)
	req.Header.Set("X-Triton-Machine-ID", machineID)
	req.Header.Set("X-Triton-Hostname", hostname)
	req.Header.Set("X-Triton-Agent-OS", os_)
	req.Header.Set("X-Triton-Agent-Arch", arch)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func postResult(t *testing.T, baseURL, token, machineID, commandID, status string, meta map[string]any) int {
	t.Helper()
	body := map[string]any{"status": status}
	if meta != nil {
		body["meta"] = meta
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost,
		baseURL+"/api/v1/agent/commands/"+commandID+"/result", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-License-Token", token)
	req.Header.Set("X-Triton-Machine-ID", machineID)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}
```

The helper `newAgentControlTestServer` will be added in Task 7 (route registration). For now, the tests reference a helper you'll implement then. Leave the Task-5 tests as-is — they'll FAIL to compile until Task 7, but the production handler code in this task can still be written and compile-checked.

- [ ] **Step 2: Skip running the tests — defer to Task 7**

Task 5 implements handlers; Task 6 implements admin handlers; Task 7 wires them up and provides the test-server helper. Run all the tests together at Task 7.

- [ ] **Step 3: Implement the handlers**

Create `pkg/server/handlers_agent_commands.go`:

```go
package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

// Default long-poll window — matches the engine-gateway pattern.
const (
	agentPollTimeout  = 30 * time.Second
	agentPollInterval = 1 * time.Second
)

// handleAgentCommandsPoll is the agent's long-poll endpoint.
// Upserts the agent row on every request (first-seen creates, subsequent
// updates hostname/os/arch hints + last_seen_at). Atomically claims any
// pending unexpired commands for this (tenant, machine) and returns them,
// along with the persistent state (paused_until) from the agent row.
// Returns 204 No Content when state and commands are both empty after
// waiting up to agentPollTimeout.
func (s *Server) handleAgentCommandsPoll(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	machineID := MachineIDFromContext(r.Context())
	if tenant == "" || machineID == "" {
		writeError(w, http.StatusUnauthorized, "tenant or machine-id missing")
		return
	}

	// Upsert the agent row, using the optional hint headers.
	if err := s.store.UpsertAgent(r.Context(), &store.AgentRecord{
		TenantID:  tenant,
		MachineID: machineID,
		Hostname:  r.Header.Get("X-Triton-Hostname"),
		OS:        r.Header.Get("X-Triton-Agent-OS"),
		Arch:      r.Header.Get("X-Triton-Agent-Arch"),
	}); err != nil {
		log.Printf("agent poll: upsert agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	deadline := time.Now().Add(agentPollTimeout)
	for {
		// Fetch current paused_until + claim pending commands atomically
		// (two statements but both keyed by the same (tenant, machineID)).
		agent, err := s.store.GetAgent(r.Context(), tenant, machineID)
		if err != nil {
			log.Printf("agent poll: get agent: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		cmds, err := s.store.ClaimPendingCommandsForAgent(r.Context(), tenant, machineID)
		if err != nil {
			log.Printf("agent poll: claim: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Build response — omit entirely if nothing to send.
		hasPause := !agent.PausedUntil.IsZero() && agent.PausedUntil.After(time.Now())
		if !hasPause && len(cmds) == 0 {
			if time.Now().After(deadline) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(agentPollInterval):
			}
			continue
		}

		resp := agentPollResponse{}
		if hasPause {
			resp.State.PausedUntil = agent.PausedUntil
		}
		for _, c := range cmds {
			resp.Commands = append(resp.Commands, agentPollCommand{
				ID:        c.ID,
				Type:      string(c.Type),
				Args:      c.Args,
				IssuedAt:  c.IssuedAt,
				ExpiresAt: c.ExpiresAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
}

// handleAgentCommandResult records the agent-reported outcome for a
// previously-dispatched command. Rejects results where the command's
// machine_id does not match the calling agent (cross-agent tampering).
func (s *Server) handleAgentCommandResult(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	machineID := MachineIDFromContext(r.Context())
	if tenant == "" || machineID == "" {
		writeError(w, http.StatusUnauthorized, "tenant or machine-id missing")
		return
	}
	cmdID := chi.URLParam(r, "id")
	if cmdID == "" {
		writeError(w, http.StatusBadRequest, "command id required")
		return
	}

	var req agentResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Status {
	case "executed", "rejected":
	default:
		writeError(w, http.StatusBadRequest, "status must be 'executed' or 'rejected'")
		return
	}

	if err := s.store.SetAgentCommandResult(r.Context(), tenant, machineID, cmdID, req.Status, req.Meta); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "command not found")
			return
		}
		log.Printf("agent result: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

- [ ] **Step 4: Verify it compiles**

```bash
go build ./pkg/server/
```

Expected: clean. Handler tests won't run until Task 7 wires routes.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/handlers_agent_commands.go pkg/server/handlers_agent_commands_test.go
git commit -m "server: agent-facing long-poll + result handlers

Handlers compile; full tests run after Task 7 registers routes + adds
the test-server helper.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Admin-facing handlers

**Files:**
- Create: `pkg/server/handlers_admin_agents.go`
- Test: `pkg/server/handlers_admin_agents_test.go` (new)

- [ ] **Step 1: Write failing admin tests**

Create `pkg/server/handlers_admin_agents_test.go`:

```go
//go:build integration

package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestAdminAgents_List(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()
	adminJWT := newAdminJWT(t, ts.URL)

	mid := strings.Repeat("e", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "host-e", "linux", "amd64")
	_ = s // unused in this test but the helper seeds the tenant
	_ = tenant

	code, body := adminGet(t, ts.URL, adminJWT, "/api/v1/admin/agents")
	assert.Equal(t, http.StatusOK, code)
	rows := body["agents"].([]any)
	require.Len(t, rows, 1)
	assert.Equal(t, mid, rows[0].(map[string]any)["machineID"])
}

func TestAdminAgents_Pause(t *testing.T) {
	ts, s, licenseToken, tenant := newAgentControlTestServer(t)
	defer ts.Close()
	adminJWT := newAdminJWT(t, ts.URL)

	mid := strings.Repeat("f", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "h", "linux", "amd64")

	code, _ := adminPost(t, ts.URL, adminJWT,
		"/api/v1/admin/agents/"+mid+"/pause",
		map[string]any{"durationSeconds": 3600})
	assert.Equal(t, http.StatusOK, code)

	a, _ := s.GetAgent(testCtx(t), tenant, mid)
	assert.False(t, a.PausedUntil.IsZero())
	assert.True(t, a.PausedUntil.After(time.Now()))
}

func TestAdminAgents_PauseOverCap(t *testing.T) {
	ts, _, licenseToken, _ := newAgentControlTestServer(t)
	defer ts.Close()
	adminJWT := newAdminJWT(t, ts.URL)

	mid := strings.Repeat("g", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "h", "linux", "amd64")

	// 91 days > 90 day cap.
	code, body := adminPost(t, ts.URL, adminJWT,
		"/api/v1/admin/agents/"+mid+"/pause",
		map[string]any{"durationSeconds": 91 * 24 * 60 * 60})
	assert.Equal(t, http.StatusBadRequest, code)
	require.Contains(t, body["error"].(string), "90")
}

func TestAdminAgents_EnqueueCancel(t *testing.T) {
	ts, _, licenseToken, _ := newAgentControlTestServer(t)
	defer ts.Close()
	adminJWT := newAdminJWT(t, ts.URL)

	mid := strings.Repeat("h", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "h", "linux", "amd64")

	code, body := adminPost(t, ts.URL, adminJWT,
		"/api/v1/admin/agents/"+mid+"/commands",
		map[string]any{"type": "cancel"})
	assert.Equal(t, http.StatusCreated, code)
	assert.NotEmpty(t, body["id"])
}

func TestAdminAgents_EnqueueInvalidType(t *testing.T) {
	ts, _, licenseToken, _ := newAgentControlTestServer(t)
	defer ts.Close()
	adminJWT := newAdminJWT(t, ts.URL)

	mid := strings.Repeat("i", 64)
	_, _ = pollAgent(t, ts.URL, licenseToken, mid, "h", "linux", "amd64")

	code, _ := adminPost(t, ts.URL, adminJWT,
		"/api/v1/admin/agents/"+mid+"/commands",
		map[string]any{"type": "reformat_disk"})
	assert.Equal(t, http.StatusBadRequest, code)
}

// adminGet / adminPost / newAdminJWT live in test helpers. Use the
// existing JWT-auth pattern from pkg/server/*_test.go.
func adminGet(t *testing.T, baseURL, jwt, path string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func adminPost(t *testing.T, baseURL, jwt, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return adminJSON(t, baseURL, jwt, http.MethodPost, path, body)
}

func adminJSON(t *testing.T, baseURL, jwt, method, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	var buf []byte
	if body != nil {
		buf, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, baseURL+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
```

Add `"bytes"` import. `newAdminJWT` is provided by Task 7.

- [ ] **Step 2: Implement admin handlers**

Create `pkg/server/handlers_admin_agents.go`:

```go
package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

const (
	// agentPauseMaxDuration caps the admin-settable pause window. "Forgotten
	// pauses" past this point become visible in the UI as they approach
	// expiry. No infinity sentinel — admin re-applies if they need longer.
	agentPauseMaxDuration = 90 * 24 * time.Hour

	// defaultAgentCommandExpiryMinutes is the default TTL for a queued
	// command when the admin doesn't specify expiresInMinutes.
	defaultAgentCommandExpiryMinutes = 60
)

func (s *Server) handleAdminListAgents(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant required")
		return
	}
	rows, err := s.store.ListAgentsByTenant(r.Context(), tenant, 500)
	if err != nil {
		log.Printf("admin list agents: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": rows})
}

func (s *Server) handleAdminGetAgent(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	mid := chi.URLParam(r, "machineID")
	if tenant == "" || mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}
	a, err := s.store.GetAgent(r.Context(), tenant, mid)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin get agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	cmds, err := s.store.ListAgentCommands(r.Context(), tenant, mid, 50)
	if err != nil {
		log.Printf("admin list agent commands: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":    a,
		"commands": cmds,
	})
}

func (s *Server) handleAdminAgentPause(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	mid := chi.URLParam(r, "machineID")
	if tenant == "" || mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}
	var req adminPauseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if (req.Until == nil) == (req.DurationSeconds == 0) {
		writeError(w, http.StatusBadRequest, "provide exactly one of 'until' or 'durationSeconds'")
		return
	}
	var until time.Time
	now := time.Now().UTC()
	if req.Until != nil {
		until = req.Until.UTC()
	} else {
		if req.DurationSeconds <= 0 {
			writeError(w, http.StatusBadRequest, "durationSeconds must be positive")
			return
		}
		until = now.Add(time.Duration(req.DurationSeconds) * time.Second)
	}
	if until.After(now.Add(agentPauseMaxDuration)) {
		writeError(w, http.StatusBadRequest, "pause may not exceed 90 days")
		return
	}
	if !until.After(now) {
		writeError(w, http.StatusBadRequest, "pause 'until' must be in the future")
		return
	}
	if err := s.store.SetAgentPausedUntil(r.Context(), tenant, mid, until); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin pause agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.auditAgentControl(r, "agent_paused", mid, map[string]any{"until": until.Format(time.RFC3339)})
	writeJSON(w, http.StatusOK, map[string]any{"pausedUntil": until})
}

func (s *Server) handleAdminAgentPauseClear(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	mid := chi.URLParam(r, "machineID")
	if tenant == "" || mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}
	if err := s.store.ClearAgentPausedUntil(r.Context(), tenant, mid); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin pause clear: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.auditAgentControl(r, "agent_pause_cleared", mid, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	mid := chi.URLParam(r, "machineID")
	if tenant == "" || mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}

	// Verify the agent exists — avoids FK-violation error on insert and
	// gives a clean 404 to the caller.
	if _, err := s.store.GetAgent(r.Context(), tenant, mid); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin enqueue: get agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var req adminAgentCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Type {
	case "cancel", "force_run":
	default:
		writeError(w, http.StatusBadRequest, "type must be 'cancel' or 'force_run'")
		return
	}
	expiresMinutes := req.ExpiresInMinutes
	if expiresMinutes <= 0 {
		expiresMinutes = defaultAgentCommandExpiryMinutes
	}
	actor := "unknown"
	if tc := TenantContextFromContext(r.Context()); tc != nil && tc.User != nil {
		actor = tc.User.ID
	}
	args := req.Args
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	cmd, err := s.store.EnqueueAgentCommand(r.Context(), &store.AgentCommand{
		TenantID:  tenant,
		MachineID: mid,
		Type:      store.AgentCommandType(req.Type),
		Args:      args,
		IssuedBy:  actor,
		ExpiresAt: time.Now().Add(time.Duration(expiresMinutes) * time.Minute),
	})
	if err != nil {
		log.Printf("admin enqueue: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.auditAgentControl(r, "agent_command_issued", mid, map[string]any{
		"commandID": cmd.ID,
		"type":      req.Type,
	})
	writeJSON(w, http.StatusCreated, cmd)
}

// auditAgentControl writes a tenant-scoped audit row. Best-effort; any
// error is logged but not surfaced to the caller, matching the existing
// audit idiom elsewhere in the server.
func (s *Server) auditAgentControl(r *http.Request, event, machineID string, extra map[string]any) {
	if s.audit == nil {
		return
	}
	actor := "unknown"
	if tc := TenantContextFromContext(r.Context()); tc != nil && tc.User != nil {
		actor = tc.User.ID
	}
	fields := map[string]any{"machineID": machineID, "actor": actor}
	for k, v := range extra {
		fields[k] = v
	}
	// Audit call signature may differ — adjust to the existing
	// recorder interface (see pkg/server/audit.go or grep for existing
	// s.audit(...) calls). If the recorder takes a different shape,
	// adapt this helper to match.
	s.audit.Record(r.Context(), event, machineID, fields)
}
```

The `s.audit` field existence depends on the existing server struct. If `*Server` doesn't have an `audit` field, look for how the existing `/api/v1/scans` handler records audits (grep `auditEvent\|WriteAudit\|s\.audit`) and use that pattern. Adjust inline.

- [ ] **Step 3: Verify compile**

```bash
go build ./pkg/server/
```

Expected: clean. Handler tests run in Task 7.

- [ ] **Step 4: Commit**

```bash
git add pkg/server/handlers_admin_agents.go pkg/server/handlers_admin_agents_test.go
git commit -m "server: admin-facing agent list/detail + pause + enqueue handlers

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Route registration + test-server helper + green tests

**Files:**
- Modify: `pkg/server/server.go`
- Test: `pkg/server/agent_control_testserver.go` (new test helper)

- [ ] **Step 1: Register the new routes**

In `pkg/server/server.go`, find the Chi router setup. The existing pattern looks roughly like:

```go
r := chi.NewRouter()
// ... middleware stack
r.Mount("/api/v1/agent-push", s.agentPushHandlers())  // or similar
```

Add two new subrouters — agent-facing under licence-token + machine-id middleware, admin-facing under the existing admin-auth middleware. Locate the existing agent-facing routes (grep `r.Route.*agent\|/api/v1/scans`) and mirror the pattern:

```go
// Agent-facing: licence token + machine-id middleware
r.Group(func(r chi.Router) {
	r.Use(s.unifiedAuth())           // existing — or whatever the token middleware is called on this server
	r.Use(RequireMachineID)
	r.Get("/api/v1/agent/commands/poll", s.handleAgentCommandsPoll)
	r.Post("/api/v1/agent/commands/{id}/result", s.handleAgentCommandResult)
})

// Admin-facing: same auth as existing admin endpoints
r.Group(func(r chi.Router) {
	r.Use(s.unifiedAuth())
	r.Use(requireAdminRole) // existing helper, whatever it is in this repo
	r.Get("/api/v1/admin/agents", s.handleAdminListAgents)
	r.Get("/api/v1/admin/agents/{machineID}", s.handleAdminGetAgent)
	r.Post("/api/v1/admin/agents/{machineID}/pause", s.handleAdminAgentPause)
	r.Delete("/api/v1/admin/agents/{machineID}/pause", s.handleAdminAgentPauseClear)
	r.Post("/api/v1/admin/agents/{machineID}/commands", s.handleAdminEnqueueCommand)
})
```

**Important**: Match the EXISTING auth middleware names. If `unifiedAuth` isn't the name, use what's actually there. If there's no dedicated admin-role middleware, inline a role check at the handler level reading `TenantContextFromContext(r.Context()).User.Role == "org_admin"`.

- [ ] **Step 2: Add the test-server helper**

Create `pkg/server/agent_control_testserver.go` (the `.go` extension without `_test` means it's visible from `server_test` package — but we want `_test` scope, so actually call it `agent_control_testserver_test.go`):

Look at how an EXISTING integration test in `pkg/server/` creates a test server (e.g., `grep -rn "httptest.NewServer" pkg/server/*_test.go | head -3`). Copy that pattern into a helper named `newAgentControlTestServer` that:

1. Opens an isolated Postgres schema via `store.NewPostgresStoreInSchema`.
2. Generates an Ed25519 keypair for licence-token verification.
3. Issues a licence token bound to a new test tenant (org).
4. Creates a `*Server` with that keypair + the store.
5. Returns `(ts *httptest.Server, s *store.PostgresStore, licenseToken string, tenantID string)`.

Also expose helpers `testCtx(t)` (returning `context.Background()` or `t.Context()` per testing.T), and `newAdminJWT(t, baseURL)` that creates an admin user + issues a JWT by POSTing to the login endpoint OR by minting a JWT directly with the server's signing key if the test server exposes it.

If there's already a similar helper in the existing test files (very likely — the repo has 111+ integration tests), prefer to REUSE it rather than duplicate. Search:

```bash
grep -rn "func new.*TestServer\|func newTestServer\|newAgentTestServer" pkg/server/*_test.go | head
```

- [ ] **Step 3: Run Task 5 + Task 6 tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestAgentPoll_|TestAgentResult_|TestAdminAgents_" ./pkg/server/ -v 2>&1 | tail -30
```

Expected: all 10 tests PASS.

- [ ] **Step 4: Run full server suite**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/server/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/server.go pkg/server/*_test.go
git commit -m "server: register agent control channel routes + test server helper

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Agent-side control client (pkg/agent)

**Files:**
- Create: `pkg/agent/control.go`
- Test: `pkg/agent/control_test.go` (new)

- [ ] **Step 1: Write failing test for the poll client**

Create `pkg/agent/control_test.go`:

```go
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandPoller_Empty204(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/agent/commands/poll", r.URL.Path)
		assert.Equal(t, "token-x", r.Header.Get("X-Triton-License-Token"))
		assert.Equal(t, "midval", r.Header.Get("X-Triton-Machine-ID"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "token-x", MachineID: "midval"}
	resp, err := c.Poll(t.Context())
	require.NoError(t, err)
	assert.Nil(t, resp, "empty 204 should yield nil response")
}

func TestCommandPoller_Commands(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state": map[string]any{"pausedUntil": "2026-05-01T00:00:00Z"},
			"commands": []map[string]any{
				{"id": "cmd-1", "type": "cancel", "args": map[string]any{}, "issuedAt": "2026-04-19T00:00:00Z", "expiresAt": "2026-04-19T01:00:00Z"},
			},
		})
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	resp, err := c.Poll(t.Context())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), resp.State.PausedUntil)
	require.Len(t, resp.Commands, 1)
	assert.Equal(t, "cancel", resp.Commands[0].Type)
}

func TestCommandPoller_PostResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/agent/commands/cmd-1/result", r.URL.Path)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "executed", body["status"])
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	err := c.PostResult(t.Context(), "cmd-1", "executed", json.RawMessage(`{"findings":3}`))
	require.NoError(t, err)
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./pkg/agent/ -run TestCommandPoller -v
```

Expected: FAIL — `CommandPoller` undefined.

- [ ] **Step 3: Implement the client**

Create `pkg/agent/control.go`:

```go
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// CommandPoller is the client-side half of the Report Server's agent
// control channel. Callers construct one per agent lifetime, call Poll
// in a loop (or until ctx cancel), and PostResult after acting on each
// dispatched command.
type CommandPoller struct {
	BaseURL      string // Report Server URL, matching Client.BaseURL
	LicenseToken string // same token used for /submit
	MachineID    string // SHA3-256 hex from license.MachineFingerprint()
	Hostname     string // hint — helps admins identify agents in the fleet view
	HTTPClient   *http.Client

	// Probe is optional; tests can set a shorter poll deadline. Production
	// defaults to 35s so the server's 30s timeout always arrives first.
	PollDeadline time.Duration
}

// PollResponse is the decoded JSON from a 200 OK poll. On 204 the caller
// gets (nil, nil) and should reconnect immediately.
type PollResponse struct {
	State    PollState      `json:"state"`
	Commands []PollCommand  `json:"commands,omitempty"`
}

type PollState struct {
	PausedUntil time.Time `json:"pausedUntil,omitempty"`
}

type PollCommand struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

func (c *CommandPoller) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	deadline := c.PollDeadline
	if deadline <= 0 {
		deadline = 35 * time.Second
	}
	return &http.Client{Timeout: deadline}
}

// Poll issues one long-poll GET and returns the decoded response, or nil
// when the server responds 204 (no state, no commands). Respects ctx
// cancellation. A non-2xx response returns an error.
func (c *CommandPoller) Poll(ctx context.Context) (*PollResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/agent/commands/poll", nil)
	if err != nil {
		return nil, fmt.Errorf("build poll request: %w", err)
	}
	req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	req.Header.Set("X-Triton-Machine-ID", c.MachineID)
	if c.Hostname != "" {
		req.Header.Set("X-Triton-Hostname", c.Hostname)
	}
	req.Header.Set("X-Triton-Agent-OS", runtime.GOOS)
	req.Header.Set("X-Triton-Agent-Arch", runtime.GOARCH)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("poll status %d: %s", resp.StatusCode, body)
	}
	var pr PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decode poll: %w", err)
	}
	return &pr, nil
}

// PostResult tells the server how a dispatched command completed.
// status must be "executed" or "rejected"; meta is opaque JSON.
func (c *CommandPoller) PostResult(ctx context.Context, commandID, status string, meta json.RawMessage) error {
	body := map[string]any{"status": status}
	if len(meta) > 0 {
		body["meta"] = meta
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/agent/commands/"+commandID+"/result", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("build result request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	req.Header.Set("X-Triton-Machine-ID", c.MachineID)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("result status %d: %s", resp.StatusCode, msg)
	}
	return nil
}
```

- [ ] **Step 4: Run tests — should pass**

```bash
go test ./pkg/agent/ -run TestCommandPoller -v
```

Expected: all 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/agent/control.go pkg/agent/control_test.go
git commit -m "agent: CommandPoller client for Report Server control channel

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Wire CommandPollLoop into runAgent + scan-loop integration

**Files:**
- Modify: `cmd/agent.go`
- Test: `cmd/agent_control_test.go` (new)

- [ ] **Step 1: Write failing tests for the integration glue**

Create `cmd/agent_control_test.go`:

```go
package cmd

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAgentControlState_PauseRespected(t *testing.T) {
	st := &agentControlState{}
	st.mu.Lock()
	st.pausedUntil = time.Now().Add(1 * time.Hour)
	st.mu.Unlock()

	until, paused := st.pauseDeadline()
	assert.True(t, paused)
	assert.True(t, until.After(time.Now()))
}

func TestAgentControlState_PastPausedUntilNotPaused(t *testing.T) {
	st := &agentControlState{}
	st.mu.Lock()
	st.pausedUntil = time.Now().Add(-1 * time.Hour)
	st.mu.Unlock()

	_, paused := st.pauseDeadline()
	assert.False(t, paused, "past paused_until should mean not paused")
}

func TestAgentControlState_ScanCancelCalled(t *testing.T) {
	st := &agentControlState{}
	var called int
	var mu sync.Mutex
	st.setScanCancel(func() {
		mu.Lock()
		called++
		mu.Unlock()
	})
	st.cancelScan()
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, called)
}

func TestAgentControlState_CancelNoScanNoop(t *testing.T) {
	st := &agentControlState{}
	// No panic on cancel when no scan is running.
	st.cancelScan()
}

// Smoke test that marshals a force_run command's args. Demonstrates the
// wire shape; the actual dispatch happens in runAgent's loop.
func TestForceRunArgsRoundTrip(t *testing.T) {
	args := map[string]string{"profile": "quick"}
	buf, _ := json.Marshal(args)
	var decoded map[string]string
	assert.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Equal(t, "quick", decoded["profile"])
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./cmd/ -run "TestAgentControlState_|TestForceRunArgsRoundTrip" -v
```

Expected: FAIL — types undefined.

- [ ] **Step 3: Add shared state struct + helpers**

In `cmd/agent.go`, near other type declarations (around `type resolvedAgentConfig struct`), add:

```go
// agentControlState is the shared state between runAgent's main scan
// loop and the commandPollLoop goroutine. Populated on startup by
// runAgent; consulted + mutated by the poll loop as commands arrive.
//
// All access goes through the mutex. The struct is cheap enough to
// pass by pointer everywhere without lock-contention concerns — writes
// happen at most once per poll (every 30s) plus once per scan start.
type agentControlState struct {
	mu          sync.Mutex
	pausedUntil time.Time          // zero value = not paused
	scanCancel  context.CancelFunc // nil when no scan in flight
}

// pauseDeadline returns (until, true) when the agent is paused with a
// future deadline, otherwise (zero, false). Past pausedUntil values are
// treated as not-paused (server-side auto-expiry).
func (s *agentControlState) pauseDeadline() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pausedUntil.IsZero() || !s.pausedUntil.After(time.Now()) {
		return time.Time{}, false
	}
	return s.pausedUntil, true
}

// setPausedUntil is called by the poll loop with whatever the server
// reports (zero = server said no pause).
func (s *agentControlState) setPausedUntil(t time.Time) {
	s.mu.Lock()
	s.pausedUntil = t
	s.mu.Unlock()
}

// setScanCancel is called at scan start + cleared (passed nil) at scan
// end by the main loop.
func (s *agentControlState) setScanCancel(fn context.CancelFunc) {
	s.mu.Lock()
	s.scanCancel = fn
	s.mu.Unlock()
}

// cancelScan is called by the poll loop when a cancel command arrives.
// Safe when no scan is running.
func (s *agentControlState) cancelScan() {
	s.mu.Lock()
	fn := s.scanCancel
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}
```

Add imports: `"context"`, `"sync"`, `"time"` (all likely present).

- [ ] **Step 4: Implement the poll loop**

Append to `cmd/agent.go`:

```go
// commandPollLoop runs as a goroutine for the agent's lifetime (when
// reportServer is configured). It long-polls GET /api/v1/agent/commands/poll,
// applies persistent state (pausedUntil) and dispatches transient
// commands (cancel immediate, force_run via forceRunCh).
func commandPollLoop(
	ctx context.Context,
	poller *agent.CommandPoller,
	st *agentControlState,
	forceRunCh chan<- *agent.PollCommand,
) {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		resp, err := poller.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "warning: command poll failed: %v — retrying in %s\n", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 2 * time.Second // reset on success

		// 204 No Content: server said nothing. Reset pausedUntil to
		// zero so a server-cleared pause is reflected. Then reconnect.
		if resp == nil {
			st.setPausedUntil(time.Time{})
			continue
		}

		// 200 with body: update state + dispatch any commands.
		st.setPausedUntil(resp.State.PausedUntil)

		for i := range resp.Commands {
			cmd := resp.Commands[i]
			switch cmd.Type {
			case "cancel":
				st.cancelScan()
				meta := json.RawMessage(`{}`)
				if err := poller.PostResult(ctx, cmd.ID, "executed", meta); err != nil {
					fmt.Fprintf(os.Stderr, "warning: cancel result POST failed: %v\n", err)
				}
			case "force_run":
				// Non-blocking send; if the channel is full (scan in
				// flight and a prior force_run is queued), drop this
				// one and POST rejected.
				select {
				case forceRunCh <- &cmd:
				default:
					meta, _ := json.Marshal(map[string]string{"reason": "force_run already pending"})
					_ = poller.PostResult(ctx, cmd.ID, "rejected", meta)
				}
			default:
				meta, _ := json.Marshal(map[string]string{"reason": "unknown command type"})
				_ = poller.PostResult(ctx, cmd.ID, "rejected", meta)
			}
		}
	}
}
```

Imports to add: `"github.com/amiryahaya/triton/pkg/agent"`, `"encoding/json"` (likely present).

- [ ] **Step 5: Hook into runAgent's lifecycle**

In `cmd/agent.go::runAgent`, after the scheduler setup block (the `baseSched := sched` addition from PR #80) and before the `for { ... }` scan loop, add:

```go
	// Remote control channel (step 6). Only spawn when we have a
	// reportServer to poll from — local-only agents get no commands.
	var ctrlState *agentControlState
	var forceRunCh chan *agent.PollCommand
	if resolved.reportServer != "" {
		ctrlState = &agentControlState{}
		forceRunCh = make(chan *agent.PollCommand, 1)
		poller := &agent.CommandPoller{
			BaseURL:      resolved.reportServer,
			LicenseToken: resolved.licenseToken,
			MachineID:    license.MachineFingerprint(),
			Hostname:     hostnameOrEmpty(),
		}
		go commandPollLoop(ctx, poller, ctrlState, forceRunCh)
	}
```

Where `hostnameOrEmpty()` is a tiny helper at the bottom of the file:

```go
func hostnameOrEmpty() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
```

Update the scan loop to honour pause + force_run. Find the existing `wait := sched.Next(time.Now())` line (from PR #80). Replace the surrounding block with:

```go
		// Compute next sleep deadline, honouring an active pause.
		var wait time.Duration
		if ctrlState != nil {
			if until, paused := ctrlState.pauseDeadline(); paused {
				// Wake at the later of (pause expiry, normal next fire).
				pauseWait := time.Until(until)
				schedWait := sched.Next(time.Now())
				if pauseWait > schedWait {
					wait = pauseWait
				} else {
					wait = schedWait
				}
				fmt.Printf("Paused until %s; next scan at %s\n",
					until.Format(time.RFC3339), time.Now().Add(wait).Format(time.RFC3339))
			} else {
				wait = sched.Next(time.Now())
			}
		} else {
			wait = sched.Next(time.Now())
		}
		if wait < 0 {
			wait = 0
		}

		// Sleep + watch for cancel / force_run.
		fmt.Printf("Next scan in %s...\n", wait.Round(time.Second))
		var forced *agent.PollCommand
		select {
		case <-time.After(wait):
		case cmd := <-forceRunCh:
			// Wake early because admin issued force_run.
			forced = cmd
		case <-ctx.Done():
			fmt.Println("\nAgent stopped.")
			return nil
		}
```

Replace `wait := sched.Next(time.Now()); ... select { case <-time.After(wait): ... }` with the above. Inside the loop body (after the sleep), before `runAgentScan`, add force-run profile override + scan-cancel wiring:

```go
		// Wire up the scan cancel context so an incoming cancel command
		// can abort this iteration.
		scanCtx, scanCancel := context.WithCancel(ctx)
		if ctrlState != nil {
			ctrlState.setScanCancel(scanCancel)
		}

		// If this iteration was triggered by force_run, honour an optional
		// profile override from its args.
		iterResolved := *resolved // shallow copy; args only muck with effectiveProfile
		if forced != nil && len(forced.Args) > 0 {
			var a struct {
				Profile string `json:"profile"`
			}
			if err := json.Unmarshal(forced.Args, &a); err == nil && a.Profile != "" {
				if validProfiles[a.Profile] {
					iterResolved.effectiveProfile = a.Profile
				}
			}
		}

		err := runAgentScan(scanCtx, activeGuard, &iterResolved, client)
		scanCancel()
		if ctrlState != nil {
			ctrlState.setScanCancel(nil)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		// Report force_run outcome back to the server.
		if forced != nil && ctrlState != nil {
			poller := &agent.CommandPoller{
				BaseURL:      resolved.reportServer,
				LicenseToken: resolved.licenseToken,
				MachineID:    license.MachineFingerprint(),
			}
			status, meta := "executed", json.RawMessage(`{}`)
			if err != nil {
				status = "rejected"
				m, _ := json.Marshal(map[string]string{"reason": err.Error()})
				meta = m
			}
			_ = poller.PostResult(ctx, forced.ID, status, meta)
		}
```

This is a lot of code changes — the key insight is you're replacing `runAgentScan(ctx, ...)` with `runAgentScan(scanCtx, ...)` + bookkeeping around it. Adjust to the existing loop body structure; if there's a different error-handling pattern, preserve it.

- [ ] **Step 6: Run the shared-state unit tests**

```bash
go test ./cmd/ -run "TestAgentControlState_|TestForceRunArgsRoundTrip" -v
```

Expected: all PASS.

- [ ] **Step 7: Run the full cmd suite — expect some existing tests to need adjustment**

```bash
go test ./cmd/... 2>&1 | tail -15
```

If any existing agent test fails because the loop structure changed (e.g., `TestRunAgent_OneShot`), update the test to match the new structure. Prefer minimal adjustment — tests that compile + pass assertively against the new loop body are the goal.

- [ ] **Step 8: Vet + build**

```bash
go vet ./cmd/...
go build ./...
```

Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add cmd/
git commit -m "agent: spawn commandPollLoop + wire pause/cancel/force_run into scan loop

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Integration test — full lifecycle

**Files:**
- Create: `test/integration/agent_control_channel_test.go`

- [ ] **Step 1: Write the lifecycle test**

Create `test/integration/agent_control_channel_test.go`:

```go
//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/agent"
)

// TestAgentControlChannel_Lifecycle:
//  1. Report Server starts. Tenant exists.
//  2. Agent polls → 204 + row created in agents table.
//  3. Admin pauses for 1h → next poll returns state.pausedUntil.
//  4. Admin enqueues cancel → next poll returns the command, marks dispatched.
//  5. Agent POSTs result → server records executed.
//  6. Admin clears pause → next poll returns 204 (no state, no commands).
func TestAgentControlChannel_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ts, s, licenseToken, tenant := newAgentControlIntegrationServer(t)
	defer ts.Close()

	poller := &agent.CommandPoller{
		BaseURL:      ts.URL,
		LicenseToken: licenseToken,
		MachineID:    strings.Repeat("7", 64),
		Hostname:     "integration-host",
	}

	// 1. First poll: 204, creates the row.
	ctx := t.Context()
	ctxShort, cancelShort := context.WithTimeout(ctx, 2*time.Second)
	defer cancelShort()
	resp, err := poller.Poll(ctxShort)
	require.NoError(t, err)
	assert.Nil(t, resp)

	// 2. Admin pauses for 1h.
	adminJWT := newAgentControlAdminJWT(t, ts.URL)
	pauseResp, pauseCode := adminCall(t, ts.URL, adminJWT, "POST",
		"/api/v1/admin/agents/"+poller.MachineID+"/pause",
		map[string]any{"durationSeconds": 3600})
	require.Equal(t, 200, pauseCode)
	require.NotEmpty(t, pauseResp["pausedUntil"])

	// 3. Agent polls → sees pausedUntil.
	resp, err = poller.Poll(ctxShort)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.State.PausedUntil.IsZero())

	// 4. Admin enqueues a cancel.
	cmdResp, code := adminCall(t, ts.URL, adminJWT, "POST",
		"/api/v1/admin/agents/"+poller.MachineID+"/commands",
		map[string]any{"type": "cancel"})
	require.Equal(t, 201, code)
	cmdID := cmdResp["id"].(string)

	// 5. Agent polls → sees the command.
	resp, err = poller.Poll(ctxShort)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Commands, 1)
	assert.Equal(t, cmdID, resp.Commands[0].ID)

	// 6. Agent POSTs result.
	require.NoError(t, poller.PostResult(ctx, cmdID, "executed",
		json.RawMessage(`{"findings":5}`)))

	// 7. Verify result persisted.
	history, _ := s.ListAgentCommands(ctx, tenant, poller.MachineID, 10)
	require.Len(t, history, 1)
	require.NotNil(t, history[0].ResultStatus)
	assert.Equal(t, "executed", *history[0].ResultStatus)

	// 8. Admin clears pause.
	_, clrCode := adminCall(t, ts.URL, adminJWT, "DELETE",
		"/api/v1/admin/agents/"+poller.MachineID+"/pause", nil)
	assert.Equal(t, 200, clrCode)

	// 9. Next poll → 204 (pausedUntil cleared, no commands).
	ctxShort2, cancelShort2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancelShort2()
	resp, err = poller.Poll(ctxShort2)
	require.NoError(t, err)
	assert.Nil(t, resp, "final poll should be 204")
}
```

Helpers `newAgentControlIntegrationServer`, `newAgentControlAdminJWT`, `adminCall` — search for existing analogs:

```bash
grep -rn "newTestReportServer\|newAdminJWT\|adminCall" test/integration/*.go | head
```

Use whatever's there; failing that, add minimal wrappers at the bottom of the test file (or in `helpers_test.go` if the existing helper file welcomes additions).

- [ ] **Step 2: Run the integration test**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestAgentControlChannel_Lifecycle ./test/integration/ -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/
git commit -m "test: integration lifecycle for agent remote control channel

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Docs

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add `7c-quater` to deployment guide**

In `docs/DEPLOYMENT_GUIDE.md`, after the `7c-ter. Server-pushed schedule override` section (added by PR #80), insert:

```markdown
### 7c-quater. Remote control channel (pause / cancel / force-run)

When an agent is bound to a Report Server (`report_server:` in agent.yaml), it opens a long-poll to `GET /api/v1/agent/commands/poll` alongside the scan-submit path. The channel delivers:

- **Persistent state** — `pausedUntil` (set by admin; agent skips scans until the deadline passes).
- **Transient commands** — `cancel` (cancels the in-flight scan) and `force_run` (triggers an immediate scan, rejects if a scan is already running).

**Setting a pause (admin):**

```bash
curl -X POST https://report.example.com/api/v1/admin/agents/<machine-id>/pause \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"durationSeconds": 3600}'
```

Hard cap: 90 days. The admin API returns HTTP 400 for longer.

**Clearing a pause:**

```bash
curl -X DELETE https://report.example.com/api/v1/admin/agents/<machine-id>/pause \
     -H "Authorization: Bearer $ADMIN_JWT"
```

**Sending a cancel:**

```bash
curl -X POST https://report.example.com/api/v1/admin/agents/<machine-id>/commands \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"type": "cancel"}'
```

**Sending a force-run with a profile override (subject to the licence's tier):**

```bash
curl -X POST https://report.example.com/api/v1/admin/agents/<machine-id>/commands \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"type": "force_run", "args": {"profile": "quick"}}'
```

**Finding the machine-id:** the agent computes it as SHA3-256 of `hostname|GOOS|GOARCH` (same value as `triton license fingerprint`). Use `GET /api/v1/admin/agents` for the fleet list — each row shows machineID alongside hostname/os/arch.

**Local-only agents (no `report_server:`) do not receive commands.** The channel is Report-Server-exclusive.

**A future PR adds UI buttons** for these actions — primary home is Manage Portal (when deployed), fallback at Report's own admin UI. This PR ships the backend only.
```

- [ ] **Step 2: Add a CLAUDE.md paragraph under Agent scheduling**

In `CLAUDE.md`, immediately after the existing "When an agent is bound to a license server..." paragraph, add:

```markdown
When the agent is also bound to a Report Server, a second goroutine runs the remote-control long-poll against `/api/v1/agent/commands/poll`, applying persistent pause state (`pausedUntil`) and transient commands (`cancel`, `force_run`). Pause is per-(tenant, machine) with a 90-day hard cap; `cancel` tugs on the running scan's context via a mutex-guarded `scanCancel`; `force_run` wakes the main scan loop via a 1-slot buffered channel. See `cmd/agent.go::commandPollLoop` + `pkg/server/handlers_agent_commands.go`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/DEPLOYMENT_GUIDE.md CLAUDE.md
git commit -m "docs: remote control channel (deployment guide + CLAUDE.md)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Memory refresh

**Files:**
- Modify: `/Users/amirrudinyahaya/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/agent-control-features.md`

- [ ] **Step 1: Flip step 6 to SHIPPED**

Replace the step-6 entry in `agent-control-features.md` with a post-ship summary: shipped PR #, list the five surfaces (migration, agents table, admin API, agent-side client, integration test), and the deferred items (admin UI — Manage primary + Report fallback, bulk commands, WebSocket upgrade).

No commit — memory lives outside the repo.

---

## Self-Review

**Spec coverage check:**

| Spec section | Implemented by |
|--------------|----------------|
| Migration — agents + agent_commands tables | Task 1 |
| `AgentRecord` / `AgentCommand` types | Task 2 |
| `AgentStore` interface + Postgres impl | Task 3 |
| Machine-ID middleware (64-hex validation) | Task 4 |
| Wire-shape types for poll response + admin requests | Task 4 |
| Poll handler (long-poll, 30s/1s, upsert-on-first-seen) | Task 5 |
| Result POST handler (cross-agent rejection) | Task 5 |
| Admin list/detail/pause/enqueue handlers (90-day cap, tier gate) | Task 6 |
| Route registration under existing auth | Task 7 |
| `CommandPoller` client (poll + post-result, HTTP timeout) | Task 8 |
| `commandPollLoop` goroutine + scan-loop integration (pause + cancel + force_run) | Task 9 |
| Full-lifecycle integration test | Task 10 |
| Deployment guide + CLAUDE.md | Task 11 |
| Memory refresh | Task 12 |

**Placeholder scan:** three comments reference existing helpers with names that depend on what's actually in the repo (`newTestTenant`, `newAdminJWT`, `auditAgentControl`'s audit call). Each comment explicitly instructs "grep for the real helper, use that name" — this is a flexibility hint, not a placeholder.

**Type consistency:**

- `AgentRecord{TenantID, MachineID, Hostname, OS, Arch, FirstSeenAt, LastSeenAt, PausedUntil}` — Task 2; used in Tasks 3/5/6/7/10.
- `AgentCommand{ID, TenantID, MachineID, Type, Args, IssuedBy, IssuedAt, ExpiresAt, DispatchedAt, ResultStatus, ResultMeta, ResultedAt}` — Task 2; used in 3/5/6/7/10.
- `AgentCommandType` constants `AgentCommandCancel` (`"cancel"`), `AgentCommandForceRun` (`"force_run"`) — Task 2; wire `type` field Task 4/5/6/8/9; string constants match the DB CHECK constraint.
- `agentPollResponse{State, Commands}` / `agentPollState{PausedUntil}` / `agentPollCommand{ID, Type, Args, IssuedAt, ExpiresAt}` — Task 4; consumed by Task 5 server-side and Task 8 client-side (client mirror types `PollResponse`/`PollState`/`PollCommand`).
- `agentControlState{mu, pausedUntil, scanCancel}` with methods `pauseDeadline`, `setPausedUntil`, `setScanCancel`, `cancelScan` — Task 9.
- `CommandPoller{BaseURL, LicenseToken, MachineID, Hostname, HTTPClient, PollDeadline}` — Task 8; consumed by Task 9.
- `adminPauseRequest{Until *time.Time, DurationSeconds int}` / `adminAgentCommandRequest{Type, Args, ExpiresInMinutes}` — Task 4; consumed by Task 6.

No drift detected across tasks.

**Scope check:** single feature, single subsystem. Does not need decomposition.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-19-agent-control-channel-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, spec + code-quality review between each.

**2. Inline Execution** — same session, batch checkpoints.

Which approach?
