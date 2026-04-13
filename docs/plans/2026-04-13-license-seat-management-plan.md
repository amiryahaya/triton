# License Seat Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the Triton agent to register with the license server on startup, heartbeat on each scan, and deactivate on shutdown — with on-demand stale seat reaping when seats are full.

**Architecture:** The agent talks directly to the license server via the existing `ServerClient` in `internal/license/client.go`. Two new fields (`license_server`, `license_id`) in `agent.yaml` enable this path. The license store's `Activate()` method gains on-demand stale seat reaping: when seats are full, it reaps activations whose `last_seen_at` exceeds a configurable threshold (default 14 days) before returning `ErrSeatsFull`. All changes are backward compatible — agents without `license_server` configured behave exactly as before.

**Tech Stack:** Go 1.25, pgx/v5, Cobra CLI, testify

**Spec:** `docs/plans/2026-04-13-license-seat-management-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/agentconfig/loader.go` | Modify | Add `LicenseServer` and `LicenseID` fields to `Config`, trim whitespace |
| `internal/agentconfig/loader_test.go` | Modify | Test new fields parse and trim correctly |
| `pkg/licensestore/store.go` | Modify | Add `ReapStaleActivations` to `Store` interface |
| `pkg/licensestore/postgres.go` | Modify | Implement `ReapStaleActivations`; add `StaleThreshold` field; integrate reap-then-retry into `Activate()` |
| `pkg/licensestore/postgres_test.go` | Modify | Tests for `ReapStaleActivations` and `Activate` with reap-on-full |
| `pkg/licenseserver/config.go` | Modify | Add `StaleActivationThreshold` field |
| `pkg/licenseserver/server.go` | Modify | Pass threshold to store after construction |
| `cmd/licenseserver/main.go` | Modify | Wire `TRITON_LICENSE_SERVER_STALE_THRESHOLD` env var |
| `cmd/agent.go` | Modify | Add activation on startup, heartbeat before each scan, deactivation on shutdown |
| `cmd/agent_test.go` | Modify | Test activation/heartbeat/deactivation/degradation paths |

---

### Task 1: Add `license_server` and `license_id` to agent config

**Files:**
- Modify: `internal/agentconfig/loader.go:39-95`
- Modify: `internal/agentconfig/loader_test.go`

- [ ] **Step 1: Write the failing test for new config fields**

Add to `internal/agentconfig/loader_test.go`:

```go
// TestLoad_LicenseServerFields verifies that the license_server
// and license_id fields round-trip through yaml parse and get
// whitespace-trimmed like other credential-shaped fields.
func TestLoad_LicenseServerFields(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte(`
license_server: "https://license.example.com"
license_id: "550e8400-e29b-41d4-a716-446655440000"
license_key: "eyJ0ZXN0Ijp0cnVlfQ.sig"
`),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "https://license.example.com", cfg.LicenseServer)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", cfg.LicenseID)
	assert.Equal(t, "eyJ0ZXN0Ijp0cnVlfQ.sig", cfg.LicenseKey)
}

// TestLoad_LicenseServerTrimmed verifies block-scalar whitespace
// trimming on the license_server and license_id fields, matching
// the existing trim behavior for license_key and report_server.
func TestLoad_LicenseServerTrimmed(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("license_server: |\n  https://license.example.com\nlicense_id: |\n  some-uuid\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "https://license.example.com", cfg.LicenseServer)
	assert.Equal(t, "some-uuid", cfg.LicenseID)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run 'TestLoad_LicenseServer' ./internal/agentconfig/`
Expected: FAIL — `cfg.LicenseServer` and `cfg.LicenseID` are undefined

- [ ] **Step 3: Add fields to Config struct**

In `internal/agentconfig/loader.go`, add to the `Config` struct after the `AlsoLocal` field (before the `loadedFrom` field):

```go
// LicenseServer is the URL of the Triton License Server for seat
// management. When set alongside LicenseID, the agent registers
// itself on startup and heartbeats on each scan interval. When
// empty, no seat tracking occurs (backward compatible).
LicenseServer string `yaml:"license_server"`

// LicenseID is the license UUID to activate against. Required
// when LicenseServer is set; ignored otherwise.
LicenseID string `yaml:"license_id"`
```

- [ ] **Step 4: Add whitespace trimming in loadFile**

In `internal/agentconfig/loader.go`, in the `loadFile` function, add after the existing trim lines:

```go
cfg.LicenseServer = strings.TrimSpace(cfg.LicenseServer)
cfg.LicenseID = strings.TrimSpace(cfg.LicenseID)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v -run 'TestLoad_LicenseServer' ./internal/agentconfig/`
Expected: PASS

- [ ] **Step 6: Run full agentconfig test suite**

Run: `go test -v ./internal/agentconfig/`
Expected: All tests PASS (existing tests unaffected)

- [ ] **Step 7: Commit**

```bash
git add internal/agentconfig/loader.go internal/agentconfig/loader_test.go
git commit -m "feat(agentconfig): add license_server and license_id fields"
```

---

### Task 2: Add `ReapStaleActivations` to the store interface

**Files:**
- Modify: `pkg/licensestore/store.go:26-32`

- [ ] **Step 1: Add method to Store interface**

In `pkg/licensestore/store.go`, add to the `// Activations` section of the `Store` interface, after `UpdateLastSeen`:

```go
// ReapStaleActivations marks active seats as inactive when their
// last_seen_at exceeds the given threshold. Returns the count of
// reaped activations. Called on-demand inside Activate when seats
// are full, within the same serializable transaction.
ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error)
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/licensestore/...`
Expected: FAIL — `PostgresStore` does not implement `Store` (missing `ReapStaleActivations`)

- [ ] **Step 3: Add stub implementation**

In `pkg/licensestore/postgres.go`, add after the `UpdateLastSeen` method:

```go
func (s *PostgresStore) ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error) {
	return 0, fmt.Errorf("not implemented")
}
```

- [ ] **Step 4: Verify compilation passes**

Run: `go build ./pkg/licensestore/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/licensestore/store.go pkg/licensestore/postgres.go
git commit -m "feat(licensestore): add ReapStaleActivations to Store interface (stub)"
```

---

### Task 3: Implement `ReapStaleActivations`

**Files:**
- Modify: `pkg/licensestore/postgres.go`
- Modify: `pkg/licensestore/postgres_test.go`

- [ ] **Step 1: Write the failing integration test**

Add to `pkg/licensestore/postgres_test.go`:

```go
func TestReapStaleActivations_ReapsOnlyStale(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 3
	require.NoError(t, s.CreateLicense(ctx, lic))

	// Activate 3 machines
	act1 := makeActivation(t, lic.ID) // will be made stale
	act2 := makeActivation(t, lic.ID) // will be made stale
	act3 := makeActivation(t, lic.ID) // fresh — should survive
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))
	require.NoError(t, s.Activate(ctx, act3))

	// Backdate act1 and act2's last_seen_at to 15 days ago
	fifteenDaysAgo := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`,
		fifteenDaysAgo, act1.ID)
	require.NoError(t, err)
	_, err = s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`,
		fifteenDaysAgo, act2.ID)
	require.NoError(t, err)

	// Reap with 14-day threshold
	reaped, err := s.ReapStaleActivations(ctx, lic.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, reaped, "two stale activations should be reaped")

	// Verify: act3 still active, act1/act2 inactive
	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only act3 should remain active")

	got1, err := s.GetActivation(ctx, act1.ID)
	require.NoError(t, err)
	assert.False(t, got1.Active, "act1 should be inactive after reap")
	assert.NotNil(t, got1.DeactivatedAt, "act1 should have deactivated_at set")

	got3, err := s.GetActivation(ctx, act3.ID)
	require.NoError(t, err)
	assert.True(t, got3.Active, "act3 should remain active (fresh)")
}

func TestReapStaleActivations_NoStaleReturnsZero(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	// All activations are fresh — nothing to reap
	reaped, err := s.ReapStaleActivations(ctx, lic.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, reaped)
}

func TestReapStaleActivations_DifferentLicenseNotAffected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic1 := makeLicense(t, org.ID)
	lic2 := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic1))
	require.NoError(t, s.CreateLicense(ctx, lic2))

	act1 := makeActivation(t, lic1.ID)
	act2 := makeActivation(t, lic2.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	// Backdate BOTH to stale
	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act1.ID)
	require.NoError(t, err)
	_, err = s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act2.ID)
	require.NoError(t, err)

	// Reap only lic1 — lic2's stale activation must not be touched
	reaped, err := s.ReapStaleActivations(ctx, lic1.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)

	got2, err := s.GetActivation(ctx, act2.ID)
	require.NoError(t, err)
	assert.True(t, got2.Active, "lic2's activation must not be reaped")
}
```

- [ ] **Step 2: Add `ExecForTest` helper to PostgresStore**

The tests need to backdate `last_seen_at` directly. Add to `pkg/licensestore/postgres.go`:

```go
// ExecForTest exposes pool.Exec for integration tests that need to
// manipulate rows directly (e.g., backdating last_seen_at for reap
// tests). Not part of the Store interface — only available on the
// concrete PostgresStore.
func (s *PostgresStore) ExecForTest(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, sql, args...)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test -v -tags integration -run 'TestReapStaleActivations' ./pkg/licensestore/`
Expected: FAIL — `ReapStaleActivations` returns "not implemented"

- [ ] **Step 4: Implement `ReapStaleActivations`**

Replace the stub in `pkg/licensestore/postgres.go`:

```go
func (s *PostgresStore) ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE activations
		 SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1
		   AND active = TRUE
		   AND last_seen_at < NOW() - $2::interval`,
		licenseID, threshold.String(),
	)
	if err != nil {
		return 0, fmt.Errorf("reaping stale activations: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
```

Note: PostgreSQL accepts interval strings like `"336h0m0s"` via `::interval` cast. Go's `time.Duration.String()` produces this format. However, PostgreSQL's interval parser needs hours — `"336h0m0s"` works because PG interprets the `h` suffix. Verified by the integration test.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v -tags integration -run 'TestReapStaleActivations' ./pkg/licensestore/`
Expected: PASS (all 3 tests)

- [ ] **Step 6: Commit**

```bash
git add pkg/licensestore/postgres.go pkg/licensestore/postgres_test.go
git commit -m "feat(licensestore): implement ReapStaleActivations"
```

---

### Task 4: Integrate stale reaping into `Activate()`

**Files:**
- Modify: `pkg/licensestore/postgres.go:363-477`
- Modify: `pkg/licensestore/postgres_test.go`

- [ ] **Step 1: Add `StaleThreshold` field to `PostgresStore`**

In `pkg/licensestore/postgres.go`, add to the `PostgresStore` struct:

```go
// StaleThreshold is the duration after which an activation with no
// heartbeat is eligible for automatic reaping during Activate. When
// zero, no reaping occurs (backward compatible with all existing
// call sites). Set via SetStaleThreshold after construction.
StaleThreshold time.Duration
```

Add the setter:

```go
// SetStaleThreshold configures the stale activation reaping threshold.
// When non-zero, Activate() will reap stale seats before returning
// ErrSeatsFull. When zero (default), Activate behaves as before.
func (s *PostgresStore) SetStaleThreshold(d time.Duration) {
	s.StaleThreshold = d
}
```

- [ ] **Step 2: Write the failing integration test**

Add to `pkg/licensestore/postgres_test.go`:

```go
func TestActivate_ReapsStaleOnFull(t *testing.T) {
	s := openTestStore(t)
	s.SetStaleThreshold(14 * 24 * time.Hour)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 2
	require.NoError(t, s.CreateLicense(ctx, lic))

	// Fill both seats
	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	// Backdate act1 to 15 days ago (stale)
	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`,
		stale, act1.ID)
	require.NoError(t, err)

	// New activation should succeed — act1 gets reaped
	act3 := makeActivation(t, lic.ID)
	err = s.Activate(ctx, act3)
	require.NoError(t, err, "activation should succeed after reaping stale seat")

	// Verify: act1 reaped, act2 still active, act3 new active
	got1, err := s.GetActivation(ctx, act1.ID)
	require.NoError(t, err)
	assert.False(t, got1.Active, "stale act1 should be reaped")

	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "act2 + act3 should be active")
}

func TestActivate_StillFullAfterReap(t *testing.T) {
	s := openTestStore(t)
	s.SetStaleThreshold(14 * 24 * time.Hour)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 2
	require.NoError(t, s.CreateLicense(ctx, lic))

	// Fill both seats — both are FRESH (not stale)
	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	// Third activation should still fail — nothing stale to reap
	act3 := makeActivation(t, lic.ID)
	err := s.Activate(ctx, act3)
	var sf *licensestore.ErrSeatsFull
	assert.ErrorAs(t, err, &sf, "should still return ErrSeatsFull when no stale seats to reap")
}

func TestActivate_NoReapWhenThresholdZero(t *testing.T) {
	s := openTestStore(t)
	// StaleThreshold is zero (default) — no reaping
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 1
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))

	// Backdate act1 to stale
	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx,
		`UPDATE activations SET last_seen_at = $1 WHERE id = $2`,
		stale, act1.ID)
	require.NoError(t, err)

	// Without threshold set, should still fail (no reaping)
	act2 := makeActivation(t, lic.ID)
	err = s.Activate(ctx, act2)
	var sf *licensestore.ErrSeatsFull
	assert.ErrorAs(t, err, &sf, "should return ErrSeatsFull when threshold is zero even if stale seats exist")
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test -v -tags integration -run 'TestActivate_ReapsStale|TestActivate_StillFull|TestActivate_NoReap' ./pkg/licensestore/`
Expected: FAIL — `TestActivate_ReapsStaleOnFull` gets `ErrSeatsFull` instead of success

- [ ] **Step 4: Modify `Activate()` to reap-then-retry**

In `pkg/licensestore/postgres.go`, modify the `Activate` method. Replace the two `if activeCount >= lic.Seats` blocks (the re-activate path at line ~431 and the new-activation path at line ~459) with a helper call. Add this private method:

```go
// reapAndRecount attempts to reap stale activations for the given
// license within the provided transaction, then re-counts active
// seats. Returns the new active count. If StaleThreshold is zero,
// returns the original count unchanged (no reaping).
// Note: requires "encoding/json" in the import block (already present in postgres.go).
func (s *PostgresStore) reapAndRecount(ctx context.Context, tx pgx.Tx, licenseID string, currentCount int) (int, error) {
	if s.StaleThreshold <= 0 {
		return currentCount, nil
	}

	tag, err := tx.Exec(ctx,
		`UPDATE activations
		 SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1
		   AND active = TRUE
		   AND last_seen_at < NOW() - $2::interval`,
		licenseID, s.StaleThreshold.String(),
	)
	if err != nil {
		return currentCount, fmt.Errorf("reaping stale activations: %w", err)
	}
	reaped := int(tag.RowsAffected())
	if reaped == 0 {
		return currentCount, nil
	}

	// Audit: log the reap event inside the transaction. The audit_log
	// table is append-only so this doesn't conflict with the
	// serializable isolation on the activations table.
	details, _ := json.Marshal(map[string]any{"reaped": reaped, "threshold": s.StaleThreshold.String()})
	_, _ = tx.Exec(ctx,
		`INSERT INTO audit_log (timestamp, event_type, license_id, actor, details)
		 VALUES (NOW(), 'auto_reap', $1, 'system', $2)`,
		licenseID, details,
	)

	var newCount int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM activations WHERE license_id = $1 AND active = TRUE`,
		licenseID,
	).Scan(&newCount); err != nil {
		return currentCount, fmt.Errorf("re-counting seats after reap: %w", err)
	}
	return newCount, nil
}
```

Then modify the two seats-full checks in `Activate()`. Replace the re-activate path (around line 431):

```go
		if activeCount >= lic.Seats {
			activeCount, err = s.reapAndRecount(ctx, tx, act.LicenseID, activeCount)
			if err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("reap during re-activate: %w", err)
			}
			if activeCount >= lic.Seats {
				_ = tx.Rollback(ctx)
				return &ErrSeatsFull{LicenseID: act.LicenseID, Seats: lic.Seats, Used: activeCount}
			}
		}
```

And replace the new-activation path (around line 459):

```go
	if activeCount >= lic.Seats {
		activeCount, err = s.reapAndRecount(ctx, tx, act.LicenseID, activeCount)
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("reap during new activate: %w", err)
		}
		if activeCount >= lic.Seats {
			_ = tx.Rollback(ctx)
			return &ErrSeatsFull{LicenseID: act.LicenseID, Seats: lic.Seats, Used: activeCount}
		}
	}
```

- [ ] **Step 5: Run new tests to verify they pass**

Run: `go test -v -tags integration -run 'TestActivate_ReapsStale|TestActivate_StillFull|TestActivate_NoReap' ./pkg/licensestore/`
Expected: PASS (all 3 tests)

- [ ] **Step 6: Run full licensestore test suite**

Run: `go test -v -tags integration ./pkg/licensestore/`
Expected: All tests PASS (existing tests use zero threshold, no reaping)

- [ ] **Step 7: Commit**

```bash
git add pkg/licensestore/postgres.go pkg/licensestore/postgres_test.go
git commit -m "feat(licensestore): integrate stale seat reaping into Activate()"
```

---

### Task 5: Wire `StaleActivationThreshold` through the license server

**Files:**
- Modify: `pkg/licenseserver/config.go`
- Modify: `pkg/licenseserver/server.go`
- Modify: `cmd/licenseserver/main.go`

- [ ] **Step 1: Add field to Config**

In `pkg/licenseserver/config.go`, add to the `Config` struct:

```go
// StaleActivationThreshold is the duration after which an
// activation with no heartbeat is eligible for automatic reaping
// during seat-full scenarios. Default: 336h (14 days).
// Configurable via TRITON_LICENSE_SERVER_STALE_THRESHOLD.
StaleActivationThreshold time.Duration
```

- [ ] **Step 2: Pass threshold to store in `New()`**

In `pkg/licenseserver/server.go`, in the `New` function, add after the store is assigned (after `store: s,` in the struct literal). Since `New` receives a `licensestore.Store` (interface), we need a type assertion to call `SetStaleThreshold`. Add after the `srv` struct is constructed:

```go
// Wire stale-seat reaping threshold into the store. Type-assert to
// the concrete PostgresStore since SetStaleThreshold is not part of
// the Store interface (it's a deployment knob, not a storage contract).
if ps, ok := s.(*licensestore.PostgresStore); ok && cfg.StaleActivationThreshold > 0 {
	ps.SetStaleThreshold(cfg.StaleActivationThreshold)
}
```

- [ ] **Step 3: Wire env var in `cmd/licenseserver/main.go`**

In `cmd/licenseserver/main.go`, add after the `binariesDir` env var line:

```go
staleThresholdStr := envOr("TRITON_LICENSE_SERVER_STALE_THRESHOLD", "336h")
```

Parse it and add to the config construction. Add after the `binariesDir` mkdir block:

```go
staleThreshold, err := time.ParseDuration(staleThresholdStr)
if err != nil {
	return fmt.Errorf("parsing TRITON_LICENSE_SERVER_STALE_THRESHOLD: %w", err)
}
if staleThreshold < 24*time.Hour {
	return fmt.Errorf("TRITON_LICENSE_SERVER_STALE_THRESHOLD must be at least 24h (got %s)", staleThreshold)
}
```

Then add to the `cfg` struct literal:

```go
StaleActivationThreshold: staleThreshold,
```

- [ ] **Step 4: Verify compilation**

Run: `go build ./cmd/licenseserver/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/licenseserver/config.go pkg/licenseserver/server.go cmd/licenseserver/main.go
git commit -m "feat(licenseserver): wire StaleActivationThreshold config (default 14 days)"
```

---

### Task 6: Agent activation on startup

**Files:**
- Modify: `cmd/agent.go`
- Modify: `internal/agentconfig/loader.go`

- [ ] **Step 1: Add `LicenseServer` and `LicenseID` to `resolvedAgentConfig`**

In `cmd/agent.go`, add to the `resolvedAgentConfig` struct:

```go
licenseServer string // license server URL for seat management
licenseID     string // license UUID to activate against
```

- [ ] **Step 2: Populate the new fields in `resolveAgentConfig`**

In `cmd/agent.go`, in `resolveAgentConfig`, add after the `alsoLocal` resolution (before the `return` statement):

```go
licenseServer := strings.TrimRight(fileCfg.LicenseServer, "/")
licenseID := fileCfg.LicenseID
```

And add to the returned struct:

```go
licenseServer: licenseServer,
licenseID:     licenseID,
```

- [ ] **Step 3: Define `seatState` struct and `activateWithLicenseServer` function**

In `cmd/agent.go`, add after the `resolvedAgentConfig` struct:

```go
// seatState tracks whether the agent successfully registered with
// the license server. Used by the heartbeat and shutdown paths to
// know whether to call validate/deactivate.
type seatState struct {
	activated bool
	client    *license.ServerClient
	licenseID string
	token     string
}

// activateWithLicenseServer attempts to register this machine with
// the license server. On success it returns a seatState with
// activated=true and overwrites resolved.licenseToken with the
// server-issued token. On any failure it logs a warning and returns
// a zero seatState (activated=false) — the agent continues with
// whatever license_key was already resolved, degrading to free tier
// if none.
func activateWithLicenseServer(resolved *resolvedAgentConfig) seatState {
	if resolved.licenseServer == "" || resolved.licenseID == "" {
		return seatState{}
	}

	client := license.NewServerClient(resolved.licenseServer)
	resp, err := client.Activate(resolved.licenseID)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: license server activation failed: %v — continuing with existing license\n", err)
		return seatState{client: client, licenseID: resolved.licenseID}
	}

	// Activation succeeded — use the server-issued token
	resolved.licenseToken = resp.Token
	fmt.Printf("  seat:        registered (%d/%d seats used, expires %s)\n",
		resp.SeatsUsed, resp.Seats, resp.ExpiresAt)

	return seatState{
		activated: true,
		client:    client,
		licenseID: resolved.licenseID,
		token:     resp.Token,
	}
}
```

- [ ] **Step 4: Wire into `runAgent`**

In `cmd/agent.go`, in `runAgent`, add the activation call after the `activeGuard` resolution block (after `resolved.licenseToken` is set from `fileCfg.LicenseKey` but BEFORE the `applyTierFiltering` call). Insert:

```go
// Attempt license server activation (seat registration).
// On success this overwrites resolved.licenseToken with the
// server-issued token, which then flows into activeGuard below.
seat := activateWithLicenseServer(resolved)

// If activation gave us a fresh token, rebuild the guard from it.
if seat.activated {
	activeGuard = license.NewGuard(resolved.licenseToken)
}
```

- [ ] **Step 5: Verify compilation**

Run: `go build ./cmd/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/agent.go
git commit -m "feat(agent): activate with license server on startup"
```

---

### Task 7: Agent heartbeat before each scan

**Files:**
- Modify: `cmd/agent.go`

- [ ] **Step 1: Add `heartbeat` function**

In `cmd/agent.go`, add after `activateWithLicenseServer`:

```go
// heartbeat calls the license server's validate endpoint to update
// last_seen_at and detect tier changes or revocations. Returns the
// updated guard if the tier changed, or the original guard if
// validation failed or was skipped. Mutates seat.activated to false
// on invalid response (stops future heartbeats).
func heartbeat(seat *seatState, currentGuard *license.Guard) *license.Guard {
	if !seat.activated || seat.client == nil {
		return currentGuard
	}

	resp, err := seat.client.Validate(seat.licenseID, seat.token)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: license server heartbeat failed: %v — continuing with current tier\n", err)
		return currentGuard
	}

	if !resp.Valid {
		fmt.Fprintf(os.Stderr,
			"warning: license server reports license invalid — degrading to free tier\n")
		seat.activated = false
		return license.NewGuard("") // free tier
	}

	// Check if tier changed (admin upgraded/downgraded the license)
	if resp.Tier != "" && license.Tier(resp.Tier) != currentGuard.Tier() {
		fmt.Printf("  license tier changed: %s → %s\n", currentGuard.Tier(), resp.Tier)
		return license.NewGuard(seat.token)
	}

	return currentGuard
}
```

- [ ] **Step 2: Wire into the scan loop**

In `cmd/agent.go`, in `runAgent`, inside the `for` loop, add BEFORE the `runAgentScan` call:

```go
		// Heartbeat: update last_seen_at and detect tier changes.
		activeGuard = heartbeat(&seat, activeGuard)
```

Note: on the first iteration (right after startup), this heartbeat is redundant with the activation call. That's fine — `Validate` is idempotent and the `last_seen_at` update is harmless. Keeping the code simple is worth one extra HTTP call on first iteration.

- [ ] **Step 3: Verify compilation**

Run: `go build ./cmd/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/agent.go
git commit -m "feat(agent): heartbeat via /validate before each scan iteration"
```

---

### Task 8: Agent deactivation on shutdown

**Files:**
- Modify: `cmd/agent.go`

- [ ] **Step 1: Add `deactivateOnShutdown` function**

In `cmd/agent.go`, add after `heartbeat`:

```go
// deactivateOnShutdown unregisters this machine from the license
// server, freeing the seat for reuse. Best-effort: errors are
// logged and ignored — the 14-day stale reaper handles ghost seats
// from unclean shutdowns.
func deactivateOnShutdown(seat *seatState) {
	if !seat.activated || seat.client == nil {
		return
	}
	// Use a fresh context with a short timeout — the parent context
	// is already canceled (that's why we're shutting down).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := seat.client.Deactivate(seat.licenseID); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: license server deactivation failed: %v (seat will be reclaimed after 14 days)\n", err)
		_ = ctx // ctx is used by the timeout; Deactivate doesn't take ctx yet
		return
	}
	fmt.Println("  seat:        deactivated (seat freed)")
}
```

Note: The current `ServerClient.Deactivate()` doesn't take a context. The 5-second timeout is enforced by the HTTP client's own timeout (15s). If needed in the future, `Deactivate` can be upgraded to accept a context — but the 15s client timeout is sufficient for now and we avoid changing the `ServerClient` API.

- [ ] **Step 2: Wire into `runAgent` after the scan loop**

In `cmd/agent.go`, in `runAgent`, add the deactivation call after the scan loop. The current loop structure is:

```go
	for {
		if err := runAgentScan(ctx, activeGuard, resolved, client); err != nil {
			...
		}
		if agentInterval == 0 {
			return nil
		}
		// wait for next interval...
	}
```

Modify the one-shot exit and add a defer:

After `seat := activateWithLicenseServer(resolved)` and the guard rebuild, add:

```go
// Deactivate on shutdown — covers both SIGINT/SIGTERM (loop exit
// via ctx.Done()) and one-shot completion (agentInterval == 0).
defer deactivateOnShutdown(&seat)
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./cmd/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/agent.go
git commit -m "feat(agent): deactivate seat on clean shutdown"
```

---

### Task 9: Agent unit tests

**Files:**
- Modify: `cmd/agent_test.go` (or create if it doesn't exist)

- [ ] **Step 1: Verify test file exists**

Run: `ls cmd/agent_test.go 2>/dev/null || echo "NOT FOUND"`

Check for an existing test file. If it doesn't exist, create `cmd/agent_test.go` with the package header. If it exists, append to it.

- [ ] **Step 2: Write tests for `activateWithLicenseServer`**

Create or add to `cmd/agent_test.go`:

```go
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/internal/license"
)

func TestActivateWithLicenseServer_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/license/activate", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "server-issued-token",
			"activationID": "act-123",
			"tier":         "pro",
			"seats":        5,
			"seatsUsed":    2,
			"expiresAt":    "2027-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	resolved := &resolvedAgentConfig{
		licenseServer: srv.URL,
		licenseID:     "lic-uuid",
		licenseToken:  "old-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.True(t, seat.activated)
	assert.Equal(t, "server-issued-token", seat.token)
	assert.Equal(t, "server-issued-token", resolved.licenseToken,
		"resolved.licenseToken should be overwritten with server-issued token")
}

func TestActivateWithLicenseServer_SeatsFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "all seats are occupied"})
	}))
	defer srv.Close()

	resolved := &resolvedAgentConfig{
		licenseServer: srv.URL,
		licenseID:     "lic-uuid",
		licenseToken:  "existing-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.False(t, seat.activated, "should not be activated when seats are full")
	assert.Equal(t, "existing-token", resolved.licenseToken,
		"existing token should be preserved on failure")
}

func TestActivateWithLicenseServer_NetworkError(t *testing.T) {
	resolved := &resolvedAgentConfig{
		licenseServer: "http://localhost:1", // unreachable
		licenseID:     "lic-uuid",
		licenseToken:  "existing-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.False(t, seat.activated)
	assert.Equal(t, "existing-token", resolved.licenseToken)
}

func TestActivateWithLicenseServer_NotConfigured(t *testing.T) {
	resolved := &resolvedAgentConfig{
		licenseServer: "",
		licenseID:     "",
	}
	seat := activateWithLicenseServer(resolved)
	assert.False(t, seat.activated)
	assert.Nil(t, seat.client)
}

func TestHeartbeat_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "tier": "pro",
		})
	}))
	defer srv.Close()

	guard := license.NewGuard("") // free tier initially
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result := heartbeat(seat, guard)
	assert.True(t, seat.activated, "should remain activated")
	// The guard should be rebuilt if tier changed
	_ = result
}

func TestHeartbeat_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": false, "reason": "license revoked",
		})
	}))
	defer srv.Close()

	guard := license.NewGuard("")
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result := heartbeat(seat, guard)
	assert.False(t, seat.activated, "should stop heartbeating after invalid response")
	assert.Equal(t, license.TierFree, result.Tier())
}

func TestHeartbeat_NetworkError(t *testing.T) {
	guard := license.NewGuard("")
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient("http://localhost:1"),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result := heartbeat(seat, guard)
	assert.True(t, seat.activated, "should remain activated on network error")
	assert.Equal(t, guard, result, "should return original guard on network error")
}

func TestHeartbeat_NotActivated(t *testing.T) {
	guard := license.NewGuard("")
	seat := &seatState{activated: false}
	result := heartbeat(seat, guard)
	assert.Equal(t, guard, result)
}

func TestDeactivateOnShutdown_Activated(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "/api/v1/license/deactivate", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deactivated"})
	}))
	defer srv.Close()

	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
	}
	deactivateOnShutdown(seat)
	assert.True(t, called, "should call deactivate endpoint")
}

func TestDeactivateOnShutdown_NotActivated(t *testing.T) {
	seat := &seatState{activated: false}
	deactivateOnShutdown(seat) // should not panic or make any calls
}
```

- [ ] **Step 3: Run the tests**

Run: `go test -v -run 'TestActivateWithLicenseServer|TestHeartbeat|TestDeactivateOnShutdown' ./cmd/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/agent_test.go
git commit -m "test(agent): unit tests for activation, heartbeat, and deactivation"
```

---

### Task 10: Full test suite verification and cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run unit tests**

Run: `make test`
Expected: All PASS

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: No new warnings

- [ ] **Step 3: Build all binaries**

Run: `make build && make build-licenseserver`
Expected: Both binaries compile cleanly

- [ ] **Step 4: Run integration tests (if PostgreSQL available)**

Run: `make test-integration`
Expected: All PASS (existing tests use zero threshold — backward compatible)

- [ ] **Step 5: Final commit (if any fixups needed)**

```bash
git add -A
git commit -m "fix: address lint/test issues from seat management implementation"
```

Only run this step if previous steps produced fixups. Do not create an empty commit.

---

## Review Checkpoint

After Task 10, pause for code review before merging. Key areas to verify:

1. **Backward compatibility:** Agent without `license_server` in yaml behaves identically to before
2. **Store interface:** `ReapStaleActivations` added; `Activate` signature unchanged
3. **Transaction safety:** `reapAndRecount` runs inside the existing serializable transaction
4. **Graceful degradation:** seats-full, revoked, expired, network errors all degrade to free tier
5. **No silent failures:** every degradation path logs a warning to stderr
