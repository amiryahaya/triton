# Portal-Pushed Schedule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** License server can push a `schedule` + `schedule_jitter` override on the existing `/validate` heartbeat; the agent applies it on the next iteration, overriding local `agent.yaml`.

**Architecture:** Two nullable columns on `licenses`, additive fields on `ValidateResponse`, a new `PATCH /api/v1/admin/licenses/{id}` handler with server-side cron validation, and an agent heartbeat lifecycle that stashes a `baseSched` at startup and swaps to a pushed override (or back to base on clear).

**Tech Stack:** Go 1.25, PostgreSQL 18 (pgx/v5), `github.com/robfig/cron/v3` (already vendored in PR #79), go-chi/v5, embedded vanilla JS admin UI.

**Spec:** `docs/plans/2026-04-19-portal-pushed-schedule-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `pkg/licensestore/migrations.go` | New migration entry #6 adding two columns. |
| `pkg/licensestore/store.go` | `LicenseRecord` gains two fields. |
| `pkg/licensestore/postgres.go` | `CreateLicense`, `GetLicense`, `ListLicenses` round-trip the new columns. New `UpdateLicense` method for partial updates. |
| `pkg/licensestore/postgres_test.go` | Round-trip tests + update tests. |
| `pkg/licenseserver/handlers_license.go` | `handleCreateLicense` extension + new `handleUpdateLicense`; cron validation; audit entry. |
| `pkg/licenseserver/handlers_license_test.go` | New file for update-handler tests (or extend existing). |
| `pkg/licenseserver/handlers_activation.go` | `handleValidate` populates `schedule` + `scheduleJitterSeconds` in response. |
| `pkg/licenseserver/server.go` | Register new `PATCH /licenses/{id}` route. |
| `internal/license/client.go` | `ValidateResponse` gains two fields; test verifies round-trip. |
| `cmd/agent.go` | `heartbeat` signature change; `runAgent` adds `baseSched` + override swap logic. |
| `cmd/agent_schedule_test.go` | New tests for override lifecycle. |
| `pkg/licenseserver/ui/dist/app.js` + `index.html` + `style.css` | Admin UI fields on license detail + create form. |
| `test/integration/license_schedule_push_test.go` (new) | Full lifecycle: create license, PATCH schedule, validate returns it, clear, validate returns empty. |
| `test/e2e/license-admin.spec.js` | Two Playwright tests (edit schedule + invalid cron error surface). |
| `docs/DEPLOYMENT_GUIDE.md` | "Server-pushed schedule override" subsection under §7c-bis. |
| `CLAUDE.md` | One-line addition under "Agent scheduling." |

Rough size: ~400 LOC production, ~500 LOC tests, ~120 LOC UI, ~60 LOC docs.

---

## Task 1: Migration — schedule + schedule_jitter columns

**Files:**
- Modify: `pkg/licensestore/migrations.go`
- Test: `pkg/licensestore/postgres_test.go`

- [ ] **Step 1: Read current migration chain**

Run:
```bash
grep -c "^	\`" pkg/licensestore/migrations.go
```

Expected: 5. Confirm the new migration will be index 5 (0-based), i.e. the 6th entry.

- [ ] **Step 2: Write the failing column-existence test**

Append to `pkg/licensestore/postgres_test.go`:

```go
func TestMigration_SchedulePushColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB test in -short mode")
	}
	store := newTestStore(t)
	defer store.Close()

	// Verify the two new columns exist with the expected types.
	var scheduleType, jitterType string
	err := store.Pool().QueryRow(context.Background(), `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_name = 'licenses' AND column_name = 'schedule'
	`).Scan(&scheduleType)
	if err != nil {
		t.Fatalf("querying schedule column: %v", err)
	}
	if scheduleType != "text" {
		t.Errorf("schedule column type = %q, want text", scheduleType)
	}

	err = store.Pool().QueryRow(context.Background(), `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_name = 'licenses' AND column_name = 'schedule_jitter'
	`).Scan(&jitterType)
	if err != nil {
		t.Fatalf("querying schedule_jitter column: %v", err)
	}
	if jitterType != "integer" {
		t.Errorf("schedule_jitter column type = %q, want integer", jitterType)
	}
}
```

NOTE: If `store.Pool()` is not a public accessor, add a test-only helper or use the package-internal test DB URL used by other tests in this file. Check how `newTestStore` exposes the pool before writing this; if it doesn't, a 2-line exported helper is acceptable.

- [ ] **Step 3: Run test to verify it fails**

Run:
```bash
go test ./pkg/licensestore/ -run TestMigration_SchedulePushColumns -v
```

Expected: FAIL — columns not found.

- [ ] **Step 4: Add the migration**

In `pkg/licensestore/migrations.go`, append after the last existing migration entry (keep the slice trailing comma style):

```go
	`ALTER TABLE licenses
		ADD COLUMN IF NOT EXISTS schedule        TEXT,
		ADD COLUMN IF NOT EXISTS schedule_jitter INTEGER;

	DO $$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'licenses_schedule_jitter_check') THEN
			ALTER TABLE licenses ADD CONSTRAINT licenses_schedule_jitter_check
				CHECK (schedule_jitter IS NULL OR schedule_jitter >= 0);
		END IF;
	END$$;`,
```

- [ ] **Step 5: Run test to verify it passes**

Run:
```bash
go test ./pkg/licensestore/ -run TestMigration_SchedulePushColumns -v
```

Expected: PASS.

- [ ] **Step 6: Run full licensestore suite**

Run:
```bash
go test ./pkg/licensestore/... -v 2>&1 | tail -5
```

Expected: all tests PASS (no regressions on existing migration idempotency).

- [ ] **Step 7: Commit**

```bash
git add pkg/licensestore/migrations.go pkg/licensestore/postgres_test.go
git commit -m "licensestore: migration adds schedule + schedule_jitter columns

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: LicenseRecord fields

**Files:**
- Modify: `pkg/licensestore/store.go`
- Test: `pkg/licensestore/postgres_test.go`

- [ ] **Step 1: Write the failing struct-shape test**

Append to `pkg/licensestore/postgres_test.go`:

```go
func TestLicenseRecord_ScheduleFields(t *testing.T) {
	// Pure compile+runtime check that the fields exist with the
	// expected types and JSON tags. Prevents accidental field
	// removal or rename.
	lic := LicenseRecord{
		Schedule:       "0 2 * * *",
		ScheduleJitter: 30,
	}
	if lic.Schedule != "0 2 * * *" {
		t.Errorf("Schedule = %q", lic.Schedule)
	}
	if lic.ScheduleJitter != 30 {
		t.Errorf("ScheduleJitter = %d", lic.ScheduleJitter)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./pkg/licensestore/ -run TestLicenseRecord_ScheduleFields -v
```

Expected: FAIL — `Schedule` / `ScheduleJitter` undefined on LicenseRecord.

- [ ] **Step 3: Add the fields**

In `pkg/licensestore/store.go`, inside the `LicenseRecord` struct (after `ProductScope`, before the "populated by joins" block):

```go
	// Schedule is an optional cron expression pushed to the agent on
	// /validate. Empty string (DB NULL) means "no override; agent
	// uses its local agent.yaml schedule/interval." See
	// docs/plans/2026-04-19-portal-pushed-schedule-design.md.
	Schedule string `json:"schedule"`

	// ScheduleJitter is the optional jitter bound in seconds applied
	// on top of the cron fire time. 0 disables (no jitter). Only
	// meaningful when Schedule is non-empty.
	ScheduleJitter int `json:"scheduleJitterSeconds"`
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./pkg/licensestore/ -run TestLicenseRecord_ScheduleFields -v
```

Expected: PASS.

- [ ] **Step 5: Verify no unrelated test broken**

Run:
```bash
go test ./pkg/licensestore/... 2>&1 | tail -5
```

Expected: all PASS (the field addition is purely additive on the struct).

- [ ] **Step 6: Commit**

```bash
git add pkg/licensestore/store.go pkg/licensestore/postgres_test.go
git commit -m "licensestore: LicenseRecord gains Schedule + ScheduleJitter fields

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Store CRUD — round-trip + UpdateLicense

**Files:**
- Modify: `pkg/licensestore/postgres.go`
- Modify: `pkg/licensestore/store.go` (Store interface)
- Test: `pkg/licensestore/postgres_test.go`

- [ ] **Step 1: Write the failing round-trip test**

Append to `pkg/licensestore/postgres_test.go`:

```go
func TestLicenseCRUD_ScheduleRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB test in -short mode")
	}
	store := newTestStore(t)
	defer store.Close()
	ctx := context.Background()

	org := createTestOrg(t, store, "ScheduleCo")
	lic := &LicenseRecord{
		ID:             "sched-lic-1",
		OrgID:          org.ID,
		Tier:           "enterprise",
		Seats:          5,
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		CreatedAt:      time.Now(),
		Schedule:       "0 2 * * 0",
		ScheduleJitter: 45,
	}
	if err := store.CreateLicense(ctx, lic); err != nil {
		t.Fatalf("CreateLicense: %v", err)
	}

	got, err := store.GetLicense(ctx, lic.ID)
	if err != nil {
		t.Fatalf("GetLicense: %v", err)
	}
	if got.Schedule != "0 2 * * 0" {
		t.Errorf("Schedule = %q, want %q", got.Schedule, "0 2 * * 0")
	}
	if got.ScheduleJitter != 45 {
		t.Errorf("ScheduleJitter = %d, want 45", got.ScheduleJitter)
	}
}

func TestUpdateLicense_ScheduleFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB test in -short mode")
	}
	store := newTestStore(t)
	defer store.Close()
	ctx := context.Background()

	org := createTestOrg(t, store, "UpdateCo")
	lic := &LicenseRecord{
		ID:        "upd-lic-1",
		OrgID:     org.ID,
		Tier:      "pro",
		Seats:     3,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	if err := store.CreateLicense(ctx, lic); err != nil {
		t.Fatalf("CreateLicense: %v", err)
	}

	// Set schedule.
	if err := store.UpdateLicense(ctx, lic.ID, LicenseUpdate{
		Schedule:       stringPtr("*/15 * * * *"),
		ScheduleJitter: intPtr(15),
	}); err != nil {
		t.Fatalf("UpdateLicense set: %v", err)
	}
	got, _ := store.GetLicense(ctx, lic.ID)
	if got.Schedule != "*/15 * * * *" || got.ScheduleJitter != 15 {
		t.Errorf("after set: Schedule=%q jitter=%d", got.Schedule, got.ScheduleJitter)
	}

	// Clear schedule via empty string.
	if err := store.UpdateLicense(ctx, lic.ID, LicenseUpdate{
		Schedule:       stringPtr(""),
		ScheduleJitter: intPtr(0),
	}); err != nil {
		t.Fatalf("UpdateLicense clear: %v", err)
	}
	got, _ = store.GetLicense(ctx, lic.ID)
	if got.Schedule != "" || got.ScheduleJitter != 0 {
		t.Errorf("after clear: Schedule=%q jitter=%d (want empty + 0)", got.Schedule, got.ScheduleJitter)
	}
}

// Tiny helpers for *T when nil means "don't touch" vs *T("") means "clear."
func stringPtr(s string) *string { return &s }
func intPtr(n int) *int          { return &n }
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./pkg/licensestore/ -run "TestLicenseCRUD_ScheduleRoundTrip|TestUpdateLicense_ScheduleFields" -v
```

Expected: FAIL — `UpdateLicense` and `LicenseUpdate` don't exist; `CreateLicense` doesn't write the two new columns.

- [ ] **Step 3: Extend `CreateLicense` + `GetLicense` + `ListLicenses` to handle the new columns**

In `pkg/licensestore/postgres.go`, replace the `CreateLicense` INSERT with:

```go
func (s *PostgresStore) CreateLicense(ctx context.Context, lic *LicenseRecord) error {
	var schedule *string
	if lic.Schedule != "" {
		v := lic.Schedule
		schedule = &v
	}
	var jitter *int
	if lic.ScheduleJitter != 0 {
		v := lic.ScheduleJitter
		jitter = &v
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO licenses (id, org_id, tier, seats, issued_at, expires_at, notes, created_at,
		                       features, limits, soft_buffer_pct, product_scope,
		                       schedule, schedule_jitter)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		lic.ID, lic.OrgID, lic.Tier, lic.Seats,
		lic.IssuedAt, lic.ExpiresAt, lic.Notes, lic.CreatedAt,
		lic.Features, lic.Limits,
		softBufferPctOrDefault(lic.SoftBufferPct),
		productScopeOrDefault(lic.ProductScope),
		schedule, jitter,
	)
	if err != nil {
		return fmt.Errorf("creating license: %w", err)
	}
	return nil
}
```

Then update `GetLicense`'s SELECT and Scan to include the two columns. Find the existing query:

```go
`SELECT l.id, l.org_id, l.tier, l.seats, l.issued_at, l.expires_at,
        l.revoked, l.revoked_at, l.revoked_by, l.notes, l.created_at,
        l.features, l.limits, l.soft_buffer_pct, l.product_scope,
        o.name,
        (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id AND a.active = TRUE)
 FROM licenses l
 JOIN organizations o ON o.id = l.org_id
 WHERE l.id = $1`
```

Replace with:

```go
`SELECT l.id, l.org_id, l.tier, l.seats, l.issued_at, l.expires_at,
        l.revoked, l.revoked_at, l.revoked_by, l.notes, l.created_at,
        l.features, l.limits, l.soft_buffer_pct, l.product_scope,
        COALESCE(l.schedule, ''), COALESCE(l.schedule_jitter, 0),
        o.name,
        (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id AND a.active = TRUE)
 FROM licenses l
 JOIN organizations o ON o.id = l.org_id
 WHERE l.id = $1`
```

And the `.Scan` below it:

```go
).Scan(&lic.ID, &lic.OrgID, &lic.Tier, &lic.Seats,
    &lic.IssuedAt, &lic.ExpiresAt,
    &lic.Revoked, &lic.RevokedAt, &lic.RevokedBy, &lic.Notes, &lic.CreatedAt,
    &lic.Features, &lic.Limits, &lic.SoftBufferPct, &lic.ProductScope,
    &lic.Schedule, &lic.ScheduleJitter,
    &lic.OrgName, &lic.SeatsUsed,
)
```

Do the same extension to `ListLicenses` (the SELECT + Scan follow the same pattern — add the two COALESCE'd columns + the two Scan targets in the same relative position).

- [ ] **Step 4: Add `LicenseUpdate` type + `UpdateLicense` method**

In `pkg/licensestore/store.go`, after `LicenseFilter`, add:

```go
// LicenseUpdate carries optional partial-update fields. A nil pointer
// means "leave this column untouched." A non-nil pointer writes its
// value — including empty string / zero, which means "clear the
// override." This three-state convention is the DB-neutral way to
// distinguish "don't touch" from "set to zero" in a JSON PATCH body.
type LicenseUpdate struct {
	Schedule       *string
	ScheduleJitter *int
}
```

Also extend the `Store` interface declaration in the same file to include:

```go
	UpdateLicense(ctx context.Context, id string, upd LicenseUpdate) error
```

In `pkg/licensestore/postgres.go`, after `RevokeLicense`, add:

```go
// UpdateLicense applies a partial update to the licenses row. Nil
// fields on upd are left untouched; non-nil fields are written.
// Empty string / zero values for Schedule / ScheduleJitter clear the
// columns (DB NULL).
func (s *PostgresStore) UpdateLicense(ctx context.Context, id string, upd LicenseUpdate) error {
	if upd.Schedule == nil && upd.ScheduleJitter == nil {
		return nil // nothing to do
	}
	setParts := []string{}
	args := []any{}
	i := 1
	if upd.Schedule != nil {
		if *upd.Schedule == "" {
			setParts = append(setParts, fmt.Sprintf("schedule = NULL"))
		} else {
			setParts = append(setParts, fmt.Sprintf("schedule = $%d", i))
			args = append(args, *upd.Schedule)
			i++
		}
	}
	if upd.ScheduleJitter != nil {
		if *upd.ScheduleJitter == 0 {
			setParts = append(setParts, fmt.Sprintf("schedule_jitter = NULL"))
		} else {
			setParts = append(setParts, fmt.Sprintf("schedule_jitter = $%d", i))
			args = append(args, *upd.ScheduleJitter)
			i++
		}
	}
	args = append(args, id)
	query := fmt.Sprintf(`UPDATE licenses SET %s WHERE id = $%d`,
		strings.Join(setParts, ", "), i)
	result, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating license: %w", err)
	}
	if result.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "license", ID: id}
	}
	return nil
}
```

Add `"strings"` to the import block at the top of `postgres.go` if not already present.

- [ ] **Step 5: Add test helper `createTestOrg` if not present**

Run:
```bash
grep -n "func createTestOrg" pkg/licensestore/postgres_test.go
```

If it doesn't exist, add this helper at the bottom of `postgres_test.go`:

```go
func createTestOrg(t *testing.T, store Store, name string) *Organization {
	t.Helper()
	org := &Organization{
		ID:   fmt.Sprintf("org-%s-%d", name, time.Now().UnixNano()),
		Name: name,
	}
	if err := store.CreateOrg(context.Background(), org); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	return org
}
```

If it already exists with a different signature, adapt the two tests above to match the existing helper.

- [ ] **Step 6: Run tests to verify they pass**

Run:
```bash
go test ./pkg/licensestore/ -run "TestLicenseCRUD_ScheduleRoundTrip|TestUpdateLicense_ScheduleFields" -v
```

Expected: both PASS.

- [ ] **Step 7: Run full licensestore suite**

Run:
```bash
go test ./pkg/licensestore/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/licensestore/
git commit -m "licensestore: round-trip schedule columns + UpdateLicense partial-update

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Admin API — PATCH + POST cron validation + audit

**Files:**
- Modify: `pkg/licenseserver/handlers_license.go`
- Modify: `pkg/licenseserver/server.go` (route registration)
- Test: `pkg/licenseserver/handlers_license_test.go` (new or append)

- [ ] **Step 1: Write failing test for POST with invalid cron**

Create `pkg/licenseserver/handlers_license_test.go` (or append if it exists):

```go
package licenseserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateLicense_InvalidCronRejected(t *testing.T) {
	ts := newAdminTestServer(t)
	defer ts.Close()

	body := map[string]any{
		"orgID":                  seedOrgID(t, ts),
		"tier":                   "pro",
		"seats":                  1,
		"expiresInDays":          30,
		"schedule":               "not a cron",
		"scheduleJitterSeconds":  0,
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/licenses", bytes.NewReader(buf))
	req.Header.Set("X-Triton-Admin-Key", testAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var errBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	if msg, _ := errBody["error"].(string); !strings.Contains(msg, "schedule") && !strings.Contains(msg, "cron") {
		t.Errorf("error message does not mention schedule/cron: %q", msg)
	}
}
```

NOTE: `newAdminTestServer` and `seedOrgID`/`testAdminKey` are expected to exist as test helpers. Before writing the test, grep:

```bash
grep -n "newAdminTestServer\|testAdminKey\|seedOrgID" pkg/licenseserver/*_test.go | head
```

If any helper doesn't exist under that exact name, use the actual existing helper (likely `newTestServer` or similar) and adapt. If no admin-auth helper exists, follow the pattern from `handlers_activation_v2_test.go` which already calls admin endpoints.

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./pkg/licenseserver/ -run TestCreateLicense_InvalidCronRejected -v
```

Expected: FAIL — the server accepts the invalid cron (because no validation exists yet) and returns 200 or 201.

- [ ] **Step 3: Add cron validation + schedule fields to create handler**

Open `pkg/licenseserver/handlers_license.go`. Locate the request-body struct inside `handleCreateLicense` (likely anonymous struct with JSON tags like `OrgID`, `Tier`, `Seats`). Add two new fields:

```go
		Schedule              string `json:"schedule"`
		ScheduleJitterSeconds int    `json:"scheduleJitterSeconds"`
```

Add validation after the existing required-field checks:

```go
	if req.Schedule != "" {
		if _, err := cron.ParseStandard(req.Schedule); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid schedule cron expression: %v", err))
			return
		}
	}
	if req.ScheduleJitterSeconds < 0 {
		writeError(w, http.StatusBadRequest, "scheduleJitterSeconds must be >= 0")
		return
	}
```

Add `"github.com/robfig/cron/v3"` to the import block at the top if not already present.

Populate the LicenseRecord before the store call:

```go
		lic.Schedule = req.Schedule
		lic.ScheduleJitter = req.ScheduleJitterSeconds
```

Add an audit log entry on successful create — check the existing `s.audit(...)` call already invoked in the handler; if the schedule is non-empty, include it in the `extra` map:

```go
	if req.Schedule != "" {
		extra["schedule"] = req.Schedule
		extra["scheduleJitterSeconds"] = req.ScheduleJitterSeconds
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./pkg/licenseserver/ -run TestCreateLicense_InvalidCronRejected -v
```

Expected: PASS.

- [ ] **Step 5: Write failing tests for PATCH**

Append to `pkg/licenseserver/handlers_license_test.go`:

```go
func TestUpdateLicense_SetAndClearSchedule(t *testing.T) {
	ts := newAdminTestServer(t)
	defer ts.Close()

	orgID := seedOrgID(t, ts)
	licID := createLicenseViaAPI(t, ts, orgID, map[string]any{
		"tier":          "pro",
		"seats":         1,
		"expiresInDays": 30,
	})

	// Set a schedule via PATCH.
	setBody := map[string]any{
		"schedule":              "0 2 * * 0",
		"scheduleJitterSeconds": 30,
	}
	if code, _ := patchLicense(t, ts, licID, setBody); code != http.StatusOK {
		t.Fatalf("PATCH set = %d, want 200", code)
	}

	// Verify via GET.
	got := getLicense(t, ts, licID)
	if got["schedule"] != "0 2 * * 0" {
		t.Errorf("GET schedule = %v", got["schedule"])
	}
	if int(got["scheduleJitterSeconds"].(float64)) != 30 {
		t.Errorf("GET jitter = %v", got["scheduleJitterSeconds"])
	}

	// Clear with empty string.
	clrBody := map[string]any{
		"schedule":              "",
		"scheduleJitterSeconds": 0,
	}
	if code, _ := patchLicense(t, ts, licID, clrBody); code != http.StatusOK {
		t.Fatalf("PATCH clear = %d, want 200", code)
	}
	got = getLicense(t, ts, licID)
	if got["schedule"] != "" {
		t.Errorf("GET schedule after clear = %v, want empty", got["schedule"])
	}
}

func TestUpdateLicense_InvalidCronRejected(t *testing.T) {
	ts := newAdminTestServer(t)
	defer ts.Close()
	orgID := seedOrgID(t, ts)
	licID := createLicenseViaAPI(t, ts, orgID, map[string]any{
		"tier": "pro", "seats": 1, "expiresInDays": 30,
	})
	code, _ := patchLicense(t, ts, licID, map[string]any{"schedule": "nope"})
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

// createLicenseViaAPI, patchLicense, getLicense are small helpers;
// add them at the bottom of this file.
func createLicenseViaAPI(t *testing.T, ts *httptest.Server, orgID string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"orgID": orgID}
	for k, v := range extra {
		body[k] = v
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/licenses", bytes.NewReader(buf))
	req.Header.Set("X-Triton-Admin-Key", testAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("create: status=%d err=%v", resp.StatusCode, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out["id"].(string)
}

func patchLicense(t *testing.T, ts *httptest.Server, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/admin/licenses/"+id, bytes.NewReader(buf))
	req.Header.Set("X-Triton-Admin-Key", testAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func getLicense(t *testing.T, ts *httptest.Server, id string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/licenses/"+id, nil)
	req.Header.Set("X-Triton-Admin-Key", testAdminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run:
```bash
go test ./pkg/licenseserver/ -run TestUpdateLicense -v
```

Expected: FAIL — 404 (no PATCH route registered).

- [ ] **Step 7: Add the PATCH handler**

In `pkg/licenseserver/handlers_license.go`, append:

```go
// handleUpdateLicense applies a partial update to a license row.
// Currently supports only schedule + scheduleJitterSeconds; extend
// the struct below when additional mutable fields are added.
func (s *Server) handleUpdateLicense(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "license id required")
		return
	}

	var req struct {
		Schedule              *string `json:"schedule"`
		ScheduleJitterSeconds *int    `json:"scheduleJitterSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Schedule != nil && *req.Schedule != "" {
		if _, err := cron.ParseStandard(*req.Schedule); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid schedule cron expression: %v", err))
			return
		}
	}
	if req.ScheduleJitterSeconds != nil && *req.ScheduleJitterSeconds < 0 {
		writeError(w, http.StatusBadRequest, "scheduleJitterSeconds must be >= 0")
		return
	}

	upd := licensestore.LicenseUpdate{
		Schedule:       req.Schedule,
		ScheduleJitter: req.ScheduleJitterSeconds,
	}
	if err := s.store.UpdateLicense(r.Context(), id, upd); err != nil {
		if errors.Is(err, &licensestore.ErrNotFound{}) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	extra := map[string]any{}
	if req.Schedule != nil {
		extra["schedule"] = *req.Schedule
	}
	if req.ScheduleJitterSeconds != nil {
		extra["scheduleJitterSeconds"] = *req.ScheduleJitterSeconds
	}
	s.audit(r, "license_schedule_updated", id, "", "", extra)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

Add imports as needed: `"github.com/go-chi/chi/v5"`, `"github.com/robfig/cron/v3"`, `"errors"`, and `"github.com/amiryahaya/triton/pkg/licensestore"`. Most of these are likely already imported in the file.

- [ ] **Step 8: Register the route**

In `pkg/licenseserver/server.go`, locate the admin-licenses route block. After the existing `r.Post("/licenses", ...)` line, add:

```go
		r.Patch("/licenses/{id}", srv.handleUpdateLicense)
```

- [ ] **Step 9: Run tests to verify they pass**

Run:
```bash
go test ./pkg/licenseserver/ -run "TestUpdateLicense|TestCreateLicense_InvalidCron" -v
```

Expected: all PASS.

- [ ] **Step 10: Extend the existing `handleGetLicense` to return the new fields (if not already automatic via JSON tags)**

Run:
```bash
grep -n "handleGetLicense\|schedule" pkg/licenseserver/handlers_license.go | head -10
```

If `handleGetLicense` writes via `writeJSON(w, 200, lic)` where `lic` is a `*LicenseRecord`, the JSON tags from Task 2 already serialize the fields — no change needed. If it copies into an anonymous struct, add the two fields to that struct.

- [ ] **Step 11: Run full licenseserver suite**

Run:
```bash
go test ./pkg/licenseserver/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 12: Commit**

```bash
git add pkg/licenseserver/
git commit -m "licenseserver: admin API create/patch schedule + cron validation + audit

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Gateway — populate schedule in /validate response

**Files:**
- Modify: `pkg/licenseserver/handlers_activation.go`
- Test: `pkg/licenseserver/handlers_activation_test.go` (append or new; check existing activation tests)

- [ ] **Step 1: Write failing test**

Append to an existing activation-handler test file (e.g., `handlers_activation_test.go` or `handlers_activation_v2_test.go`):

```go
func TestValidate_ReturnsScheduleFromLicense(t *testing.T) {
	ts := newAdminTestServer(t)
	defer ts.Close()

	orgID := seedOrgID(t, ts)
	licID := createLicenseViaAPI(t, ts, orgID, map[string]any{
		"tier": "pro", "seats": 1, "expiresInDays": 30,
		"schedule": "0 2 * * *", "scheduleJitterSeconds": 60,
	})

	// Activate a machine.
	actResp := activateMachine(t, ts, licID, "machine-abc")

	// Validate and assert the response carries the schedule fields.
	valResp := validateMachine(t, ts, licID, "machine-abc", actResp["token"].(string))
	if valResp["schedule"] != "0 2 * * *" {
		t.Errorf("schedule = %v, want '0 2 * * *'", valResp["schedule"])
	}
	if int(valResp["scheduleJitterSeconds"].(float64)) != 60 {
		t.Errorf("jitter = %v, want 60", valResp["scheduleJitterSeconds"])
	}
}

func TestValidate_EmptyScheduleOmitted(t *testing.T) {
	ts := newAdminTestServer(t)
	defer ts.Close()
	orgID := seedOrgID(t, ts)
	licID := createLicenseViaAPI(t, ts, orgID, map[string]any{
		"tier": "pro", "seats": 1, "expiresInDays": 30,
	})
	actResp := activateMachine(t, ts, licID, "machine-abc")
	valResp := validateMachine(t, ts, licID, "machine-abc", actResp["token"].(string))
	// With omitempty on the wire and no schedule set, the key is absent.
	if v, ok := valResp["schedule"]; ok && v != "" {
		t.Errorf("schedule should be absent or empty, got %v", v)
	}
}

// activateMachine and validateMachine helpers — add at the bottom of
// the file if not already present:

func activateMachine(t *testing.T, ts *httptest.Server, licID, machineID string) map[string]any {
	t.Helper()
	body := map[string]any{
		"licenseID": licID,
		"machineID": machineID,
		"hostname":  "h-" + machineID,
		"os":        "linux",
		"arch":      "amd64",
	}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/api/v1/activate", "application/json", bytes.NewReader(buf))
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("activate: status=%d err=%v", resp.StatusCode, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func validateMachine(t *testing.T, ts *httptest.Server, licID, machineID, token string) map[string]any {
	t.Helper()
	body := map[string]any{
		"licenseID": licID,
		"machineID": machineID,
		"token":     token,
	}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/api/v1/validate", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./pkg/licenseserver/ -run "TestValidate_ReturnsScheduleFromLicense|TestValidate_EmptyScheduleOmitted" -v
```

Expected: FAIL — `schedule` key not present in validate response.

- [ ] **Step 3: Populate the validate response**

In `pkg/licenseserver/handlers_activation.go`, inside `handleValidate`, find the existing `writeJSON(w, http.StatusOK, map[string]any{...})` call at the end. Add the two new fields to the map:

```go
	resp := map[string]any{
		"valid":           true,
		"tier":            lic.Tier,
		"orgID":           lic.OrgID,
		"orgName":         orgName,
		"seats":           lic.Seats,
		"seatsUsed":       lic.SeatsUsed,
		"expiresAt":       lic.ExpiresAt.Format(time.RFC3339),
		"cacheTTL":        validateCacheTTLSeconds,
		"features":        features,
		"limits":          limits,
		"soft_buffer_pct": lic.SoftBufferPct,
		"product_scope":   lic.ProductScope,
		"usage":           usage,
	}
	// Portal-pushed schedule override (design spec
	// 2026-04-19-portal-pushed-schedule-design.md). Emit only when
	// non-empty so old agents with no corresponding field see an
	// absent key rather than an empty string.
	if lic.Schedule != "" {
		resp["schedule"] = lic.Schedule
		resp["scheduleJitterSeconds"] = lic.ScheduleJitter
	}
	writeJSON(w, http.StatusOK, resp)
```

(Replace the existing inline `writeJSON(w, http.StatusOK, map[string]any{...})` with the two-statement version above.)

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./pkg/licenseserver/ -run "TestValidate_ReturnsScheduleFromLicense|TestValidate_EmptyScheduleOmitted" -v
```

Expected: both PASS.

- [ ] **Step 5: Run full licenseserver suite to confirm no regression**

Run:
```bash
go test ./pkg/licenseserver/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/
git commit -m "licenseserver: /validate returns schedule + scheduleJitterSeconds when set

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Client ValidateResponse — add two fields

**Files:**
- Modify: `internal/license/client.go`
- Test: add a test in `internal/license/client_test.go` (or the nearest existing test file)

- [ ] **Step 1: Write the failing deserialization test**

Run to find the existing test file:

```bash
ls internal/license/*_test.go
```

Append to the file that already contains `ValidateResponse` tests (likely `client_test.go`) — or create `client_test.go` if none exists:

```go
func TestValidateResponse_ScheduleFields(t *testing.T) {
	body := `{"valid":true,"tier":"pro","schedule":"0 2 * * *","scheduleJitterSeconds":30}`
	var vr ValidateResponse
	if err := json.Unmarshal([]byte(body), &vr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if vr.Schedule != "0 2 * * *" {
		t.Errorf("Schedule = %q", vr.Schedule)
	}
	if vr.ScheduleJitterSeconds != 30 {
		t.Errorf("ScheduleJitterSeconds = %d", vr.ScheduleJitterSeconds)
	}
}

func TestValidateResponse_ScheduleOmitted(t *testing.T) {
	body := `{"valid":true,"tier":"pro"}`
	var vr ValidateResponse
	if err := json.Unmarshal([]byte(body), &vr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if vr.Schedule != "" {
		t.Errorf("Schedule should be empty, got %q", vr.Schedule)
	}
	if vr.ScheduleJitterSeconds != 0 {
		t.Errorf("ScheduleJitterSeconds should be 0, got %d", vr.ScheduleJitterSeconds)
	}
}
```

Import `"encoding/json"` and `"testing"` if not already.

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/license/ -run TestValidateResponse_Schedule -v
```

Expected: FAIL — `vr.Schedule` undefined.

- [ ] **Step 3: Add the fields**

In `internal/license/client.go`, inside the `ValidateResponse` struct, after the `CacheTTL` field:

```go
	// Schedule is the server-pushed cron expression override. Empty
	// means "no override — agent uses its local agent.yaml
	// schedule/interval." See
	// docs/plans/2026-04-19-portal-pushed-schedule-design.md.
	Schedule string `json:"schedule,omitempty"`

	// ScheduleJitterSeconds is the jitter bound in seconds. 0 disables.
	// Only meaningful when Schedule is non-empty.
	ScheduleJitterSeconds int `json:"scheduleJitterSeconds,omitempty"`
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/license/ -run TestValidateResponse_Schedule -v
```

Expected: both PASS.

- [ ] **Step 5: Run full license suite**

Run:
```bash
go test ./internal/license/... 2>&1 | tail -5
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/license/
git commit -m "license: ValidateResponse carries schedule + scheduleJitterSeconds

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Agent heartbeat signature + override lifecycle

**Files:**
- Modify: `cmd/agent.go`
- Test: `cmd/agent_schedule_test.go` (append)

- [ ] **Step 1: Write failing test for heartbeat returning an override**

Append to `cmd/agent_schedule_test.go`:

```go
// fakeServerClient lets us drive heartbeat behavior in tests without
// real HTTP. Implements just enough of *license.ServerClient's
// surface that heartbeat uses. If heartbeat calls methods beyond
// Validate, extend this fake rather than reaching for a real client.
type fakeServerClient struct {
	resp *license.ValidateResponse
	err  error
}

func (f *fakeServerClient) Validate(_, _ string) (*license.ValidateResponse, error) {
	return f.resp, f.err
}
func (f *fakeServerClient) Deactivate(string) error { return nil }

func TestHeartbeat_ReturnsServerOverride(t *testing.T) {
	seat := &seatState{
		activated: true,
		client:    &fakeServerClient{resp: &license.ValidateResponse{
			Valid:                 true,
			Tier:                  "pro",
			Schedule:              "0 2 * * *",
			ScheduleJitterSeconds: 30,
		}},
		licenseID: "lic-1",
		token:     "tok",
	}
	g := license.NewGuard("")
	_, override, err := heartbeat(seat, g)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if override == nil {
		t.Fatal("expected non-nil override")
	}
	if override.Kind != agentconfig.ScheduleKindCron {
		t.Errorf("Kind = %q", override.Kind)
	}
	if override.CronExpr != "0 2 * * *" {
		t.Errorf("CronExpr = %q", override.CronExpr)
	}
	if override.Jitter != 30*time.Second {
		t.Errorf("Jitter = %v", override.Jitter)
	}
}

func TestHeartbeat_EmptyScheduleReturnsNilOverride(t *testing.T) {
	seat := &seatState{
		activated: true,
		client: &fakeServerClient{resp: &license.ValidateResponse{
			Valid: true, Tier: "pro",
		}},
		licenseID: "lic-1", token: "tok",
	}
	g := license.NewGuard("")
	_, override, err := heartbeat(seat, g)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if override != nil {
		t.Errorf("expected nil override, got %+v", override)
	}
}
```

NOTE: The existing `seatState.client` field is `*license.ServerClient` (a concrete type). To make `fakeServerClient` fit, Task 7 must also refactor `seatState.client` to an interface. Do this in Step 3 below.

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./cmd/ -run "TestHeartbeat_" -v
```

Expected: FAIL — the heartbeat signature is `(seat *seatState, currentGuard *license.Guard) *license.Guard` (single return), plus `seatState.client` is a concrete type and the fake won't assign.

- [ ] **Step 3: Introduce an interface for the server client + refactor `seatState`**

In `cmd/agent.go`, above the `seatState` declaration, add:

```go
// heartbeatClient is the minimal surface heartbeat() uses. Declared
// as an interface so tests can inject a fake without spinning up a
// real license server.
type heartbeatClient interface {
	Validate(licenseID, token string) (*license.ValidateResponse, error)
	Deactivate(licenseID string) error
}
```

Change `seatState.client` from `*license.ServerClient` to `heartbeatClient`:

```go
type seatState struct {
	activated bool
	client    heartbeatClient
	licenseID string
	token     string
}
```

`*license.ServerClient` already satisfies this interface (it has both methods), so callers don't need to change type-wise — but verify with `go build ./cmd/` after the change.

- [ ] **Step 4: Change heartbeat signature + lifecycle logic**

Replace the existing `heartbeat` function body:

```go
func heartbeat(seat *seatState, currentGuard *license.Guard) (*license.Guard, *agentconfig.ScheduleSpec, error) {
	if !seat.activated || seat.client == nil {
		return currentGuard, nil, nil
	}

	resp, err := seat.client.Validate(seat.licenseID, seat.token)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: license server heartbeat failed: %v — continuing with current tier\n", err)
		return currentGuard, nil, nil
	}

	if !resp.Valid {
		fmt.Fprintf(os.Stderr,
			"warning: license server reports license invalid — degrading to free tier\n")
		seat.activated = false
		return license.NewGuard(""), nil, nil
	}

	if resp.Tier != "" && license.Tier(resp.Tier) != currentGuard.Tier() {
		fmt.Printf("  notice: license tier changed on server (%s → %s) — restart agent to apply\n",
			currentGuard.Tier(), resp.Tier)
	}

	// Portal-pushed schedule override. Empty schedule means "no
	// override — caller should revert to baseSched." Non-empty
	// produces a ScheduleSpec for newSchedulerFromSpec. Parse error
	// here means the caller should log and keep its previous sched.
	if resp.Schedule == "" {
		return currentGuard, nil, nil
	}
	spec := agentconfig.ScheduleSpec{
		Kind:     agentconfig.ScheduleKindCron,
		CronExpr: resp.Schedule,
		Jitter:   time.Duration(resp.ScheduleJitterSeconds) * time.Second,
	}
	return currentGuard, &spec, nil
}
```

The `err` return is reserved for a future validation path where the server-pushed value is structurally malformed before the agent tries to build a scheduler. For now it stays `nil` from heartbeat; `newSchedulerFromSpec` surfaces parse errors in the caller.

- [ ] **Step 5: Update the `runAgent` loop to consume the new return**

In `cmd/agent.go`, find the existing loop call:

```go
activeGuard = heartbeat(&seat, activeGuard)
```

Replace with:

```go
var override *agentconfig.ScheduleSpec
var hbErr error
activeGuard, override, hbErr = heartbeat(&seat, activeGuard)
switch {
case hbErr != nil:
	fmt.Fprintf(os.Stderr, "warning: server-pushed schedule invalid (%v) — keeping previous schedule\n", hbErr)
case override != nil:
	newSched, nerr := newSchedulerFromSpec(*override)
	if nerr != nil {
		fmt.Fprintf(os.Stderr, "warning: server-pushed schedule build failed (%v) — keeping previous\n", nerr)
	} else {
		sched = newSched
		fmt.Printf("  schedule updated from server: %s\n", sched.Describe())
	}
default:
	// Server pushed no schedule. If we had previously adopted an
	// override, revert to the yaml-derived baseline so an admin
	// clearing the field restores the operator's local setting.
	if sched != baseSched {
		sched = baseSched
		fmt.Printf("  schedule reverted to local default: %s\n", sched.Describe())
	}
}
```

And immediately after the existing scheduler-construction block (near the top of runAgent where `sched, err := newSchedulerFromSpec(spec)` is assigned), add one line to stash the baseline:

```go
baseSched := sched
```

Put it directly after the `if sched != nil { ... } else { ... }` block that prints the schedule banner. `baseSched` and `sched` must both be of type `scheduler` for `sched != baseSched` to compile — since both are the same interface type, that's automatic.

NOTE: Comparing two `scheduler` interface values with `!=` is legal in Go iff the underlying types are comparable. `intervalScheduler` is a value type with comparable fields, and `cronScheduler` has a `cron.Schedule` interface field which may or may not be comparable. If the comparison panics at runtime on cronScheduler, fall back to a boolean flag:

```go
// Alternative if interface equality panics: add to runAgent scope
// after baseSched assignment:
onOverride := false

// In the switch:
case override != nil: ... onOverride = true
default:
	if onOverride {
		sched = baseSched
		onOverride = false
		fmt.Printf("  schedule reverted to local default: %s\n", sched.Describe())
	}
```

Test both and use whichever runs cleanly on first try. The boolean flag is safer.

- [ ] **Step 6: Run tests to verify they pass**

Run:
```bash
go test ./cmd/ -run "TestHeartbeat_" -v
```

Expected: both new tests PASS.

- [ ] **Step 7: Run full cmd suite**

Run:
```bash
go test ./cmd/... 2>&1 | tail -5
```

Expected: all PASS. If any existing heartbeat test fails because the call site now expects three return values, update that test inline.

- [ ] **Step 8: Commit**

```bash
git add cmd/
git commit -m "agent: heartbeat returns ScheduleSpec override; runAgent applies it

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Admin UI — schedule fields on license detail + create

**Files:**
- Modify: `pkg/licenseserver/ui/dist/index.html`
- Modify: `pkg/licenseserver/ui/dist/app.js`
- Modify: `pkg/licenseserver/ui/dist/style.css` (if spacing needs tuning)

- [ ] **Step 1: Locate the existing license detail form**

Run:
```bash
grep -n "license-detail\|licenseDetail\|#license" pkg/licenseserver/ui/dist/*.html pkg/licenseserver/ui/dist/app.js | head -15
```

Understand where license fields are currently rendered (seats, tier, expiry, notes). The schedule fields go in the same surface.

- [ ] **Step 2: Add Scheduling section to the license detail template**

In `pkg/licenseserver/ui/dist/index.html`, inside the license detail template/container, append a new section near the bottom of the fields block (above Save/Revoke buttons):

```html
<section class="form-section">
  <h3>Scheduling (optional)</h3>
  <label>
    Cron schedule
    <input type="text" id="lic-schedule" placeholder="0 2 * * 0"
           pattern="[0-9*/,\- ]{3,}" />
    <small>5-field cron expression, e.g. <code>0 2 * * 0</code> for Sundays at 02:00 local.
           Leave empty to let the agent's local agent.yaml schedule win.</small>
  </label>
  <label>
    Jitter (seconds)
    <input type="number" id="lic-schedule-jitter" min="0" step="1" value="0" />
    <small>0 disables. Typical 30–300 for fleet staggering.</small>
  </label>
  <button type="button" id="lic-schedule-clear">Clear schedule</button>
</section>
```

(If the detail page is fully JS-rendered rather than templated HTML, port this into the `app.js` render function instead — the fields and IDs remain the same.)

- [ ] **Step 3: Wire the form to GET/PATCH**

In `pkg/licenseserver/ui/dist/app.js`, find the license detail rendering function. Add schedule-loading after the existing field hydration:

```javascript
document.getElementById('lic-schedule').value = license.schedule || '';
document.getElementById('lic-schedule-jitter').value =
    license.scheduleJitterSeconds || 0;
```

Add a save handler (attach to the existing license save button, or a dedicated "Save schedule" button within the section):

```javascript
async function saveLicenseSchedule(licenseId) {
  const schedule = document.getElementById('lic-schedule').value.trim();
  const jitter = parseInt(document.getElementById('lic-schedule-jitter').value, 10) || 0;
  const resp = await fetch(`/api/v1/admin/licenses/${licenseId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'X-Triton-Admin-Key': adminKey,
    },
    body: JSON.stringify({ schedule, scheduleJitterSeconds: jitter }),
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    alert('Save failed: ' + (body.error || resp.statusText));
    return;
  }
  showNotice('Schedule saved');
}

document.getElementById('lic-schedule-clear').addEventListener('click', () => {
  document.getElementById('lic-schedule').value = '';
  document.getElementById('lic-schedule-jitter').value = 0;
});
```

Wire the save handler to whatever button the existing UI uses for "save license" — or add a dedicated button; either works as long as the flow is discoverable.

- [ ] **Step 4: Add fields to the license create form**

Locate the create-license modal/form in `app.js`/`index.html`. Add the same two inputs (without a "Clear" button — create starts with them empty) and include `schedule` + `scheduleJitterSeconds` in the POST body:

```javascript
const body = {
  // ...existing fields
  schedule: document.getElementById('new-lic-schedule').value.trim(),
  scheduleJitterSeconds: parseInt(document.getElementById('new-lic-schedule-jitter').value, 10) || 0,
};
```

- [ ] **Step 5: Smoke-test the UI manually**

Run the license server locally:

```bash
make container-run-licenseserver
```

Browse to `http://localhost:8081/ui/`, log in, open a license, paste a cron like `0 2 * * *`, save, reload — verify the value persists. Then clear and reload — verify it empties.

If the UI build requires a bundler, run `make ui-license-build` (or whatever the admin UI build target is; check `Makefile`).

Stop the stack when done:

```bash
make container-stop-licenseserver
```

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/ui/
git commit -m "licenseserver/ui: schedule fields on license detail + create forms

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Integration test — full lifecycle

**Files:**
- Create: `test/integration/license_schedule_push_test.go`

- [ ] **Step 1: Write the integration test**

Create `test/integration/license_schedule_push_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/license"
)

// TestPortalScheduleLifecycle covers:
//   1. Create a license via admin API.
//   2. Activate a machine.
//   3. Validate — no schedule returned.
//   4. Admin sets schedule on the license.
//   5. Validate — schedule returned.
//   6. Admin clears schedule.
//   7. Validate — schedule absent again.
func TestPortalScheduleLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	srv := startTestLicenseServer(t) // existing helper in this package
	defer srv.Shutdown(context.Background())

	adminURL := srv.URL + "/api/v1/admin"
	clientURL := srv.URL

	// 1. Create license.
	orgID := adminCreateOrg(t, adminURL, "ScheduleCo")
	licID := adminCreateLicense(t, adminURL, orgID, map[string]any{
		"tier": "pro", "seats": 1, "expiresInDays": 30,
	})

	// 2. Activate.
	sc := license.NewServerClient(clientURL)
	act, err := sc.Activate(licID)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// 3. Validate — no schedule.
	val, err := sc.Validate(licID, act.Token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if val.Schedule != "" {
		t.Errorf("initial Schedule should be empty, got %q", val.Schedule)
	}

	// 4. Set schedule via admin PATCH.
	adminPatchLicense(t, adminURL, licID, map[string]any{
		"schedule":              "0 2 * * *",
		"scheduleJitterSeconds": 45,
	})

	// 5. Validate — schedule present.
	time.Sleep(100 * time.Millisecond) // let async audit settle; PG commit is sync so this is defensive
	val, err = sc.Validate(licID, act.Token)
	if err != nil {
		t.Fatalf("Validate 2: %v", err)
	}
	if val.Schedule != "0 2 * * *" {
		t.Errorf("Schedule = %q, want '0 2 * * *'", val.Schedule)
	}
	if val.ScheduleJitterSeconds != 45 {
		t.Errorf("ScheduleJitterSeconds = %d, want 45", val.ScheduleJitterSeconds)
	}

	// 6. Clear.
	adminPatchLicense(t, adminURL, licID, map[string]any{
		"schedule":              "",
		"scheduleJitterSeconds": 0,
	})

	// 7. Validate — schedule absent.
	val, err = sc.Validate(licID, act.Token)
	if err != nil {
		t.Fatalf("Validate 3: %v", err)
	}
	if val.Schedule != "" {
		t.Errorf("Schedule after clear = %q, want empty", val.Schedule)
	}
}
```

NOTE: `startTestLicenseServer`, `adminCreateOrg`, `adminCreateLicense`, `adminPatchLicense` are helpers that likely already exist in `test/integration/license_server_test.go` or `helpers_test.go`. Grep for them first:

```bash
grep -rn "func startTestLicenseServer\|func adminCreate" test/integration/ | head
```

If `adminPatchLicense` doesn't exist, add it near the other admin helpers in the same file. Signature:

```go
func adminPatchLicense(t *testing.T, adminURL, licID string, body map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, adminURL+"/licenses/"+licID, bytes.NewReader(buf))
	req.Header.Set("X-Triton-Admin-Key", testAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("patch license: status=%d err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
}
```

- [ ] **Step 2: Run the integration test**

Run:
```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5434/triton_test?sslmode=disable" \
	go test -tags integration -run TestPortalScheduleLifecycle ./test/integration/ -v
```

Expected: PASS. If the DB URL differs in your local `make db-up` setup, adjust.

- [ ] **Step 3: Commit**

```bash
git add test/integration/license_schedule_push_test.go
git commit -m "test: integration lifecycle for portal-pushed schedule

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: E2E browser test

**Files:**
- Modify: `test/e2e/license-admin.spec.js`
- Modify: `test/e2e/license-global-setup.js` (if a schedule-enabled license needs seeding)

- [ ] **Step 1: Append the Playwright test**

At the bottom of `test/e2e/license-admin.spec.js`:

```javascript
test('license detail: can set and clear schedule', async ({ page }) => {
  // Assumes the global setup seeded a license we can open.
  await page.goto('/ui/#licenses');
  await page.getByRole('link', { name: /edit|details/i }).first().click();

  await page.locator('#lic-schedule').fill('0 2 * * 0');
  await page.locator('#lic-schedule-jitter').fill('30');
  await page.getByRole('button', { name: /save/i }).click();

  await expect(page.locator('.notice')).toContainText(/saved/i);

  // Reload and verify.
  await page.reload();
  await expect(page.locator('#lic-schedule')).toHaveValue('0 2 * * 0');
  await expect(page.locator('#lic-schedule-jitter')).toHaveValue('30');

  // Clear.
  await page.locator('#lic-schedule-clear').click();
  await page.getByRole('button', { name: /save/i }).click();
  await page.reload();
  await expect(page.locator('#lic-schedule')).toHaveValue('');
});

test('license detail: invalid cron surfaces server error', async ({ page }) => {
  await page.goto('/ui/#licenses');
  await page.getByRole('link', { name: /edit|details/i }).first().click();

  await page.locator('#lic-schedule').fill('not a cron');

  page.on('dialog', async (dialog) => {
    expect(dialog.message()).toMatch(/invalid|schedule|cron/i);
    await dialog.dismiss();
  });

  await page.getByRole('button', { name: /save/i }).click();
});
```

- [ ] **Step 2: Run the E2E suite**

Run:
```bash
make test-e2e-license
```

Expected: both new tests PASS along with the existing 22.

- [ ] **Step 3: Commit**

```bash
git add test/e2e/
git commit -m "test/e2e: license admin UI schedule edit + invalid cron dialog

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Docs — DEPLOYMENT_GUIDE.md + CLAUDE.md

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add "Server-pushed schedule override" subsection**

In `docs/DEPLOYMENT_GUIDE.md`, find the existing `### 7c-bis. Scheduling (cron vs interval)` section (added by PR #79). After it, insert a new `### 7c-ter. Server-pushed schedule override` block:

```markdown
### 7c-ter. Server-pushed schedule override

When an agent is bound to a license server (`license_server:` +
`license_id:` in agent.yaml, or via `triton license activate`), the
license server can push a `schedule` and `schedule_jitter` override
on the existing `/validate` heartbeat. The agent applies it starting
from the next iteration.

**Precedence:** when the license server pushes a non-empty `schedule`,
it overrides `agent.yaml::schedule` and any `--interval` flag. When
the server pushes nothing (license has no schedule set), the agent
uses its local yaml-derived baseline — meaning operators who want
their local setting to win should configure a license with no schedule.

**How to set one:**

1. Log into the license server admin UI.
2. Open the target license.
3. Enter a cron expression (5-field, local timezone on the agent host)
   and optional jitter in seconds.
4. Save. Connected agents pick up the change on their next iteration.

**How to clear:** empty the `Schedule` field in the admin UI and save,
or `PATCH /api/v1/admin/licenses/{id}` with `{"schedule": "", "scheduleJitterSeconds": 0}`.

**Validation:** invalid cron expressions are rejected by the admin API
at write time. A malformed value that somehow reaches the agent is
logged and the agent keeps its previous schedule — the fleet is never
silenced by a bad push.

**No "schedule lock" in agent.yaml.** If a specific agent must resist
server pushes, use the offline-token flow (`triton license` without
`--license-server`). The server cannot push to agents it doesn't talk to.

**One-iteration lag:** the first scan after agent startup uses the
yaml-derived schedule. The server-pushed value first applies when the
heartbeat runs between iteration 1 and iteration 2. For 24h cadences
this is invisible; for sub-minute testing cron, plan around it.
```

- [ ] **Step 2: Update CLAUDE.md**

In `CLAUDE.md`, find the `### Agent scheduling` subsection (added by PR #79). Append one sentence to the end of its paragraph:

```markdown
When the agent is bound to a license server, the server can push a `schedule` override via `/validate`; agent adopts it on the next iteration and reverts to the yaml baseline when the server clears the field. See `pkg/licenseserver/handlers_activation.go::handleValidate` and `cmd/agent.go::heartbeat`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/DEPLOYMENT_GUIDE.md CLAUDE.md
git commit -m "docs: portal-pushed schedule override (deployment guide + CLAUDE.md)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Memory update

**Files:**
- Modify: `/Users/amirrudinyahaya/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/agent-control-features.md`

- [ ] **Step 1: Flip item 5 to fully shipped**

Find the current entry for step 5 (which step 5a marked as "partial") and replace its prose to indicate both 5a (local cron, PR #79) and 5b (portal-pushed, pending PR) are shipped. Keep a pointer to the design spec for future readers.

- [ ] **Step 2: Update the "last updated" header date to today's date**

No commit — this is a memory file outside the repo.

---

## Self-Review

**Spec coverage check:**

| Spec section | Implemented by |
|--------------|----------------|
| Migration — two nullable columns | Task 1 |
| LicenseRecord fields | Task 2 |
| Store CRUD round-trip + UpdateLicense | Task 3 |
| Admin API: POST validation + PATCH + audit | Task 4 |
| Gateway populates ValidateResponse | Task 5 |
| Client ValidateResponse fields | Task 6 |
| Agent heartbeat override lifecycle (baseSched / sched) | Task 7 |
| Admin UI: detail + create forms | Task 8 |
| Integration test (full lifecycle) | Task 9 |
| E2E browser tests | Task 10 |
| Docs (deployment guide + CLAUDE.md) | Task 11 |
| Backward compat (old agent, old server) | Covered by omitempty + interface extension — implicit in Tasks 5/6 |
| Cron validation on write | Task 4 Steps 3, 7 |
| No schedule_lock in yaml | Task 11 doc note |

**Placeholder scan:** no TODO / TBD / "implement later" in the task code. Three intentional "check if helper exists first, adapt if not" notes in Tasks 4 + 5 + 9 — those are flexibility hints, not placeholders, because the helper names in this codebase are stable enough to name but subject to minor signature drift.

**Type consistency:**
- `ScheduleSpec{Kind, CronExpr, Interval, Jitter}` — from PR #79, reused by Task 7 unchanged.
- `LicenseRecord.Schedule string` / `LicenseRecord.ScheduleJitter int` — Task 2; used identically in Tasks 3, 4, 5.
- `LicenseUpdate{Schedule *string, ScheduleJitter *int}` — Task 3; consumed in Task 4 Step 7.
- `ValidateResponse.Schedule string` / `ValidateResponse.ScheduleJitterSeconds int` — Task 6; consumed in Task 7.
- `heartbeatClient` interface — Task 7, satisfied by existing `*license.ServerClient`.
- `heartbeat(...) (*license.Guard, *agentconfig.ScheduleSpec, error)` — Task 7; consumed by runAgent loop in the same task.

No drift detected.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-19-portal-pushed-schedule-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch checkpoints.

Which approach?
