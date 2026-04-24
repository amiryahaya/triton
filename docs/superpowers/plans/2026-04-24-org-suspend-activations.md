# Org Suspend Action + Activations Column Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a hard-suspend action to organisations (blocks new activations and validation of existing machines) and an active-activations column on the org list that shows a count only for orgs with seated licences.

**Architecture:** Migration 8 adds a `suspended` column to `organizations`; the `SuspendOrg` store method flips it; `handleActivate` and `handleValidate` both check it and return 403 if set. `ListOrgs` is enriched with two subquery-computed fields (`has_seated_licenses`, `active_activations`) so the frontend gets everything in one call. Frontend adds a Suspend/Unsuspend button and an Activations column to `Organisations.vue` and a status pill + button to `OrganisationDetail.vue`.

**Tech Stack:** Go 1.25, pgx/v5, Chi router, Vue 3 + TypeScript, Vitest

---

## File Map

| File | Change |
|---|---|
| `pkg/licensestore/migrations.go` | Append version 8 (ADD COLUMN suspended) |
| `pkg/licensestore/store.go` | Add `Suspended`, `ActiveActivations`, `HasSeatedLicenses` to `Organization`; add `SuspendOrg` to `Store` interface |
| `pkg/licensestore/postgres.go` | Implement `SuspendOrg`; update `GetOrg` and `ListOrgs` scan targets |
| `pkg/licensestore/postgres_test.go` | Add `TestSuspendOrg`, `TestListOrgs_ComputedFields` |
| `pkg/licenseserver/handlers_org.go` | Add `handleSuspendOrg` |
| `pkg/licenseserver/server.go` | Register `POST /api/v1/admin/orgs/{id}/suspend` |
| `pkg/licenseserver/handlers_activation.go` | Add org suspension checks in `handleActivate` and `handleValidate` |
| `pkg/licenseserver/handlers_org_test.go` | Create: `TestHandleSuspendOrg_*` |
| `pkg/licenseserver/handlers_activation_test.go` | Create: `TestHandleActivate_OrgSuspended`, `TestHandleValidate_OrgSuspended` |
| `web/packages/api-client/src/types.ts` | Add `suspended`, `activeActivations`, `hasSeatedLicenses` to `Organisation` |
| `web/packages/api-client/src/licenseServer.ts` | Add `suspendOrg` method |
| `web/apps/license-portal/src/views/Organisations.vue` | Add Activations column, Suspend button, Suspended pill |
| `web/apps/license-portal/src/views/OrganisationDetail.vue` | Add Status field, Suspend button |
| `web/apps/license-portal/tests/views/Organisations.spec.ts` | Update fixtures; add 5 new test cases |
| `web/apps/license-portal/tests/views/OrganisationDetail.spec.ts` | Create: status pill + suspend button tests |

---

## Task 1: Migration 8 — add `suspended` column

**Files:**
- Modify: `pkg/licensestore/migrations.go` (append after the last entry in the `migrations` slice)

- [ ] **Step 1: Append migration version 8**

  Open `pkg/licensestore/migrations.go`. The `migrations` slice currently ends after the version 7 entry (around line 170). Append a comma after the closing backtick of version 7 and add:

  ```go
  // Version 8: Add suspended column to organizations.
  // suspended=true blocks new activations and validation for all machines
  // on any licence belonging to this org (hard suspend).
  `ALTER TABLE organizations ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT FALSE;`,
  ```

- [ ] **Step 2: Verify the file compiles**

  ```bash
  go build ./pkg/licensestore/...
  ```
  Expected: no output (clean build).

- [ ] **Step 3: Commit**

  ```bash
  git add pkg/licensestore/migrations.go
  git commit -m "feat(licensestore): migration 8 — add suspended column to organizations"
  ```

---

## Task 2: Update `Organization` struct and `Store` interface

**Files:**
- Modify: `pkg/licensestore/store.go` (lines 73–80 — the `Organization` struct, and ~line 15 — `Store` interface org section)

- [ ] **Step 1: Add fields to `Organization` struct**

  Replace the existing `Organization` struct (currently `ID`, `Name`, `Contact`, `Notes`, `CreatedAt`, `UpdatedAt`) with:

  ```go
  // Organization represents a customer organization.
  type Organization struct {
  	ID        string    `json:"id"`
  	Name      string    `json:"name"`
  	Contact   string    `json:"contact"`
  	Notes     string    `json:"notes"`
  	Suspended bool      `json:"suspended"`
  	// ActiveActivations and HasSeatedLicenses are read-only computed fields
  	// populated by ListOrgs — never written to the database directly.
  	ActiveActivations int  `json:"activeActivations"`
  	HasSeatedLicenses bool `json:"hasSeatedLicenses"`
  	CreatedAt time.Time `json:"createdAt"`
  	UpdatedAt time.Time `json:"updatedAt"`
  }
  ```

- [ ] **Step 2: Add `SuspendOrg` to the `Store` interface**

  In the `Store` interface, the Organizations section currently reads:
  ```go
  CreateOrg(ctx context.Context, org *Organization) error
  GetOrg(ctx context.Context, id string) (*Organization, error)
  ListOrgs(ctx context.Context) ([]Organization, error)
  UpdateOrg(ctx context.Context, org *Organization) error
  DeleteOrg(ctx context.Context, id string) error
  ```

  Add `SuspendOrg` after `DeleteOrg`:
  ```go
  SuspendOrg(ctx context.Context, id string, suspended bool) error
  ```

- [ ] **Step 3: Verify compilation**

  ```bash
  go build ./pkg/licensestore/...
  ```
  Expected: compile error — `PostgresStore` does not implement `Store` (missing `SuspendOrg`). This is the expected red state before Task 3.

---

## Task 3: Implement `SuspendOrg` and update `GetOrg` / `ListOrgs` in postgres.go

**Files:**
- Modify: `pkg/licensestore/postgres.go`

- [ ] **Step 1: Add `SuspendOrg` method**

  Add immediately after the `DeleteOrg` function (around line 236):

  ```go
  func (s *PostgresStore) SuspendOrg(ctx context.Context, id string, suspended bool) error {
  	tag, err := s.pool.Exec(ctx,
  		`UPDATE organizations SET suspended = $2, updated_at = NOW() WHERE id = $1`,
  		id, suspended,
  	)
  	if err != nil {
  		return fmt.Errorf("suspending organization: %w", err)
  	}
  	if tag.RowsAffected() == 0 {
  		return &ErrNotFound{Resource: "organization", ID: id}
  	}
  	return nil
  }
  ```

- [ ] **Step 2: Update `GetOrg` to scan the `suspended` column**

  Replace the `GetOrg` function body (currently around lines 167–180) with:

  ```go
  func (s *PostgresStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
  	var org Organization
  	err := s.pool.QueryRow(ctx,
  		`SELECT id, name, contact, notes, suspended, created_at, updated_at
  		 FROM organizations WHERE id = $1`, id,
  	).Scan(&org.ID, &org.Name, &org.Contact, &org.Notes, &org.Suspended,
  		&org.CreatedAt, &org.UpdatedAt)
  	if errors.Is(err, pgx.ErrNoRows) {
  		return nil, &ErrNotFound{Resource: "organization", ID: id}
  	}
  	if err != nil {
  		return nil, fmt.Errorf("getting organization: %w", err)
  	}
  	return &org, nil
  }
  ```

- [ ] **Step 3: Update `ListOrgs` to scan `suspended` and the two computed fields**

  Replace the `ListOrgs` function body (currently around lines 182–200) with:

  ```go
  func (s *PostgresStore) ListOrgs(ctx context.Context) ([]Organization, error) {
  	rows, err := s.pool.Query(ctx, `
  		SELECT
  			o.id, o.name, o.contact, o.notes, o.suspended,
  			o.created_at, o.updated_at,
  			EXISTS (
  				SELECT 1 FROM licenses l WHERE l.org_id = o.id AND l.seats > 0
  			) AS has_seated_licenses,
  			COALESCE((
  				SELECT COUNT(*)
  				FROM activations a
  				JOIN licenses l ON a.license_id = l.id
  				WHERE l.org_id = o.id AND a.active = TRUE AND l.seats > 0
  			), 0) AS active_activations
  		FROM organizations o
  		ORDER BY o.name
  		LIMIT 1000`)
  	if err != nil {
  		return nil, fmt.Errorf("listing organizations: %w", err)
  	}
  	defer rows.Close()

  	orgs := make([]Organization, 0)
  	for rows.Next() {
  		var org Organization
  		if err := rows.Scan(
  			&org.ID, &org.Name, &org.Contact, &org.Notes, &org.Suspended,
  			&org.CreatedAt, &org.UpdatedAt,
  			&org.HasSeatedLicenses, &org.ActiveActivations,
  		); err != nil {
  			return nil, fmt.Errorf("scanning organization: %w", err)
  		}
  		orgs = append(orgs, org)
  	}
  	return orgs, rows.Err()
  }
  ```

- [ ] **Step 4: Verify the package compiles cleanly**

  ```bash
  go build ./pkg/licensestore/... ./pkg/licenseserver/...
  ```
  Expected: no errors.

- [ ] **Step 5: Commit**

  ```bash
  git add pkg/licensestore/store.go pkg/licensestore/postgres.go
  git commit -m "feat(licensestore): SuspendOrg method + enriched ListOrgs with activation counts"
  ```

---

## Task 4: Store-layer tests for SuspendOrg and computed fields

**Files:**
- Modify: `pkg/licensestore/postgres_test.go` (append after `TestDeleteOrg_WithLicenses` around line 199)

These are integration tests — they require PostgreSQL. They are tagged `//go:build integration` (the file already carries that tag at line 1).

- [ ] **Step 1: Write failing tests**

  Append the two test functions to `pkg/licensestore/postgres_test.go`:

  ```go
  func TestSuspendOrg(t *testing.T) {
  	s := openTestStore(t)
  	ctx := context.Background()

  	org := makeOrg(t)
  	require.NoError(t, s.CreateOrg(ctx, org))

  	// Suspend
  	require.NoError(t, s.SuspendOrg(ctx, org.ID, true))
  	got, err := s.GetOrg(ctx, org.ID)
  	require.NoError(t, err)
  	assert.True(t, got.Suspended)

  	// Unsuspend
  	require.NoError(t, s.SuspendOrg(ctx, org.ID, false))
  	got, err = s.GetOrg(ctx, org.ID)
  	require.NoError(t, err)
  	assert.False(t, got.Suspended)

  	// Not found
  	err = s.SuspendOrg(ctx, nonExistentUUID, true)
  	var nf *licensestore.ErrNotFound
  	assert.ErrorAs(t, err, &nf)
  }

  func TestListOrgs_ComputedFields(t *testing.T) {
  	s := openTestStore(t)
  	ctx := context.Background()

  	org := makeOrg(t)
  	require.NoError(t, s.CreateOrg(ctx, org))

  	// Before any licence: has_seated_licenses=false, active_activations=0.
  	orgs, err := s.ListOrgs(ctx)
  	require.NoError(t, err)
  	require.Len(t, orgs, 1)
  	assert.False(t, orgs[0].HasSeatedLicenses)
  	assert.Equal(t, 0, orgs[0].ActiveActivations)

  	// Add a seated licence and one active activation.
  	lic := makeLicense(t, org.ID) // seats=5
  	require.NoError(t, s.CreateLicense(ctx, lic))
  	act := makeActivation(t, lic.ID)
  	require.NoError(t, s.Activate(ctx, act))

  	orgs, err = s.ListOrgs(ctx)
  	require.NoError(t, err)
  	require.Len(t, orgs, 1)
  	assert.True(t, orgs[0].HasSeatedLicenses)
  	assert.Equal(t, 1, orgs[0].ActiveActivations)

  	// Deactivate — count drops to zero.
  	require.NoError(t, s.Deactivate(ctx, lic.ID, act.MachineID))
  	orgs, err = s.ListOrgs(ctx)
  	require.NoError(t, err)
  	assert.Equal(t, 0, orgs[0].ActiveActivations)

  	// Unlimited licence (seats=0) does not count toward has_seated_licenses.
  	unlimitedLic := makeLicense(t, org.ID)
  	unlimitedLic.ID = uuid.Must(uuid.NewV7()).String()
  	unlimitedLic.Seats = 0
  	require.NoError(t, s.CreateLicense(ctx, unlimitedLic))
  	orgs, err = s.ListOrgs(ctx)
  	require.NoError(t, err)
  	// Still has the seated lic from above, so has_seated_licenses stays true.
  	assert.True(t, orgs[0].HasSeatedLicenses)
  }
  ```

  Note: `makeActivation` sets `Active: true` but the `Activate` method manages that. The token field in `makeActivation` is a stub; `store.Activate` stores the token as-is.

- [ ] **Step 2: Run failing tests**

  ```bash
  go test -v -tags integration -run "TestSuspendOrg|TestListOrgs_ComputedFields" ./pkg/licensestore/...
  ```
  Expected: **PASS** (the implementation is already in place from Task 3).

- [ ] **Step 3: Commit**

  ```bash
  git add pkg/licensestore/postgres_test.go
  git commit -m "test(licensestore): TestSuspendOrg and TestListOrgs_ComputedFields"
  ```

---

## Task 5: `handleSuspendOrg` handler and route

**Files:**
- Modify: `pkg/licenseserver/handlers_org.go` (append at the end)
- Modify: `pkg/licenseserver/server.go` (line ~129, after `r.Delete("/orgs/{id}", ...)`)

- [ ] **Step 1: Add `handleSuspendOrg` to handlers_org.go**

  Append at the end of `pkg/licenseserver/handlers_org.go`:

  ```go
  // POST /api/v1/admin/orgs/{id}/suspend
  //
  // Toggles the suspended flag on an organisation. Suspended organisations
  // are immediately rejected on both activate and validate requests.
  // Body: {"suspended": true|false}
  func (s *Server) handleSuspendOrg(w http.ResponseWriter, r *http.Request) {
  	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
  	id := chi.URLParam(r, "id")

  	var req struct {
  		Suspended bool `json:"suspended"`
  	}
  	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
  		writeError(w, http.StatusBadRequest, "invalid request body")
  		return
  	}

  	if err := s.store.SuspendOrg(r.Context(), id, req.Suspended); err != nil {
  		if isNotFound(err) {
  			writeError(w, http.StatusNotFound, "organisation not found")
  			return
  		}
  		log.Printf("suspend org error: %v", err)
  		writeError(w, http.StatusInternalServerError, "internal server error")
  		return
  	}

  	event := "org_unsuspended"
  	if req.Suspended {
  		event = "org_suspended"
  	}
  	s.audit(r, event, "", id, "", nil)

  	w.WriteHeader(http.StatusNoContent)
  }
  ```

- [ ] **Step 2: Register the route in server.go**

  In `pkg/licenseserver/server.go`, find the Organizations block (around lines 124–129):
  ```go
  // Organizations
  r.Post("/orgs", srv.handleCreateOrg)
  r.Get("/orgs", srv.handleListOrgs)
  r.Get("/orgs/{id}", srv.handleGetOrg)
  r.Put("/orgs/{id}", srv.handleUpdateOrg)
  r.Delete("/orgs/{id}", srv.handleDeleteOrg)
  ```

  Add one line after `r.Delete(...)`:
  ```go
  r.Post("/orgs/{id}/suspend", srv.handleSuspendOrg)
  ```

- [ ] **Step 3: Build**

  ```bash
  go build ./pkg/licenseserver/...
  ```
  Expected: clean.

- [ ] **Step 4: Commit**

  ```bash
  git add pkg/licenseserver/handlers_org.go pkg/licenseserver/server.go
  git commit -m "feat(licenseserver): POST /api/v1/admin/orgs/{id}/suspend handler"
  ```

---

## Task 6: Suspend enforcement in `handleActivate` and `handleValidate`

**Files:**
- Modify: `pkg/licenseserver/handlers_activation.go`

### handleActivate

- [ ] **Step 1: Add org suspension check after the license lookup**

  In `handleActivate`, find the block that ends with the license lookup error handling (around line 51):
  ```go
  lic, err := s.store.GetLicense(r.Context(), req.LicenseID)
  if err != nil {
      if isNotFound(err) {
          writeError(w, http.StatusNotFound, "license not found")
          return
      }
      log.Printf("activate get license error: %v", err)
      writeError(w, http.StatusInternalServerError, "internal server error")
      return
  }

  // Pre-sign a token for this machine.
  ```

  Insert this block between the license lookup and the comment `// Pre-sign a token for this machine.`:

  ```go
  // Reject activations for suspended organisations.
  if lic.OrgID != "" {
      org, orgErr := s.store.GetOrg(r.Context(), lic.OrgID)
      if orgErr != nil {
          log.Printf("activate: org lookup failed for %s: %v", lic.OrgID, orgErr)
          writeError(w, http.StatusInternalServerError, "internal server error")
          return
      }
      if org.Suspended {
          writeError(w, http.StatusForbidden, "organisation suspended")
          return
      }
  }
  ```

### handleValidate

- [ ] **Step 2: Add org suspension check after the expiry check**

  In `handleValidate`, find the expiry check block (around line 200–203):
  ```go
  if time.Now().After(lic.ExpiresAt) {
      writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
      return
  }

  // Check activation
  ```

  Insert this block between the expiry check and the `// Check activation` comment:

  ```go
  // Hard-block validation for suspended organisations.
  if lic.OrgID != "" {
      if org, err := s.store.GetOrg(r.Context(), lic.OrgID); err == nil && org.Suspended {
          writeError(w, http.StatusForbidden, "organisation suspended")
          return
      }
  }
  ```

  Note: the non-fatal `err == nil &&` pattern is consistent with the existing org-name lookup below — if GetOrg fails, validation is allowed through (conservative: don't block on a temporary DB error).

- [ ] **Step 3: Build and verify**

  ```bash
  go build ./pkg/licenseserver/...
  ```
  Expected: clean.

- [ ] **Step 4: Commit**

  ```bash
  git add pkg/licenseserver/handlers_activation.go
  git commit -m "feat(licenseserver): block activate and validate for suspended organisations"
  ```

---

## Task 7: Handler tests — suspend endpoint + enforcement

**Files:**
- Create: `pkg/licenseserver/handlers_org_test.go`
- Create: `pkg/licenseserver/handlers_activation_suspension_test.go`

### Org handler tests

- [ ] **Step 1: Create handlers_org_test.go**

  ```go
  //go:build integration

  package licenseserver_test

  import (
  	"bytes"
  	"encoding/json"
  	"net/http"
  	"testing"

  	"github.com/stretchr/testify/assert"
  	"github.com/stretchr/testify/require"
  )

  func TestHandleSuspendOrg_Success(t *testing.T) {
  	ts, _ := setupTestServer(t)
  	const adminKey = "test-admin-key"

  	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SuspendCo")

  	// Suspend
  	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
  		"/api/v1/admin/orgs/"+orgID+"/suspend",
  		map[string]any{"suspended": true})
  	assert.Equal(t, http.StatusNoContent, resp.status)

  	// Verify org is suspended by listing orgs
  	listResp := adminDo(t, ts.URL, adminKey, http.MethodGet, "/api/v1/admin/orgs", nil)
  	require.Equal(t, http.StatusOK, listResp.status)
  	var orgs []map[string]any
  	require.NoError(t, json.Unmarshal(listResp.body, &orgs))
  	var found map[string]any
  	for _, o := range orgs {
  		if o["id"] == orgID {
  			found = o
  		}
  	}
  	require.NotNil(t, found)
  	assert.Equal(t, true, found["suspended"])

  	// Unsuspend
  	resp2 := adminDo(t, ts.URL, adminKey, http.MethodPost,
  		"/api/v1/admin/orgs/"+orgID+"/suspend",
  		map[string]any{"suspended": false})
  	assert.Equal(t, http.StatusNoContent, resp2.status)
  }

  func TestHandleSuspendOrg_NotFound(t *testing.T) {
  	ts, _ := setupTestServer(t)
  	const adminKey = "test-admin-key"

  	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
  		"/api/v1/admin/orgs/00000000-0000-0000-0000-000000000000/suspend",
  		map[string]any{"suspended": true})
  	assert.Equal(t, http.StatusNotFound, resp.status)
  }

  func TestHandleSuspendOrg_BadBody(t *testing.T) {
  	ts, _ := setupTestServer(t)
  	const adminKey = "test-admin-key"

  	orgID := createOrgViaAPI(t, ts.URL, adminKey, "BadBodyCo")

  	req, _ := http.NewRequest(http.MethodPost,
  		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
  		bytes.NewBufferString("not-json"))
  	req.Header.Set("X-Triton-Admin-Key", adminKey)
  	req.Header.Set("Content-Type", "application/json")
  	res, err := http.DefaultClient.Do(req)
  	require.NoError(t, err)
  	res.Body.Close()
  	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
  }

  func TestHandleSuspendOrg_RequiresAdminKey(t *testing.T) {
  	ts, _ := setupTestServer(t)

  	orgID := createOrgViaAPI(t, ts.URL, "test-admin-key", "AuthTestCo")

  	req, _ := http.NewRequest(http.MethodPost,
  		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
  		bytes.NewBufferString(`{"suspended":true}`))
  	req.Header.Set("Content-Type", "application/json")
  	// No admin key header
  	res, err := http.DefaultClient.Do(req)
  	require.NoError(t, err)
  	res.Body.Close()
  	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
  }
  ```

- [ ] **Step 2: Run org handler tests**

  ```bash
  go test -v -tags integration -run "TestHandleSuspendOrg" ./pkg/licenseserver/...
  ```
  Expected: all 4 PASS.

### Suspension enforcement tests

- [ ] **Step 3: Create handlers_activation_suspension_test.go**

  ```go
  //go:build integration

  package licenseserver_test

  import (
  	"bytes"
  	"encoding/json"
  	"net/http"
  	"testing"
  	"time"

  	"github.com/stretchr/testify/assert"
  	"github.com/stretchr/testify/require"

  	"github.com/amiryahaya/triton/pkg/licensestore"
  )

  // seedOrgAndLicense creates an org + active licence, returns orgID and licID.
  func seedOrgAndLicense(t *testing.T, tsURL, adminKey, orgName string) (orgID, licID string) {
  	t.Helper()
  	orgID = createOrgViaAPI(t, tsURL, adminKey, orgName)
  	licID = createLicenseViaAPIWithFields(t, tsURL, adminKey, orgID, map[string]any{
  		"tier":  "pro",
  		"seats": 5,
  		"days":  365,
  		"features": map[string]any{
  			"report": true, "manage": false, "comprehensive_profile": false,
  			"diff_trend": false, "custom_policy": false, "sso": false,
  		},
  		"limits":        []any{},
  		"product_scope": "report",
  	})
  	return
  }

  func TestHandleActivate_OrgSuspended(t *testing.T) {
  	ts, _ := setupTestServer(t)
  	const adminKey = "test-admin-key"

  	orgID, licID := seedOrgAndLicense(t, ts.URL, adminKey, "SuspendActivateCo")

  	// Suspend the org
  	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
  		"/api/v1/admin/orgs/"+orgID+"/suspend",
  		map[string]any{"suspended": true})
  	require.Equal(t, http.StatusNoContent, resp.status)

  	// Attempt to activate — must be rejected with 403
  	body, _ := json.Marshal(map[string]any{
  		"licenseID": licID,
  		"machineID": "machine-abc",
  		"hostname":  "host.example.com",
  		"os":        "linux",
  		"arch":      "amd64",
  	})
  	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/activate",
  		bytes.NewReader(body))
  	req.Header.Set("Content-Type", "application/json")
  	res, err := http.DefaultClient.Do(req)
  	require.NoError(t, err)
  	res.Body.Close()
  	assert.Equal(t, http.StatusForbidden, res.StatusCode)
  }

  func TestHandleValidate_OrgSuspended(t *testing.T) {
  	ts, store := setupTestServer(t)
  	const adminKey = "test-admin-key"

  	orgID, licID := seedOrgAndLicense(t, ts.URL, adminKey, "SuspendValidateCo")

  	// Activate a machine while the org is still active
  	activateBody, _ := json.Marshal(map[string]any{
  		"licenseID": licID,
  		"machineID": "machine-xyz",
  		"hostname":  "host.example.com",
  		"os":        "linux",
  		"arch":      "amd64",
  	})
  	activateReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/activate",
  		bytes.NewReader(activateBody))
  	activateReq.Header.Set("Content-Type", "application/json")
  	activateRes, err := http.DefaultClient.Do(activateReq)
  	require.NoError(t, err)
  	var activateResp map[string]any
  	require.NoError(t, json.NewDecoder(activateRes.Body).Decode(&activateResp))
  	activateRes.Body.Close()
  	require.Equal(t, http.StatusCreated, activateRes.StatusCode)
  	token := activateResp["token"].(string)

  	// Suspend the org via the store directly (faster than API round-trip)
  	require.NoError(t, store.SuspendOrg(t.Context(), orgID, true))

  	// Attempt to validate — must now be rejected with 403
  	validateBody, _ := json.Marshal(map[string]any{
  		"licenseID": licID,
  		"machineID": "machine-xyz",
  		"token":     token,
  	})
  	validateReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/validate",
  		bytes.NewReader(validateBody))
  	validateReq.Header.Set("Content-Type", "application/json")
  	validateRes, err := http.DefaultClient.Do(validateReq)
  	require.NoError(t, err)
  	validateRes.Body.Close()
  	assert.Equal(t, http.StatusForbidden, validateRes.StatusCode)

  	// Unsuspend — validate should succeed again
  	require.NoError(t, store.SuspendOrg(t.Context(), orgID, false))
  	validateReq2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/validate",
  		bytes.NewReader(validateBody))
  	validateReq2.Header.Set("Content-Type", "application/json")
  	validateRes2, err := http.DefaultClient.Do(validateReq2)
  	require.NoError(t, err)
  	var validateResp2 map[string]any
  	require.NoError(t, json.NewDecoder(validateRes2.Body).Decode(&validateResp2))
  	validateRes2.Body.Close()
  	assert.Equal(t, http.StatusOK, validateRes2.StatusCode)
  	assert.Equal(t, true, validateResp2["valid"])
  	_ = time.Time{} // suppress unused import
  	_ = licensestore.Organization{} // suppress unused import
  }
  ```

  Note: `t.Context()` is available in Go 1.21+. Remove the unused import lines if the compiler complains — they are just import guards.

- [ ] **Step 4: Run enforcement tests**

  ```bash
  go test -v -tags integration -run "TestHandleActivate_OrgSuspended|TestHandleValidate_OrgSuspended" ./pkg/licenseserver/...
  ```
  Expected: both PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add pkg/licenseserver/handlers_org_test.go pkg/licenseserver/handlers_activation_suspension_test.go
  git commit -m "test(licenseserver): org suspend handler and enforcement tests"
  ```

---

## Task 8: Frontend — update `Organisation` type and API client

**Files:**
- Modify: `web/packages/api-client/src/types.ts`
- Modify: `web/packages/api-client/src/licenseServer.ts`

- [ ] **Step 1: Update `Organisation` in types.ts**

  Replace the current `Organisation` interface:
  ```ts
  export interface Organisation {
    id: string;
    name: string;
    contact: string;
    notes: string;
    createdAt: string;
    updatedAt: string;
  }
  ```
  With:
  ```ts
  export interface Organisation {
    id: string;
    name: string;
    contact: string;
    notes: string;
    suspended: boolean;
    activeActivations: number;
    hasSeatedLicenses: boolean;
    createdAt: string;
    updatedAt: string;
  }
  ```

- [ ] **Step 2: Add `suspendOrg` to licenseServer.ts**

  In `pkg — web/packages/api-client/src/licenseServer.ts`, the returned object from `createLicenseApi` currently ends with `audit`. Add `suspendOrg` after `deleteOrg`:

  ```ts
  suspendOrg: (id: string, suspended: boolean) =>
    http.post<void>(`/v1/admin/orgs/${id}/suspend`, { suspended }),
  ```

  The full updated section should read:
  ```ts
  orgs: () => http.get<Organisation[]>('/v1/admin/orgs'),
  org: (id: string) => http.get<Organisation>(`/v1/admin/orgs/${id}`),
  createOrg: (req: CreateOrgRequest) =>
    http.post<Organisation>('/v1/admin/orgs', req),
  deleteOrg: (id: string) => http.del<void>(`/v1/admin/orgs/${id}`),
  suspendOrg: (id: string, suspended: boolean) =>
    http.post<void>(`/v1/admin/orgs/${id}/suspend`, { suspended }),
  ```

- [ ] **Step 3: Verify TypeScript compiles**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm -r tsc --noEmit
  ```
  Expected: no errors.

- [ ] **Step 4: Commit**

  ```bash
  git add web/packages/api-client/src/types.ts web/packages/api-client/src/licenseServer.ts
  git commit -m "feat(api-client): Organisation suspended fields + suspendOrg method"
  ```

---

## Task 9: Update `Organisations.vue`

**Files:**
- Modify: `web/apps/license-portal/src/views/Organisations.vue`

- [ ] **Step 1: Replace the entire file content**

  Replace `web/apps/license-portal/src/views/Organisations.vue` with:

  ```vue
  <script setup lang="ts">
  import { onMounted, ref } from 'vue';
  import {
    TDataTable, TPanel, TButton, TConfirmDialog, TPill, useToast, type Column,
  } from '@triton/ui';
  import type { Organisation } from '@triton/api-client';
  import { useApiClient } from '../stores/apiClient';
  import OrganisationForm from './modals/OrganisationForm.vue';

  const api = useApiClient();
  const toast = useToast();
  const items = ref<Organisation[]>([]);
  const loading = ref(false);
  const formOpen = ref(false);
  const confirmOpen = ref(false);
  const pendingDelete = ref<Organisation | null>(null);

  interface OrgRow extends Organisation {
    [key: string]: unknown;
  }

  const columns: Column<OrgRow>[] = [
    { key: 'name', label: 'Name', width: '1.5fr' },
    { key: 'contact', label: 'Contact', width: '1.2fr' },
    { key: 'notes', label: 'Notes', width: '1.5fr' },
    { key: 'activeActivations', label: 'Activations', width: '0.9fr' },
    { key: 'createdAt', label: 'Created', width: '1fr' },
    { key: 'updatedAt', label: 'Updated', width: '1fr' },
    { key: 'id', label: '', width: '220px', align: 'right' },
  ];

  async function load() {
    loading.value = true;
    try {
      items.value = await api.get().orgs();
    } catch (err) {
      toast.error({ title: 'Failed to load organisations', description: String(err) });
    } finally {
      loading.value = false;
    }
  }

  onMounted(load);

  function onRowClick(row: Record<string, unknown>) {
    window.location.hash = `#/orgs/${String(row.id)}`;
  }

  function askDelete(o: Organisation) {
    pendingDelete.value = o;
    confirmOpen.value = true;
  }

  async function confirmDelete() {
    const o = pendingDelete.value;
    if (!o) return;
    try {
      await api.get().deleteOrg(o.id);
      items.value = items.value.filter((x) => x.id !== o.id);
      toast.success({ title: 'Organisation deleted' });
    } catch (err) {
      toast.error({ title: 'Delete failed', description: String(err) });
    } finally {
      confirmOpen.value = false;
      pendingDelete.value = null;
    }
  }

  async function onSubmit(payload: { name: string; contact?: string; notes?: string }) {
    try {
      const o = await api.get().createOrg(payload);
      await load();
      formOpen.value = false;
      toast.success({ title: 'Organisation created', description: o.name });
    } catch (err) {
      toast.error({ title: 'Create failed', description: String(err) });
    }
  }

  async function toggleSuspend(o: Organisation) {
    const next = !o.suspended;
    try {
      await api.get().suspendOrg(o.id, next);
      const idx = items.value.findIndex((x) => x.id === o.id);
      if (idx !== -1) items.value[idx] = { ...items.value[idx], suspended: next };
      toast.success({ title: next ? 'Organisation suspended' : 'Organisation unsuspended' });
    } catch (err) {
      toast.error({ title: 'Action failed', description: String(err) });
    }
  }
  </script>

  <template>
    <TPanel
      title="Organisations"
      :subtitle="items.length ? `· ${items.length} total` : ''"
    >
      <template #action>
        <TButton
          variant="primary"
          size="sm"
          @click="formOpen = true"
        >
          New organisation
        </TButton>
      </template>

      <TDataTable
        :columns="columns"
        :rows="items"
        row-key="id"
        :empty-text="loading ? 'Loading…' : 'No organisations yet.'"
        @row-click="onRowClick"
      >
        <template #[`cell:name`]="{ row }">
          <span class="name-cell">
            {{ String(row.name) }}
            <TPill
              v-if="row.suspended"
              variant="unsafe"
            >Suspended</TPill>
          </span>
        </template>
        <template #[`cell:activeActivations`]="{ row }">
          {{ row.hasSeatedLicenses ? String(row.activeActivations) : '—' }}
        </template>
        <template #[`cell:id`]="{ row }">
          <span class="actions">
            <TButton
              :variant="row.suspended ? 'secondary' : 'secondary'"
              size="sm"
              :data-test="`org-suspend-${String(row.id)}`"
              @click.stop="toggleSuspend(row as unknown as Organisation)"
            >
              {{ row.suspended ? 'Unsuspend' : 'Suspend' }}
            </TButton>
            <TButton
              variant="danger"
              size="sm"
              :data-test="`org-delete-${String(row.id)}`"
              @click.stop="askDelete(row as unknown as Organisation)"
            >
              Delete
            </TButton>
          </span>
        </template>
      </TDataTable>
    </TPanel>

    <OrganisationForm
      :open="formOpen"
      @close="formOpen = false"
      @submit="onSubmit"
    />

    <TConfirmDialog
      :open="confirmOpen"
      title="Delete organisation?"
      :message="pendingDelete
        ? `Deleting '${pendingDelete.name}' cascades to all its licences and activations.`
        : ''"
      confirm-label="Delete"
      variant="danger"
      @confirm="confirmDelete"
      @cancel="confirmOpen = false; pendingDelete = null"
    />
  </template>

  <style scoped>
  .name-cell { display: flex; align-items: center; gap: var(--space-2); }
  .actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
  </style>
  ```

- [ ] **Step 2: TypeScript check**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm -r tsc --noEmit
  ```
  Expected: no errors.

- [ ] **Step 3: Commit**

  ```bash
  git add web/apps/license-portal/src/views/Organisations.vue
  git commit -m "feat(license-portal): Activations column + Suspend/Unsuspend button in org list"
  ```

---

## Task 10: Update `OrganisationDetail.vue`

**Files:**
- Modify: `web/apps/license-portal/src/views/OrganisationDetail.vue`

- [ ] **Step 1: Add imports for `TButton` and `useToast`**

  The current import from `@triton/ui` is:
  ```ts
  import {
    TPanel, TDataTable, TPill, useToast, type Column, type PillVariant,
  } from '@triton/ui';
  ```

  Add `TButton` to the import:
  ```ts
  import {
    TPanel, TDataTable, TPill, TButton, useToast, type Column, type PillVariant,
  } from '@triton/ui';
  ```

- [ ] **Step 2: Add `toggleSuspend` function**

  After the `onLicenceClick` function, append:

  ```ts
  async function toggleSuspend() {
    if (!org.value) return;
    const next = !org.value.suspended;
    try {
      await api.get().suspendOrg(org.value.id, next);
      org.value = { ...org.value, suspended: next };
      toast.success({ title: next ? 'Organisation suspended' : 'Organisation unsuspended' });
    } catch (err) {
      toast.error({ title: 'Action failed', description: String(err) });
    }
  }
  ```

- [ ] **Step 3: Add Status field to the kv grid**

  In the `<dl class="kv">` section, find:
  ```html
  <dt>Created</dt><dd>{{ org.createdAt }}</dd>
  ```

  Insert the Status row before `<dt>Created</dt>`:
  ```html
  <dt>Status</dt>
  <dd>
    <TPill :variant="org.suspended ? 'unsafe' : 'safe'">
      {{ org.suspended ? 'Suspended' : 'Active' }}
    </TPill>
  </dd>
  ```

- [ ] **Step 4: Add Suspend/Unsuspend button to the panel action slot**

  Replace `<TPanel :title="org.name">` with:
  ```html
  <TPanel :title="org.name">
    <template #action>
      <TButton
        variant="secondary"
        size="sm"
        :data-test="`org-detail-suspend`"
        @click="toggleSuspend"
      >
        {{ org.suspended ? 'Unsuspend' : 'Suspend' }}
      </TButton>
    </template>
  ```

- [ ] **Step 5: TypeScript check**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm -r tsc --noEmit
  ```
  Expected: no errors.

- [ ] **Step 6: Commit**

  ```bash
  git add web/apps/license-portal/src/views/OrganisationDetail.vue
  git commit -m "feat(license-portal): status pill and suspend button on org detail view"
  ```

---

## Task 11: Frontend tests

**Files:**
- Modify: `web/apps/license-portal/tests/views/Organisations.spec.ts`
- Create: `web/apps/license-portal/tests/views/OrganisationDetail.spec.ts`

- [ ] **Step 1: Update Organisations.spec.ts fixtures and add test cases**

  Replace the entire file with:

  ```ts
  import { describe, it, expect, vi, beforeEach } from 'vitest';
  import { mount, flushPromises } from '@vue/test-utils';
  import { createTestingPinia } from '@pinia/testing';
  import Organisations from '../../src/views/Organisations.vue';
  import { useApiClient } from '../../src/stores/apiClient';

  beforeEach(() => { vi.clearAllMocks(); });

  const ORGS = [
    {
      id: 'O1', name: 'Acme', contact: 'alice@acme.com', notes: '',
      suspended: false, activeActivations: 3, hasSeatedLicenses: true,
      createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z',
    },
    {
      id: 'O2', name: 'Globex', contact: '', notes: 'partner',
      suspended: true, activeActivations: 0, hasSeatedLicenses: false,
      createdAt: '2026-04-12T00:00:00Z', updatedAt: '2026-04-20T00:00:00Z',
    },
  ];

  function mountWith(orgs = ORGS) {
    const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
    const w = mount(Organisations, {
      global: { plugins: [pinia] },
    });
    const client = useApiClient();
    vi.spyOn(client, 'get').mockReturnValue({
      orgs: vi.fn().mockResolvedValue(orgs),
      deleteOrg: vi.fn().mockResolvedValue(undefined),
      createOrg: vi.fn().mockResolvedValue(orgs[0]),
      suspendOrg: vi.fn().mockResolvedValue(undefined),
    } as unknown as ReturnType<typeof client.get>);
    w.unmount();
    const w2 = mount(Organisations, {
      global: { plugins: [pinia] },
    });
    return w2;
  }

  describe('Organisations view', () => {
    it('renders rows for each org from the bare array', async () => {
      const w = mountWith();
      await flushPromises();
      await flushPromises();
      const html = w.html();
      expect(html).toContain('Acme');
      expect(html).toContain('Globex');
      expect(html).toContain('alice@acme.com');
      expect(html).toContain('partner');
      w.unmount();
    });

    it('opens OrganisationForm modal when "New organisation" is clicked', async () => {
      const w = mountWith();
      await flushPromises();
      await flushPromises();

      const buttons = w.findAll('button');
      const newBtn = buttons.find((b) => b.text().includes('New organisation'));
      expect(newBtn).toBeTruthy();
      await newBtn!.trigger('click');
      await flushPromises();

      expect(document.querySelector('.t-modal')).not.toBeNull();
      w.unmount();
    });

    it('shows activation count for orgs with seated licences', async () => {
      const w = mountWith();
      await flushPromises();
      await flushPromises();
      // O1 has hasSeatedLicenses=true and activeActivations=3
      expect(w.html()).toContain('3');
      w.unmount();
    });

    it('shows — for orgs without seated licences', async () => {
      const w = mountWith();
      await flushPromises();
      await flushPromises();
      // O2 has hasSeatedLicenses=false — cell should show —
      expect(w.html()).toContain('—');
      w.unmount();
    });

    it('shows Suspended pill for suspended org', async () => {
      const w = mountWith();
      await flushPromises();
      await flushPromises();
      // O2 is suspended
      expect(w.html()).toContain('Suspended');
      w.unmount();
    });

    it('calls suspendOrg with true when Suspend is clicked', async () => {
      const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
      const w = mount(Organisations, { global: { plugins: [pinia] } });
      const client = useApiClient();
      const suspendOrgSpy = vi.fn().mockResolvedValue(undefined);
      vi.spyOn(client, 'get').mockReturnValue({
        orgs: vi.fn().mockResolvedValue(ORGS),
        deleteOrg: vi.fn(),
        createOrg: vi.fn(),
        suspendOrg: suspendOrgSpy,
      } as unknown as ReturnType<typeof client.get>);
      w.unmount();
      const w2 = mount(Organisations, { global: { plugins: [pinia] } });
      await flushPromises();
      await flushPromises();

      // O1 is not suspended — clicking "Suspend" on it
      const suspendBtn = w2.find('[data-test="org-suspend-O1"]');
      expect(suspendBtn.exists()).toBe(true);
      await suspendBtn.trigger('click');
      await flushPromises();

      expect(suspendOrgSpy).toHaveBeenCalledWith('O1', true);
      w2.unmount();
    });

    it('calls suspendOrg with false when Unsuspend is clicked', async () => {
      const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
      const w = mount(Organisations, { global: { plugins: [pinia] } });
      const client = useApiClient();
      const suspendOrgSpy = vi.fn().mockResolvedValue(undefined);
      vi.spyOn(client, 'get').mockReturnValue({
        orgs: vi.fn().mockResolvedValue(ORGS),
        deleteOrg: vi.fn(),
        createOrg: vi.fn(),
        suspendOrg: suspendOrgSpy,
      } as unknown as ReturnType<typeof client.get>);
      w.unmount();
      const w2 = mount(Organisations, { global: { plugins: [pinia] } });
      await flushPromises();
      await flushPromises();

      // O2 is suspended — clicking "Unsuspend" on it
      const unsuspendBtn = w2.find('[data-test="org-suspend-O2"]');
      expect(unsuspendBtn.exists()).toBe(true);
      await unsuspendBtn.trigger('click');
      await flushPromises();

      expect(suspendOrgSpy).toHaveBeenCalledWith('O2', false);
      w2.unmount();
    });
  });
  ```

- [ ] **Step 2: Run Organisations unit tests**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm --filter license-portal test --run
  ```
  Expected: all tests PASS.

- [ ] **Step 3: Create OrganisationDetail.spec.ts**

  ```ts
  import { describe, it, expect, vi, beforeEach } from 'vitest';
  import { mount, flushPromises } from '@vue/test-utils';
  import { createTestingPinia } from '@pinia/testing';
  import { createRouter, createWebHashHistory } from 'vue-router';
  import OrganisationDetail from '../../src/views/OrganisationDetail.vue';
  import { useApiClient } from '../../src/stores/apiClient';

  beforeEach(() => { vi.clearAllMocks(); });

  const ACTIVE_ORG = {
    id: 'O1', name: 'Acme', contact: 'alice@acme.com', notes: '',
    suspended: false, activeActivations: 2, hasSeatedLicenses: true,
    createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z',
  };
  const SUSPENDED_ORG = { ...ACTIVE_ORG, id: 'O2', suspended: true };

  function makeRouter(orgId: string) {
    return createRouter({
      history: createWebHashHistory(),
      routes: [{ path: '/orgs/:id', component: OrganisationDetail }],
    });
  }

  function mountWith(org: typeof ACTIVE_ORG) {
    const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
    const router = makeRouter(org.id);
    router.push(`/orgs/${org.id}`);
    const w = mount(OrganisationDetail, {
      global: { plugins: [pinia, router] },
    });
    const client = useApiClient();
    const suspendOrgSpy = vi.fn().mockResolvedValue(undefined);
    vi.spyOn(client, 'get').mockReturnValue({
      org: vi.fn().mockResolvedValue(org),
      licences: vi.fn().mockResolvedValue([]),
      suspendOrg: suspendOrgSpy,
    } as unknown as ReturnType<typeof client.get>);
    w.unmount();
    const w2 = mount(OrganisationDetail, {
      global: { plugins: [pinia, router] },
    });
    return { w: w2, suspendOrgSpy };
  }

  describe('OrganisationDetail view', () => {
    it('shows Active pill for an active org', async () => {
      const { w } = mountWith(ACTIVE_ORG);
      await flushPromises();
      expect(w.html()).toContain('Active');
      expect(w.html()).not.toContain('Suspended');
      w.unmount();
    });

    it('shows Suspended pill for a suspended org', async () => {
      const { w } = mountWith(SUSPENDED_ORG);
      await flushPromises();
      expect(w.html()).toContain('Suspended');
      w.unmount();
    });

    it('Suspend button is present and calls suspendOrg with true for active org', async () => {
      const { w, suspendOrgSpy } = mountWith(ACTIVE_ORG);
      await flushPromises();

      const btn = w.find('[data-test="org-detail-suspend"]');
      expect(btn.exists()).toBe(true);
      expect(btn.text()).toBe('Suspend');
      await btn.trigger('click');
      await flushPromises();

      expect(suspendOrgSpy).toHaveBeenCalledWith('O1', true);
      w.unmount();
    });

    it('Unsuspend button calls suspendOrg with false for suspended org', async () => {
      const { w, suspendOrgSpy } = mountWith(SUSPENDED_ORG);
      await flushPromises();

      const btn = w.find('[data-test="org-detail-suspend"]');
      expect(btn.exists()).toBe(true);
      expect(btn.text()).toBe('Unsuspend');
      await btn.trigger('click');
      await flushPromises();

      expect(suspendOrgSpy).toHaveBeenCalledWith('O2', false);
      w.unmount();
    });
  });
  ```

- [ ] **Step 4: Run OrganisationDetail unit tests**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm --filter license-portal test --run
  ```
  Expected: all tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add web/apps/license-portal/tests/views/Organisations.spec.ts \
          web/apps/license-portal/tests/views/OrganisationDetail.spec.ts
  git commit -m "test(license-portal): org suspend + activations column unit tests"
  ```

---

## Task 12: Build the license portal and verify

- [ ] **Step 1: Build the license portal**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton/web && pnpm --filter license-portal build
  ```
  Expected: build succeeds, `pkg/licenseserver/ui/dist/` is populated.

- [ ] **Step 2: Run the full backend unit test suite**

  ```bash
  cd /Users/amirrudinyahaya/Workspace/triton && make test
  ```
  Expected: all unit tests pass.

- [ ] **Step 3: Run integration tests (requires PostgreSQL)**

  ```bash
  make test-integration
  ```
  Expected: all integration tests pass, including the new `TestSuspendOrg`, `TestListOrgs_ComputedFields`, `TestHandleSuspendOrg_*`, `TestHandleActivate_OrgSuspended`, `TestHandleValidate_OrgSuspended`.

- [ ] **Step 4: Final commit (if dist changed)**

  ```bash
  git add pkg/licenseserver/ui/dist/
  git commit -m "build(license-portal): rebuild dist with suspend action + activations column"
  ```

---

## Self-Review Notes

- `Organisation` type exported from `index.ts` re-exports from `types.ts` — no change needed in `index.ts`.
- `failingStore` in `failingstore_test.go` embeds `*PostgresStore` — it automatically satisfies the updated interface, no changes needed.
- `GetOrg` in `handleValidate` at line ~227 still runs for the `orgName` response field — the new suspension check above it uses the same pattern (non-fatal GetOrg failure) for consistency.
- `TButton` only accepts `'primary' | 'secondary' | 'ghost' | 'danger'` — the Suspend button uses `secondary` (no "warn" variant exists).
- The `CreateOrg` postgres method does not set `suspended` — it defaults to `FALSE` via the DB column default, which is correct.
