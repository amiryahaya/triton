# Report Portal — Superadmin Setup + Tenant Licensing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `platform_admin` role to the Report Portal with setup wizard, platform admin CRUD, tenant creation that activates a Licence Portal licence, and background licence lifecycle enforcement.

**Architecture:** Platform admins live in the Report Portal's own `users` table (org_id = NULL). Each tenant activation uses `machineID = instanceID + "/" + tenantID` so each (instance, tenant) pair is a unique seat. A 24h background goroutine refreshes licence status; a per-request middleware enforces grace/expired gates.

**Tech Stack:** Go 1.25, pgx/v5, chi/v5, Vue 3 + Vite, Vitest, `internal/license.ServerClient`, `internal/auth.UserClaims`

---

## File Map

**Backend — new files:**
- `pkg/store/tenant_licence_postgres.go` — `GetOrCreateInstance`, `GetTenantLicence`, `UpsertTenantLicence`, `ListTenantLicences`, `DeleteTenantLicence`
- `pkg/server/handlers_setup.go` — `handleSetupStatus`, `handleFirstSetup`
- `pkg/server/middleware_setup_guard.go` — `SetupGuard` (redirect to /setup until platform_admin exists)
- `pkg/server/handlers_platform_admins.go` — platform admin CRUD
- `pkg/server/handlers_platform_tenants.go` — tenant CRUD + licence activation
- `pkg/server/licence_middleware.go` — `TenantLicenceGate` per-request enforcement
- `pkg/server/licence_validator.go` — 24h background validator goroutine

**Backend — modified files:**
- `pkg/store/migrations.go` — version 27: nullable org_id, platform_admin role, report_instance, tenant_licences, licence_id on orgs
- `pkg/store/store.go` — `ReportInstance`, `TenantLicence` types; extend `Store` interface; add `LicenceID` to `Organization`
- `pkg/store/identity_postgres.go` — handle NULL org_id when scanning users; org queries include licence_id
- `internal/license/client.go` — `ActivateForTenant`, `DeactivateForTenant`, `ValidateForTenant`
- `pkg/server/server.go` — add `LicencePortalURL`, `LicencePortalClient` to Config; start validator goroutine; register new routes
- `pkg/server/auth_lookup.go` — add `loadUserByID`, `loadUserByEmail` that accept platform_admin
- `pkg/server/auth_middleware.go` — add `RequirePlatformAdmin` middleware

**Frontend — new files:**
- `web/apps/report-portal/src/views/Setup.vue`
- `web/apps/report-portal/src/views/PlatformAdmins.vue`
- `web/apps/report-portal/src/views/TenantDetail.vue`

**Frontend — modified files:**
- `web/apps/report-portal/src/views/Tenants.vue` — implement existing stub as platform tenant list
- `web/apps/report-portal/src/router.ts` — add /setup, /platform/* routes
- `web/apps/report-portal/src/nav.ts` — add Platform section
- `web/apps/report-portal/src/App.vue` — setup guard + change-password interstitial

**Tests:**
- `pkg/server/handlers_setup_test.go`
- `pkg/server/handlers_platform_test.go`

---

## Task 1: Database Migration (version 27)

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/store/store_test.go — add to existing TestMigrations or create new
func TestMigration27_PlatformAdminSchema(t *testing.T) {
    s := newTestStore(t)
    defer s.Close()

    // report_instance table exists and auto-populates via GetOrCreateInstance
    _, err := s.pool.Exec(context.Background(),
        `INSERT INTO report_instance (id) VALUES (gen_random_uuid())`)
    require.NoError(t, err)

    // tenant_licences table exists
    _, err = s.pool.Exec(context.Background(),
        `INSERT INTO tenant_licences (org_id, licence_id, token, expires_at, status)
         VALUES (gen_random_uuid(), 'test-lic', 'tok', NOW()+interval'1 year', 'active')`)
    // This will fail FK since org doesn't exist — that's expected
    require.Error(t, err)

    // users.org_id is nullable (platform_admin)
    _, err = s.pool.Exec(context.Background(),
        `INSERT INTO users (id, org_id, email, name, role, password, must_change_password, invited_at, created_at, updated_at)
         VALUES (gen_random_uuid(), NULL, 'admin@test.com', 'Admin', 'platform_admin',
                 'hash', false, NOW(), NOW(), NOW())`)
    require.NoError(t, err)
}
```

Run: `go test -v -run TestMigration27 ./pkg/store/`
Expected: FAIL — migration 27 does not exist yet

- [ ] **Step 2: Add migration version 27**

In `pkg/store/migrations.go`, after the last entry (version 26), append:

```go
// Version 27: Platform admin role + Report Portal licensing schema.
//
// - users.org_id made nullable so platform_admin users can exist without an org.
//   The FK constraint remains; NULL is simply ignored by PostgreSQL.
// - users role CHECK expanded to include 'platform_admin' and 'org_officer'.
// - report_instance: stable UUID identifying this Report Portal deployment.
//   One row; used as the machineID prefix for Licence Portal activations.
// - tenant_licences: caches the activation token + expiry per tenant.
// - organizations.licence_id: the licence key used to activate this tenant.
`ALTER TABLE users ALTER COLUMN org_id DROP NOT NULL;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('platform_admin', 'org_admin', 'org_user', 'org_officer'));

CREATE TABLE IF NOT EXISTS report_instance (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_licences (
    org_id       UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    licence_id   TEXT NOT NULL,
    token        TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    renewed_at   TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'grace', 'expired'))
);

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS licence_id TEXT NOT NULL DEFAULT '';`,
```

- [ ] **Step 3: Run test to verify it passes**

Run: `go test -v -run TestMigration27 ./pkg/store/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/store/migrations.go pkg/store/store_test.go
git commit -m "feat(store): migration v27 — platform_admin role + tenant licensing schema"
```

---

## Task 2: Store Types + Interface Extension

**Files:**
- Modify: `pkg/store/store.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/store/store_test.go
func TestTenantLicenceStoreInterface(t *testing.T) {
    s := newTestStore(t)
    defer s.Close()

    // GetOrCreateInstance returns stable ID on repeated calls
    inst1, err := s.GetOrCreateInstance(context.Background())
    require.NoError(t, err)
    inst2, err := s.GetOrCreateInstance(context.Background())
    require.NoError(t, err)
    require.Equal(t, inst1.ID, inst2.ID)

    // Create org then upsert tenant licence
    org := &Organization{ID: uuid.Must(uuid.NewV7()).String(), Name: "Acme"}
    require.NoError(t, s.CreateOrg(context.Background(), org))

    tl := &TenantLicence{
        OrgID:     org.ID,
        LicenceID: "lic-abc",
        Token:     "tok-xyz",
        ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
        Status:    "active",
    }
    require.NoError(t, s.UpsertTenantLicence(context.Background(), tl))

    got, err := s.GetTenantLicence(context.Background(), org.ID)
    require.NoError(t, err)
    require.Equal(t, "lic-abc", got.LicenceID)

    list, err := s.ListTenantLicences(context.Background())
    require.NoError(t, err)
    require.Len(t, list, 1)

    require.NoError(t, s.DeleteTenantLicence(context.Background(), org.ID))
    _, err = s.GetTenantLicence(context.Background(), org.ID)
    require.ErrorAs(t, err, &ErrNotFound{})
}
```

Run: `go test -v -run TestTenantLicenceStoreInterface ./pkg/store/`
Expected: compile error — types don't exist yet

- [ ] **Step 2: Add types to store.go**

In `pkg/store/store.go`, add after the `Organization` struct:

```go
// LicenceID is the licence key used to provision this tenant.
// Added to Organization in migration v27.
```

Update `Organization` struct to include `LicenceID`:

```go
type Organization struct {
    ID                     string    `json:"id"`
    Name                   string    `json:"name"`
    LicenceID              string    `json:"licenceId,omitempty"`
    ExecutiveTargetPercent float64   `json:"executiveTargetPercent"`
    ExecutiveDeadlineYear  int       `json:"executiveDeadlineYear"`
    CreatedAt              time.Time `json:"createdAt"`
    UpdatedAt              time.Time `json:"updatedAt"`
}
```

Add new types:

```go
// ReportInstance is the stable identity of this Report Portal deployment.
// One row exists; created on first call to GetOrCreateInstance.
type ReportInstance struct {
    ID        string    `json:"id"`
    CreatedAt time.Time `json:"createdAt"`
}

// TenantLicence caches the Licence Portal activation for a tenant.
type TenantLicence struct {
    OrgID       string     `json:"orgId"`
    LicenceID   string     `json:"licenceId"`
    Token       string     `json:"-"`
    ActivatedAt time.Time  `json:"activatedAt"`
    ExpiresAt   time.Time  `json:"expiresAt"`
    RenewedAt   *time.Time `json:"renewedAt,omitempty"`
    Status      string     `json:"status"` // active | grace | expired
}
```

- [ ] **Step 3: Extend Store interface**

In `pkg/store/store.go`, add a new interface and embed it in `Store`:

```go
// TenantLicenceStore manages per-tenant licence records.
type TenantLicenceStore interface {
    // GetOrCreateInstance returns the single report_instance row,
    // creating it if it doesn't exist.
    GetOrCreateInstance(ctx context.Context) (*ReportInstance, error)

    // GetTenantLicence returns the licence record for the given org.
    GetTenantLicence(ctx context.Context, orgID string) (*TenantLicence, error)

    // UpsertTenantLicence inserts or replaces the licence record.
    UpsertTenantLicence(ctx context.Context, tl *TenantLicence) error

    // ListTenantLicences returns all tenant_licences rows.
    ListTenantLicences(ctx context.Context) ([]TenantLicence, error)

    // DeleteTenantLicence removes the licence record for the given org.
    DeleteTenantLicence(ctx context.Context, orgID string) error
}
```

In the `Store` interface, add `TenantLicenceStore` to the embedded list.

- [ ] **Step 4: Run test to verify compile error resolves (still fails at runtime)**

Run: `go build ./pkg/store/`
Expected: compile error — PostgresStore does not implement TenantLicenceStore

- [ ] **Step 5: Commit**

```bash
git add pkg/store/store.go pkg/store/store_test.go
git commit -m "feat(store): TenantLicence + ReportInstance types + interface extension"
```

---

## Task 3: Postgres Implementation — Tenant Licences

**Files:**
- Modify: `pkg/store/identity_postgres.go` (nullable org_id + licence_id)
- Create: `pkg/store/tenant_licence_postgres.go`

- [ ] **Step 1: Fix identity_postgres.go for nullable org_id + licence_id**

In `pkg/store/identity_postgres.go`, update `CreateOrg` to include `licence_id`:

```go
func (s *PostgresStore) CreateOrg(ctx context.Context, org *Organization) error {
    now := time.Now().UTC()
    if org.CreatedAt.IsZero() {
        org.CreatedAt = now
    }
    if org.UpdatedAt.IsZero() {
        org.UpdatedAt = now
    }
    _, err := s.pool.Exec(ctx,
        `INSERT INTO organizations (id, name, licence_id, executive_target_percent, executive_deadline_year, created_at, updated_at)
         VALUES ($1, $2, $3, COALESCE(NULLIF($4::numeric, 0), 80.0), COALESCE(NULLIF($5::integer, 0), 2030), $6, $7)`,
        org.ID, org.Name, org.LicenceID,
        org.ExecutiveTargetPercent, org.ExecutiveDeadlineYear,
        org.CreatedAt, org.UpdatedAt,
    )
    if err != nil {
        var pgErr *pgconn.PgError
        if errors.As(err, &pgErr) && pgErr.Code == "23505" {
            return &ErrConflict{Message: "organization with this id already exists"}
        }
        return fmt.Errorf("creating organization: %w", err)
    }
    return nil
}
```

Update `GetOrg`, `ListOrgs`, `UpdateOrg` to include `licence_id` in SELECT/UPDATE.

For `GetOrg`:
```go
func (s *PostgresStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
    var org Organization
    err := s.pool.QueryRow(ctx,
        `SELECT id, name, licence_id, executive_target_percent, executive_deadline_year, created_at, updated_at
         FROM organizations WHERE id = $1`, id,
    ).Scan(&org.ID, &org.Name, &org.LicenceID, &org.ExecutiveTargetPercent,
        &org.ExecutiveDeadlineYear, &org.CreatedAt, &org.UpdatedAt)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, &ErrNotFound{Resource: "organization", ID: id}
        }
        return nil, fmt.Errorf("getting organization: %w", err)
    }
    return &org, nil
}
```

Apply same pattern to `ListOrgs` and `UpdateOrg`.

Fix `scanUser` to handle NULL org_id:

```go
func scanUser(row pgx.Row) (*User, error) {
    var u User
    var orgID *string
    err := row.Scan(&u.ID, &orgID, &u.Email, &u.Name, &u.Role, &u.Password,
        &u.MustChangePassword, &u.InvitedAt, &u.CreatedAt, &u.UpdatedAt)
    if err != nil {
        return nil, err
    }
    if orgID != nil {
        u.OrgID = *orgID
    }
    return &u, nil
}
```

Fix `CreateUser` to insert NULL when OrgID is empty:

```go
func (s *PostgresStore) CreateUser(ctx context.Context, user *User) error {
    // ...
    var orgIDParam *string
    if user.OrgID != "" {
        orgIDParam = &user.OrgID
    }
    _, err := s.pool.Exec(ctx,
        `INSERT INTO users (id, org_id, email, name, role, password, must_change_password, invited_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        user.ID, orgIDParam, user.Email, user.Name, user.Role, user.Password,
        user.MustChangePassword, user.InvitedAt, user.CreatedAt, user.UpdatedAt,
    )
    // ...
}
```

Fix `ListUsers` — platform admins filter: when `filter.OrgID == "platform"` return platform_admin users; otherwise filter by org_id IS NOT NULL:

```go
func (s *PostgresStore) ListUsers(ctx context.Context, filter UserFilter) ([]User, error) {
    query := `SELECT ` + userSelectColumns + ` FROM users WHERE 1=1`
    args := []any{}
    idx := 0
    if filter.OrgID == "platform" {
        idx++
        query += fmt.Sprintf(" AND role = 'platform_admin'")
    } else if filter.OrgID != "" {
        idx++
        query += fmt.Sprintf(" AND org_id = $%d", idx)
        args = append(args, filter.OrgID)
    }
    // ... rest unchanged
}
```

- [ ] **Step 2: Create tenant_licence_postgres.go**

```go
package store

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5"
)

func (s *PostgresStore) GetOrCreateInstance(ctx context.Context) (*ReportInstance, error) {
    // Insert a row if none exists, then read it back.
    _, err := s.pool.Exec(ctx,
        `INSERT INTO report_instance (id) VALUES (gen_random_uuid()) ON CONFLICT DO NOTHING`)
    if err != nil {
        return nil, fmt.Errorf("ensuring report instance: %w", err)
    }
    var inst ReportInstance
    err = s.pool.QueryRow(ctx,
        `SELECT id, created_at FROM report_instance LIMIT 1`).
        Scan(&inst.ID, &inst.CreatedAt)
    if err != nil {
        return nil, fmt.Errorf("reading report instance: %w", err)
    }
    return &inst, nil
}

func (s *PostgresStore) GetTenantLicence(ctx context.Context, orgID string) (*TenantLicence, error) {
    var tl TenantLicence
    err := s.pool.QueryRow(ctx,
        `SELECT org_id, licence_id, token, activated_at, expires_at, renewed_at, status
         FROM tenant_licences WHERE org_id = $1`, orgID).
        Scan(&tl.OrgID, &tl.LicenceID, &tl.Token, &tl.ActivatedAt,
            &tl.ExpiresAt, &tl.RenewedAt, &tl.Status)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, &ErrNotFound{Resource: "tenant_licence", ID: orgID}
        }
        return nil, fmt.Errorf("getting tenant licence: %w", err)
    }
    return &tl, nil
}

func (s *PostgresStore) UpsertTenantLicence(ctx context.Context, tl *TenantLicence) error {
    if tl.ActivatedAt.IsZero() {
        tl.ActivatedAt = time.Now().UTC()
    }
    _, err := s.pool.Exec(ctx,
        `INSERT INTO tenant_licences (org_id, licence_id, token, activated_at, expires_at, renewed_at, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (org_id) DO UPDATE SET
             licence_id   = EXCLUDED.licence_id,
             token        = EXCLUDED.token,
             expires_at   = EXCLUDED.expires_at,
             renewed_at   = EXCLUDED.renewed_at,
             status       = EXCLUDED.status`,
        tl.OrgID, tl.LicenceID, tl.Token, tl.ActivatedAt,
        tl.ExpiresAt, tl.RenewedAt, tl.Status,
    )
    if err != nil {
        return fmt.Errorf("upserting tenant licence: %w", err)
    }
    return nil
}

func (s *PostgresStore) ListTenantLicences(ctx context.Context) ([]TenantLicence, error) {
    rows, err := s.pool.Query(ctx,
        `SELECT org_id, licence_id, token, activated_at, expires_at, renewed_at, status
         FROM tenant_licences ORDER BY activated_at DESC`)
    if err != nil {
        return nil, fmt.Errorf("listing tenant licences: %w", err)
    }
    defer rows.Close()

    var out []TenantLicence
    for rows.Next() {
        var tl TenantLicence
        if err := rows.Scan(&tl.OrgID, &tl.LicenceID, &tl.Token, &tl.ActivatedAt,
            &tl.ExpiresAt, &tl.RenewedAt, &tl.Status); err != nil {
            return nil, fmt.Errorf("scanning tenant licence: %w", err)
        }
        out = append(out, tl)
    }
    if out == nil {
        out = []TenantLicence{}
    }
    return out, rows.Err()
}

func (s *PostgresStore) DeleteTenantLicence(ctx context.Context, orgID string) error {
    tag, err := s.pool.Exec(ctx,
        `DELETE FROM tenant_licences WHERE org_id = $1`, orgID)
    if err != nil {
        return fmt.Errorf("deleting tenant licence: %w", err)
    }
    if tag.RowsAffected() == 0 {
        return &ErrNotFound{Resource: "tenant_licence", ID: orgID}
    }
    return nil
}
```

- [ ] **Step 3: Run tests**

Run: `go test -v -run TestTenantLicenceStoreInterface ./pkg/store/`
Expected: PASS

Run: `go build ./...`
Expected: no compile errors

- [ ] **Step 4: Commit**

```bash
git add pkg/store/tenant_licence_postgres.go pkg/store/identity_postgres.go
git commit -m "feat(store): TenantLicence + ReportInstance postgres implementation"
```

---

## Task 4: License Client — Tenant Activation Methods

**Files:**
- Modify: `internal/license/client.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/license/client_test.go
func TestActivateForTenant_SendsCustomMachineID(t *testing.T) {
    var captured map[string]string
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = json.NewDecoder(r.Body).Decode(&captured)
        json.NewEncoder(w).Encode(map[string]any{
            "token": "tok", "activationID": "aid", "tier": "enterprise",
            "expiresAt": "2027-01-01T00:00:00Z",
        })
        w.WriteHeader(http.StatusCreated)
    }))
    defer srv.Close()

    c := NewServerClient(srv.URL)
    _, err := c.ActivateForTenant("lic-123", "inst-abc/tenant-xyz")
    require.NoError(t, err)
    require.Equal(t, "inst-abc/tenant-xyz", captured["machineID"])
}
```

Run: `go test -v -run TestActivateForTenant ./internal/license/`
Expected: FAIL — method not defined

- [ ] **Step 2: Add three new methods to client.go**

```go
// ActivateForTenant activates a licence with a custom machineID of the form
// "instanceID/tenantID". Used by the Report Portal to create a unique
// activation seat per (instance, tenant) pair.
func (c *ServerClient) ActivateForTenant(licenceKey, machineID string) (*ActivateResponse, error) {
    body := map[string]string{
        "licenseID": licenceKey,
        "machineID": machineID,
    }
    data, err := json.Marshal(body)
    if err != nil {
        return nil, fmt.Errorf("marshalling request: %w", err)
    }
    resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/activate",
        "application/json", bytes.NewReader(data))
    if err != nil {
        return nil, fmt.Errorf("connecting to licence server: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()
    respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
    if err != nil {
        return nil, fmt.Errorf("reading response: %w", err)
    }
    switch resp.StatusCode {
    case http.StatusConflict:
        return nil, fmt.Errorf("no seats available")
    case http.StatusForbidden:
        var e map[string]string
        _ = json.Unmarshal(respBody, &e)
        return nil, fmt.Errorf("activation denied: %s", e["error"])
    case http.StatusNotFound:
        return nil, fmt.Errorf("licence not found")
    case http.StatusCreated:
        // ok
    default:
        return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, respBody)
    }
    var result ActivateResponse
    if err := json.Unmarshal(respBody, &result); err != nil {
        return nil, fmt.Errorf("parsing response: %w", err)
    }
    return &result, nil
}

// DeactivateForTenant releases a tenant activation seat using the given machineID.
func (c *ServerClient) DeactivateForTenant(licenceKey, machineID string) error {
    body := map[string]string{"licenseID": licenceKey, "machineID": machineID}
    data, _ := json.Marshal(body)
    resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/deactivate",
        "application/json", bytes.NewReader(data))
    if err != nil {
        return fmt.Errorf("connecting to licence server: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()
    _, _ = io.Copy(io.Discard, resp.Body)
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("deactivation failed (status %d)", resp.StatusCode)
    }
    return nil
}

// ValidateForTenant validates a cached token with the given machineID.
func (c *ServerClient) ValidateForTenant(licenceID, token, machineID string) (*ValidateResponse, error) {
    body := map[string]string{
        "licenseID": licenceID,
        "machineID": machineID,
        "token":     token,
    }
    data, _ := json.Marshal(body)
    resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/validate",
        "application/json", bytes.NewReader(data))
    if err != nil {
        return nil, fmt.Errorf("connecting to licence server: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()
    respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
    if err != nil {
        return nil, fmt.Errorf("reading response: %w", err)
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("validate failed (status %d): %s", resp.StatusCode, respBody)
    }
    var result ValidateResponse
    if err := json.Unmarshal(respBody, &result); err != nil {
        return nil, fmt.Errorf("parsing response: %w", err)
    }
    return &result, nil
}
```

- [ ] **Step 3: Run test**

Run: `go test -v -run TestActivateForTenant ./internal/license/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/license/client.go internal/license/client_test.go
git commit -m "feat(license): ActivateForTenant/DeactivateForTenant/ValidateForTenant with custom machineID"
```

---

## Task 5: Server Config + Auth Helpers for platform_admin

**Files:**
- Modify: `pkg/server/server.go` (Config fields)
- Modify: `pkg/server/auth_lookup.go` (new helpers)
- Modify: `pkg/server/auth_middleware.go` (RequirePlatformAdmin)

- [ ] **Step 1: Write the failing test**

```go
// pkg/server/auth_middleware_test.go — add:
func TestRequirePlatformAdmin_AcceptsPlatformAdmin(t *testing.T) {
    srv := &Server{}
    claims := &auth.UserClaims{Role: "platform_admin"}
    ctx := context.WithValue(context.Background(), claimsContextKey{}, claims)
    called := false
    h := RequirePlatformAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        called = true
    }))
    rr := httptest.NewRecorder()
    h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
    require.True(t, called)
    require.Equal(t, 200, rr.Code)
}

func TestRequirePlatformAdmin_RejectsOrgAdmin(t *testing.T) {
    claims := &auth.UserClaims{Role: "org_admin"}
    ctx := context.WithValue(context.Background(), claimsContextKey{}, claims)
    h := RequirePlatformAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
    rr := httptest.NewRecorder()
    h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
    require.Equal(t, 403, rr.Code)
}
```

Run: `go test -v -run TestRequirePlatformAdmin ./pkg/server/`
Expected: FAIL — `RequirePlatformAdmin` undefined

- [ ] **Step 2: Add RequirePlatformAdmin to auth_middleware.go**

```go
// RequirePlatformAdmin enforces that the authenticated user has role=platform_admin.
// Returns 401 if no claims are present (JWTAuth not in chain) and 403 otherwise.
func RequirePlatformAdmin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := ClaimsFromContext(r.Context())
        if claims == nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        if claims.Role != "platform_admin" {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

- [ ] **Step 3: Add loadUserByID and loadUserByEmail to auth_lookup.go**

These accept any role (used by handleLogin + handleChangePassword so platform_admin can authenticate):

```go
// loadUserByID fetches any user by ID regardless of role. Used by auth
// handlers that must work for both org users and platform admins.
func (s *Server) loadUserByID(ctx context.Context, id string) (*store.User, int) {
    user, err := s.store.GetUser(ctx, id)
    if err != nil {
        var nf *store.ErrNotFound
        if errors.As(err, &nf) {
            return nil, http.StatusNotFound
        }
        log.Printf("loadUserByID error: %v", err)
        return nil, http.StatusInternalServerError
    }
    return user, 0
}

// loadUserByEmail fetches any user by email regardless of role.
func (s *Server) loadUserByEmail(ctx context.Context, email string) (*store.User, int) {
    user, err := s.store.GetUserByEmail(ctx, email)
    if err != nil {
        var nf *store.ErrNotFound
        if errors.As(err, &nf) {
            return nil, http.StatusNotFound
        }
        log.Printf("loadUserByEmail error: %v", err)
        return nil, http.StatusInternalServerError
    }
    return user, 0
}
```

- [ ] **Step 4: Update handleLogin and handleChangePassword to use new helpers**

In `pkg/server/handlers_auth.go`, change `handleLogin` to call `loadUserByEmail` instead of `loadOrgUserByEmail`. Change `handleChangePassword` to call `loadUserByID` instead of `loadOrgUserByID`. The role check for org isolation still happens in other middleware; these auth endpoints just need to work for any valid user.

- [ ] **Step 5: Add Config fields to server.go**

In `pkg/server/server.go`, add to `Config`:

```go
// LicencePortalURL is the base URL of the Licence Portal used to
// activate/validate/deactivate tenant licences. When empty, tenant
// creation returns 503.
LicencePortalURL string
```

Add to `Server` struct:

```go
// licencePortalClient communicates with the external Licence Portal.
// Nil when LicencePortalURL is not configured.
licencePortalClient *license.ServerClient

// licenceValidatorDone is closed when the background validator exits.
licenceValidatorDone chan struct{}
```

In `New()`, after building `srv`:
```go
if cfg.LicencePortalURL != "" {
    srv.licencePortalClient = license.NewServerClient(cfg.LicencePortalURL)
}
```

- [ ] **Step 6: Run tests**

Run: `go test -v -run TestRequirePlatformAdmin ./pkg/server/`
Expected: PASS

Run: `go build ./...`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add pkg/server/auth_middleware.go pkg/server/auth_lookup.go pkg/server/server.go pkg/server/handlers_auth.go
git commit -m "feat(server): RequirePlatformAdmin middleware + loadUserByID/Email helpers + LicencePortalURL config"
```

---

## Task 6: Setup Handlers + Guard Middleware

**Files:**
- Create: `pkg/server/handlers_setup.go`
- Create: `pkg/server/middleware_setup_guard.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/server/handlers_setup_test.go`:

```go
package server_test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestHandleSetupStatus_NeedsSetup(t *testing.T) {
    srv, _ := newTestServer(t)
    resp := doRequest(t, srv, "GET", "/api/v1/setup/status", nil, "")
    require.Equal(t, 200, resp.StatusCode)
    var body map[string]bool
    _ = json.NewDecoder(resp.Body).Decode(&body)
    require.True(t, body["needsSetup"])
}

func TestHandleFirstSetup_CreatesAdmin(t *testing.T) {
    srv, _ := newTestServer(t)
    body := `{"name":"Alice","email":"alice@example.com"}`
    resp := doRequest(t, srv, "POST", "/api/v1/setup", strings.NewReader(body), "")
    require.Equal(t, 201, resp.StatusCode)
}

func TestHandleFirstSetup_BlocksSecondCall(t *testing.T) {
    srv, _ := newTestServer(t)
    body := `{"name":"Alice","email":"alice@example.com"}`
    resp1 := doRequest(t, srv, "POST", "/api/v1/setup", strings.NewReader(body), "")
    require.Equal(t, 201, resp1.StatusCode)
    resp2 := doRequest(t, srv, "POST", "/api/v1/setup",
        strings.NewReader(`{"name":"Bob","email":"bob@example.com"}`), "")
    require.Equal(t, 409, resp2.StatusCode)
}

func TestHandleSetupStatus_ReadyAfterSetup(t *testing.T) {
    srv, _ := newTestServer(t)
    body := `{"name":"Alice","email":"alice@example.com"}`
    _ = doRequest(t, srv, "POST", "/api/v1/setup", strings.NewReader(body), "")
    resp := doRequest(t, srv, "GET", "/api/v1/setup/status", nil, "")
    var out map[string]bool
    _ = json.NewDecoder(resp.Body).Decode(&out)
    require.False(t, out["needsSetup"])
}
```

Run: `go test -v -run TestHandleSetup ./pkg/server/`
Expected: FAIL — routes don't exist yet

- [ ] **Step 2: Create handlers_setup.go**

```go
package server

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"

    "github.com/amiryahaya/triton/internal/auth"
    "github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/setup/status — public, no auth.
// Returns {"needsSetup": true} when no platform_admin exists.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
    users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: "platform"})
    if err != nil {
        log.Printf("setup status: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": len(users) == 0})
}

// POST /api/v1/setup — public, blocked after first use.
// Body: {"name": "Alice", "email": "alice@example.com"}
func (s *Server) handleFirstSetup(w http.ResponseWriter, r *http.Request) {
    users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: "platform"})
    if err != nil {
        log.Printf("setup: list users: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if len(users) > 0 {
        writeError(w, http.StatusConflict, "setup already completed")
        return
    }

    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
    var req struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    email := strings.ToLower(strings.TrimSpace(req.Email))
    name := strings.TrimSpace(req.Name)
    if email == "" || name == "" {
        writeError(w, http.StatusBadRequest, "name and email are required")
        return
    }

    tempPassword, err := auth.GenerateTempPassword(24)
    if err != nil {
        log.Printf("setup: gen temp password: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    now := time.Now().UTC()
    user := &store.User{
        ID:                 uuid.Must(uuid.NewV7()).String(),
        OrgID:              "", // platform_admin has no org
        Email:              email,
        Name:               name,
        Role:               "platform_admin",
        Password:           string(hashed),
        MustChangePassword: true,
        InvitedAt:          now,
        CreatedAt:          now,
        UpdatedAt:          now,
    }
    if err := s.store.CreateUser(r.Context(), user); err != nil {
        var conflict *store.ErrConflict
        if errors.As(err, &conflict) {
            writeError(w, http.StatusConflict, "email already in use")
            return
        }
        log.Printf("setup: create user: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    if s.config.Mailer != nil {
        _ = s.config.Mailer.SendInviteEmail(r.Context(), inviteEmailData(
            email, name, "Report Portal", tempPassword, s.config.InviteLoginURL,
        ))
    }

    writeJSON(w, http.StatusCreated, map[string]string{"id": user.ID, "tempPassword": tempPassword})
}
```

- [ ] **Step 3: Create middleware_setup_guard.go**

```go
package server

import (
    "log"
    "net/http"

    "github.com/amiryahaya/triton/pkg/store"
)

// SetupGuard redirects every request to /setup when no platform_admin
// exists, except for the /api/v1/setup/* and /ui/* endpoints themselves.
func (s *Server) SetupGuard(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Always allow setup endpoints and static assets.
        if isSetupPath(r.URL.Path) {
            next.ServeHTTP(w, r)
            return
        }
        users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: "platform"})
        if err != nil {
            log.Printf("setup guard: %v", err)
            next.ServeHTTP(w, r)
            return
        }
        if len(users) == 0 {
            // API calls get 307; browser GETs on /ui/* also get 307 to the
            // SPA which handles the /setup hash route.
            http.Redirect(w, r, "/api/v1/setup/status", http.StatusTemporaryRedirect)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func isSetupPath(path string) bool {
    return path == "/api/v1/setup/status" ||
        path == "/api/v1/setup" ||
        len(path) >= 4 && path[:4] == "/ui/"
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestHandleSetup ./pkg/server/`
Expected: PASS (after routes are wired in Task 11, these run)

Note: full wiring happens in Task 11. At this point verify `go build ./...` passes.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/handlers_setup.go pkg/server/middleware_setup_guard.go pkg/server/handlers_setup_test.go
git commit -m "feat(server): setup handlers + setup guard middleware"
```

---

## Task 7: Platform Admin CRUD Handlers

**Files:**
- Create: `pkg/server/handlers_platform_admins.go`

- [ ] **Step 1: Write failing tests in handlers_platform_test.go**

Create `pkg/server/handlers_platform_test.go`:

```go
package server_test

import (
    "encoding/json"
    "net/http"
    "strings"
    "testing"

    "github.com/stretchr/testify/require"
)

// helpers: seedPlatformAdmin creates a platform_admin and returns JWT
func seedPlatformAdmin(t *testing.T, srv *httptest.Server) string {
    t.Helper()
    body := `{"name":"Alice","email":"alice@example.com"}`
    resp := doRequest(t, srv, "POST", "/api/v1/setup", strings.NewReader(body), "")
    require.Equal(t, 201, resp.StatusCode)
    // login to get JWT
    loginResp := doRequest(t, srv, "POST", "/api/v1/auth/login",
        strings.NewReader(`{"email":"alice@example.com","password":"<from resp>"}`), "")
    // NOTE: in tests, read tempPassword from setup response body
    // For simplicity tests use quickPlatformAdminJWT helper below
    _ = loginResp
    return quickPlatformAdminJWT(t, srv)
}

func TestListPlatformAdmins(t *testing.T) {
    srv, _ := newTestServer(t)
    jwt := seedPlatformAdmin(t, srv.srv)
    resp := doRequest(t, srv.srv, "GET", "/api/v1/platform/admins", nil, jwt)
    require.Equal(t, 200, resp.StatusCode)
    var admins []map[string]any
    _ = json.NewDecoder(resp.Body).Decode(&admins)
    require.Len(t, admins, 1)
}

func TestInvitePlatformAdmin(t *testing.T) {
    srv, _ := newTestServer(t)
    jwt := seedPlatformAdmin(t, srv.srv)
    body := `{"name":"Bob","email":"bob@example.com"}`
    resp := doRequest(t, srv.srv, "POST", "/api/v1/platform/admins",
        strings.NewReader(body), jwt)
    require.Equal(t, 201, resp.StatusCode)
}

func TestDeletePlatformAdmin_CannotDeleteSelf(t *testing.T) {
    srv, store := newTestServer(t)
    jwt := seedPlatformAdmin(t, srv.srv)
    // Get own ID from JWT claims
    claims := parseJWT(t, jwt)
    resp := doRequest(t, srv.srv, "DELETE",
        "/api/v1/platform/admins/"+claims["sub"].(string), nil, jwt)
    require.Equal(t, 400, resp.StatusCode)
}

func TestPlatformAdmins_RequiresAuth(t *testing.T) {
    srv, _ := newTestServer(t)
    resp := doRequest(t, srv.srv, "GET", "/api/v1/platform/admins", nil, "")
    require.Equal(t, 401, resp.StatusCode)
}
```

Run: `go test -v -run TestListPlatformAdmins ./pkg/server/`
Expected: FAIL — routes don't exist yet

- [ ] **Step 2: Create handlers_platform_admins.go**

```go
package server

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"

    "github.com/amiryahaya/triton/internal/auth"
    "github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/platform/admins
func (s *Server) handleListPlatformAdmins(w http.ResponseWriter, r *http.Request) {
    users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: "platform"})
    if err != nil {
        log.Printf("list platform admins: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, users)
}

// POST /api/v1/platform/admins
// Body: {"name": "...", "email": "..."}
func (s *Server) handleInvitePlatformAdmin(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
    var req struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    email := strings.ToLower(strings.TrimSpace(req.Email))
    name := strings.TrimSpace(req.Name)
    if email == "" || name == "" {
        writeError(w, http.StatusBadRequest, "name and email are required")
        return
    }

    tempPassword, err := auth.GenerateTempPassword(24)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    now := time.Now().UTC()
    user := &store.User{
        ID:                 uuid.Must(uuid.NewV7()).String(),
        OrgID:              "",
        Email:              email,
        Name:               name,
        Role:               "platform_admin",
        Password:           string(hashed),
        MustChangePassword: true,
        InvitedAt:          now,
        CreatedAt:          now,
        UpdatedAt:          now,
    }
    if err := s.store.CreateUser(r.Context(), user); err != nil {
        var conflict *store.ErrConflict
        if errors.As(err, &conflict) {
            writeError(w, http.StatusConflict, "email already in use")
            return
        }
        log.Printf("invite platform admin: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    if s.config.Mailer != nil {
        _ = s.config.Mailer.SendInviteEmail(r.Context(), inviteEmailData(
            email, name, "Report Portal", tempPassword, s.config.InviteLoginURL,
        ))
    }

    writeJSON(w, http.StatusCreated, map[string]string{
        "id":           user.ID,
        "tempPassword": tempPassword,
    })
}

// DELETE /api/v1/platform/admins/{id}
func (s *Server) handleDeletePlatformAdmin(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    claims := ClaimsFromContext(r.Context())
    if claims != nil && claims.Sub == id {
        writeError(w, http.StatusBadRequest, "cannot delete yourself")
        return
    }
    if err := s.store.DeleteUser(r.Context(), id); err != nil {
        var nf *store.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "admin not found")
            return
        }
        log.Printf("delete platform admin: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

Add `inviteEmailData` helper if it doesn't already exist (check `handlers_users.go` first; if a similar helper is there, reuse it):

```go
// inviteEmailData is a thin shim so both setup and admin-invite paths
// call Mailer.SendInviteEmail with the same shape.
func inviteEmailData(email, name, orgName, tempPassword, loginURL string) mailer.InviteEmailData {
    return mailer.InviteEmailData{
        ToEmail:      email,
        ToName:       name,
        OrgName:      orgName,
        TempPassword: tempPassword,
        LoginURL:     loginURL,
    }
}
```

- [ ] **Step 3: Run tests**

Run: `go build ./pkg/server/` — should compile
Full test run after route wiring in Task 11.

- [ ] **Step 4: Commit**

```bash
git add pkg/server/handlers_platform_admins.go pkg/server/handlers_platform_test.go
git commit -m "feat(server): platform admin CRUD handlers"
```

---

## Task 8: Tenant CRUD + Licence Activation Handlers

**Files:**
- Create: `pkg/server/handlers_platform_tenants.go`

- [ ] **Step 1: Write failing tests**

Add to `pkg/server/handlers_platform_test.go`:

```go
func TestCreateTenant_ValidLicence(t *testing.T) {
    // Mock licence portal
    lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.Contains(r.URL.Path, "activate") {
            w.WriteHeader(http.StatusCreated)
            json.NewEncoder(w).Encode(map[string]any{
                "token": "tok-123", "activationID": "aid",
                "tier": "enterprise", "expiresAt": "2027-01-01T00:00:00Z",
                "product_scope": "report",
            })
        }
    }))
    defer lp.Close()

    srv, _ := newTestServerWithLicencePortal(t, lp.URL)
    jwt := seedPlatformAdmin(t, srv.srv)

    body := `{"licenceKey":"lic-abc","adminName":"Bob","adminEmail":"bob@acme.com"}`
    resp := doRequest(t, srv.srv, "POST", "/api/v1/platform/tenants",
        strings.NewReader(body), jwt)
    require.Equal(t, 201, resp.StatusCode)
}

func TestCreateTenant_LicencePortalUnreachable(t *testing.T) {
    srv, _ := newTestServerWithLicencePortal(t, "http://127.0.0.1:1") // unreachable
    jwt := seedPlatformAdmin(t, srv.srv)
    body := `{"licenceKey":"lic-abc","adminName":"Bob","adminEmail":"bob@acme.com"}`
    resp := doRequest(t, srv.srv, "POST", "/api/v1/platform/tenants",
        strings.NewReader(body), jwt)
    require.Equal(t, 503, resp.StatusCode)
}

func TestListTenants_ReturnsList(t *testing.T) {
    srv, _ := newTestServer(t)
    jwt := seedPlatformAdmin(t, srv.srv)
    resp := doRequest(t, srv.srv, "GET", "/api/v1/platform/tenants", nil, jwt)
    require.Equal(t, 200, resp.StatusCode)
}
```

Run: `go test -v -run TestCreateTenant ./pkg/server/`
Expected: FAIL — routes don't exist

- [ ] **Step 2: Create handlers_platform_tenants.go**

```go
package server

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"

    "github.com/amiryahaya/triton/internal/auth"
    "github.com/amiryahaya/triton/pkg/store"
)

type tenantResponse struct {
    store.Organization
    LicenceStatus string     `json:"licenceStatus"`
    ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

// GET /api/v1/platform/tenants
func (s *Server) handleListPlatformTenants(w http.ResponseWriter, r *http.Request) {
    orgs, err := s.store.ListOrgs(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    licences, _ := s.store.ListTenantLicences(r.Context())
    licMap := map[string]store.TenantLicence{}
    for _, tl := range licences {
        licMap[tl.OrgID] = tl
    }
    out := make([]tenantResponse, 0, len(orgs))
    for _, org := range orgs {
        tr := tenantResponse{Organization: org}
        if tl, ok := licMap[org.ID]; ok {
            tr.LicenceStatus = tl.Status
            tr.ExpiresAt = &tl.ExpiresAt
        } else {
            tr.LicenceStatus = "active" // backward compat: no row = active
        }
        out = append(out, tr)
    }
    writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/platform/tenants/{id}
func (s *Server) handleGetPlatformTenant(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    org, err := s.store.GetOrg(r.Context(), id)
    if err != nil {
        var nf *store.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "tenant not found")
            return
        }
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    tr := tenantResponse{Organization: *org, LicenceStatus: "active"}
    if tl, err := s.store.GetTenantLicence(r.Context(), id); err == nil {
        tr.LicenceStatus = tl.Status
        tr.ExpiresAt = &tl.ExpiresAt
    }
    writeJSON(w, http.StatusOK, tr)
}

// POST /api/v1/platform/tenants
// Body: {"licenceKey":"...","adminName":"...","adminEmail":"..."}
func (s *Server) handleCreatePlatformTenant(w http.ResponseWriter, r *http.Request) {
    if s.licencePortalClient == nil {
        writeError(w, http.StatusServiceUnavailable, "licence server unavailable")
        return
    }

    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
    var req struct {
        LicenceKey  string `json:"licenceKey"`
        AdminName   string `json:"adminName"`
        AdminEmail  string `json:"adminEmail"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))
    if req.LicenceKey == "" || req.AdminName == "" || req.AdminEmail == "" {
        writeError(w, http.StatusBadRequest, "licenceKey, adminName, and adminEmail are required")
        return
    }

    inst, err := s.store.GetOrCreateInstance(r.Context())
    if err != nil {
        log.Printf("create tenant: get instance: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    tenantID := uuid.Must(uuid.NewV7()).String()
    machineID := inst.ID + "/" + tenantID

    activation, err := s.licencePortalClient.ActivateForTenant(req.LicenceKey, machineID)
    if err != nil {
        status, msg := classifyActivationError(err)
        writeError(w, status, msg)
        return
    }

    // Validate product scope
    if activation.ProductScope != "report" && activation.ProductScope != "bundle" && activation.ProductScope != "" {
        _ = s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID)
        writeError(w, http.StatusUnprocessableEntity, "licence not valid for Report Portal")
        return
    }

    expiresAt, _ := time.Parse(time.RFC3339, activation.ExpiresAt)
    if expiresAt.IsZero() {
        expiresAt = time.Now().Add(365 * 24 * time.Hour) // fallback
    }

    // Create org
    now := time.Now().UTC()
    org := &store.Organization{
        ID:        tenantID,
        Name:      req.AdminEmail, // name set to org email as default; admin can rename
        LicenceID: req.LicenceKey,
        CreatedAt: now,
        UpdatedAt: now,
    }
    if err := s.store.CreateOrg(r.Context(), org); err != nil {
        _ = s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID)
        log.Printf("create tenant: create org: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    // Create tenant licence record
    tl := &store.TenantLicence{
        OrgID:     tenantID,
        LicenceID: req.LicenceKey,
        Token:     activation.Token,
        ExpiresAt: expiresAt,
        Status:    "active",
    }
    if err := s.store.UpsertTenantLicence(r.Context(), tl); err != nil {
        _ = s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID)
        _ = s.store.DeleteOrg(r.Context(), tenantID)
        log.Printf("create tenant: upsert licence: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    // Create first tenant admin
    tempPassword, _ := auth.GenerateTempPassword(24)
    hashed, _ := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
    adminUser := &store.User{
        ID:                 uuid.Must(uuid.NewV7()).String(),
        OrgID:              tenantID,
        Email:              req.AdminEmail,
        Name:               req.AdminName,
        Role:               "org_admin",
        Password:           string(hashed),
        MustChangePassword: true,
        InvitedAt:          now,
        CreatedAt:          now,
        UpdatedAt:          now,
    }
    if err := s.store.CreateUser(r.Context(), adminUser); err != nil {
        _ = s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID)
        _ = s.store.DeleteTenantLicence(r.Context(), tenantID)
        _ = s.store.DeleteOrg(r.Context(), tenantID)
        log.Printf("create tenant: create admin user: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    if s.config.Mailer != nil {
        _ = s.config.Mailer.SendInviteEmail(r.Context(), inviteEmailData(
            req.AdminEmail, req.AdminName, org.Name, tempPassword, s.config.InviteLoginURL,
        ))
    }

    writeJSON(w, http.StatusCreated, tenantResponse{
        Organization:  *org,
        LicenceStatus: "active",
        ExpiresAt:     &expiresAt,
    })
}

// POST /api/v1/platform/tenants/{id}/renew
// Body: {"licenceKey": "new-uuid"}
func (s *Server) handleRenewTenantLicence(w http.ResponseWriter, r *http.Request) {
    if s.licencePortalClient == nil {
        writeError(w, http.StatusServiceUnavailable, "licence server unavailable")
        return
    }

    id := chi.URLParam(r, "id")
    var req struct {
        LicenceKey string `json:"licenceKey"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LicenceKey == "" {
        writeError(w, http.StatusBadRequest, "licenceKey is required")
        return
    }

    inst, err := s.store.GetOrCreateInstance(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    machineID := inst.ID + "/" + id

    // Activate new licence first
    activation, err := s.licencePortalClient.ActivateForTenant(req.LicenceKey, machineID)
    if err != nil {
        status, msg := classifyActivationError(err)
        writeError(w, status, msg)
        return
    }

    // Deactivate old
    oldTL, _ := s.store.GetTenantLicence(r.Context(), id)
    if oldTL != nil && oldTL.LicenceID != req.LicenceKey {
        _ = s.licencePortalClient.DeactivateForTenant(oldTL.LicenceID, machineID)
    }

    expiresAt, _ := time.Parse(time.RFC3339, activation.ExpiresAt)
    if expiresAt.IsZero() {
        expiresAt = time.Now().Add(365 * 24 * time.Hour)
    }
    now := time.Now().UTC()
    tl := &store.TenantLicence{
        OrgID:     id,
        LicenceID: req.LicenceKey,
        Token:     activation.Token,
        ExpiresAt: expiresAt,
        RenewedAt: &now,
        Status:    "active",
    }
    if err := s.store.UpsertTenantLicence(r.Context(), tl); err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    writeJSON(w, http.StatusOK, tl)
}

// DELETE /api/v1/platform/tenants/{id}
func (s *Server) handleDeletePlatformTenant(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")

    if s.licencePortalClient != nil {
        if tl, err := s.store.GetTenantLicence(r.Context(), id); err == nil {
            inst, _ := s.store.GetOrCreateInstance(r.Context())
            if inst != nil {
                _ = s.licencePortalClient.DeactivateForTenant(tl.LicenceID, inst.ID+"/"+id)
            }
        }
    }

    if err := s.store.DeleteOrg(r.Context(), id); err != nil {
        var nf *store.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "tenant not found")
            return
        }
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// classifyActivationError maps licence client errors to HTTP status + message pairs.
func classifyActivationError(err error) (int, string) {
    msg := err.Error()
    switch {
    case strings.Contains(msg, "licence not found"):
        return http.StatusNotFound, "licence not found"
    case strings.Contains(msg, "no seats available"):
        return http.StatusUnprocessableEntity, "no seats available"
    case strings.Contains(msg, "activation denied"):
        if strings.Contains(msg, "revoked") {
            return http.StatusUnprocessableEntity, "licence revoked"
        }
        if strings.Contains(msg, "expired") {
            return http.StatusUnprocessableEntity, "licence expired"
        }
        return http.StatusUnprocessableEntity, msg
    case strings.Contains(msg, "connecting"):
        return http.StatusServiceUnavailable, "licence server unavailable"
    default:
        return http.StatusServiceUnavailable, "licence server unavailable"
    }
}
```

- [ ] **Step 3: Run tests**

Run: `go build ./pkg/server/` — should compile
Full test run after route wiring in Task 11.

- [ ] **Step 4: Commit**

```bash
git add pkg/server/handlers_platform_tenants.go
git commit -m "feat(server): tenant CRUD + licence activation handlers"
```

---

## Task 9: Licence Enforcement Middleware

**Files:**
- Create: `pkg/server/licence_middleware.go`

- [ ] **Step 1: Write failing test**

Add to handlers_platform_test.go:

```go
func TestTenantLicenceGate_BlocksExpired(t *testing.T) {
    s, store := newTestServer(t)
    // Create org with expired licence
    org := &storelib.Organization{ID: uuid.Must(uuid.NewV7()).String(), Name: "Expired"}
    _ = store.CreateOrg(context.Background(), org)
    _ = store.UpsertTenantLicence(context.Background(), &storelib.TenantLicence{
        OrgID: org.ID, LicenceID: "x", Token: "t",
        ExpiresAt: time.Now().Add(-40 * 24 * time.Hour), Status: "expired",
    })
    // Login as org user and hit a data endpoint
    // ... (abbreviated: assert 403 with {"error":"licence expired"})
}

func TestTenantLicenceGate_AddsGraceHeader(t *testing.T) {
    // ... assert X-Licence-Grace: true header when status=grace
}
```

Run: `go test -v -run TestTenantLicenceGate ./pkg/server/`
Expected: FAIL — middleware not defined

- [ ] **Step 2: Create licence_middleware.go**

```go
package server

import (
    "errors"
    "net/http"

    "github.com/amiryahaya/triton/pkg/store"
)

// TenantLicenceGate enforces licence status for tenant-scoped routes.
// Must run after UnifiedAuth so TenantFromContext is populated.
//
// Missing row → pass through (backward compat: existing tenants without
// a tenant_licences row are treated as active).
// active → pass through.
// grace  → pass through + X-Licence-Grace: true header.
// expired → 403 {"error": "licence expired"}.
func (s *Server) TenantLicenceGate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tenant := TenantFromContext(r.Context())
        if tenant == nil || tenant.OrgID == "" {
            next.ServeHTTP(w, r)
            return
        }

        tl, err := s.store.GetTenantLicence(r.Context(), tenant.OrgID)
        if err != nil {
            var nf *store.ErrNotFound
            if errors.As(err, &nf) {
                // No licence row — allow (backward compat).
                next.ServeHTTP(w, r)
                return
            }
            // DB error: fail open to avoid blocking legitimate users.
            next.ServeHTTP(w, r)
            return
        }

        switch tl.Status {
        case "expired":
            writeError(w, http.StatusForbidden, "licence expired")
        case "grace":
            w.Header().Set("X-Licence-Grace", "true")
            next.ServeHTTP(w, r)
        default:
            next.ServeHTTP(w, r)
        }
    })
}
```

- [ ] **Step 3: Run test**

Run: `go build ./pkg/server/`
Expected: compiles cleanly

- [ ] **Step 4: Commit**

```bash
git add pkg/server/licence_middleware.go
git commit -m "feat(server): TenantLicenceGate enforcement middleware"
```

---

## Task 10: Background Licence Validator

**Files:**
- Create: `pkg/server/licence_validator.go`

- [ ] **Step 1: Write failing test**

```go
// pkg/server/licence_validator_test.go
package server

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "github.com/amiryahaya/triton/pkg/store"
)

func TestComputeLicenceStatus_Active(t *testing.T) {
    status := computeLicenceStatus(time.Now().Add(60 * 24 * time.Hour))
    require.Equal(t, "active", status)
}

func TestComputeLicenceStatus_Grace(t *testing.T) {
    status := computeLicenceStatus(time.Now().Add(-5 * 24 * time.Hour))
    require.Equal(t, "grace", status)
}

func TestComputeLicenceStatus_Expired(t *testing.T) {
    status := computeLicenceStatus(time.Now().Add(-35 * 24 * time.Hour))
    require.Equal(t, "expired", status)
}
```

Run: `go test -v -run TestComputeLicenceStatus ./pkg/server/`
Expected: FAIL — function not defined

- [ ] **Step 2: Create licence_validator.go**

```go
package server

import (
    "context"
    "log"
    "time"
)

const (
    licenceValidatorInterval = 24 * time.Hour
    licenceGracePeriod       = 30 * 24 * time.Hour // 30 days grace after expiry
    licenceWarnBefore        = 14 * 24 * time.Hour // warn banner 14 days before expiry
)

// startLicenceValidator launches a goroutine that validates all tenant
// licences every 24 hours. It stops when ctx is cancelled (Server.Shutdown).
func (s *Server) startLicenceValidator(ctx context.Context) {
    if s.licencePortalClient == nil {
        return // no licence portal configured — skip
    }
    go func() {
        ticker := time.NewTicker(licenceValidatorInterval)
        defer ticker.Stop()
        // Run once immediately on startup
        s.runLicenceValidation(ctx)
        for {
            select {
            case <-ticker.C:
                s.runLicenceValidation(ctx)
            case <-ctx.Done():
                return
            }
        }
    }()
}

func (s *Server) runLicenceValidation(ctx context.Context) {
    licences, err := s.store.ListTenantLicences(ctx)
    if err != nil {
        log.Printf("licence validator: list licences: %v", err)
        return
    }

    inst, err := s.store.GetOrCreateInstance(ctx)
    if err != nil {
        log.Printf("licence validator: get instance: %v", err)
        return
    }

    for _, tl := range licences {
        if tl.Status == "expired" {
            continue // already expired — no point validating
        }

        machineID := inst.ID + "/" + tl.OrgID
        resp, err := s.licencePortalClient.ValidateForTenant(tl.LicenceID, tl.Token, machineID)
        if err != nil {
            // Licence Portal unreachable — rely on cached expires_at.
            log.Printf("licence validator: validate %s: %v (using cached expires_at)", tl.OrgID, err)
        } else if resp.Valid {
            // Update token + expires_at from server response.
            expiresAt, _ := time.Parse(time.RFC3339, resp.ExpiresAt)
            if !expiresAt.IsZero() {
                tl.ExpiresAt = expiresAt
            }
            now := time.Now().UTC()
            tl.RenewedAt = &now
            tl.Token = tl.Token // token unchanged unless server sends new one
        }

        tl.Status = computeLicenceStatus(tl.ExpiresAt)
        if err := s.store.UpsertTenantLicence(ctx, &tl); err != nil {
            log.Printf("licence validator: upsert %s: %v", tl.OrgID, err)
        }
    }
}

// computeLicenceStatus derives the licence status from the expiry time.
// active  — expires_at is in the future.
// grace   — expired within the last 30 days.
// expired — expired more than 30 days ago.
func computeLicenceStatus(expiresAt time.Time) string {
    now := time.Now().UTC()
    if expiresAt.After(now) {
        return "active"
    }
    if now.Sub(expiresAt) <= licenceGracePeriod {
        return "grace"
    }
    return "expired"
}
```

- [ ] **Step 3: Run test**

Run: `go test -v -run TestComputeLicenceStatus ./pkg/server/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/server/licence_validator.go pkg/server/licence_validator_test.go
git commit -m "feat(server): background licence validator goroutine"
```

---

## Task 11: Route Wiring in server.go

**Files:**
- Modify: `pkg/server/server.go`

- [ ] **Step 1: Write failing test**

```go
// pkg/server/handlers_setup_test.go
func TestSetupRouteExists(t *testing.T) {
    srv := newIntegrationTestServer(t)
    resp, _ := http.Get(srv.URL + "/api/v1/setup/status")
    require.Equal(t, 200, resp.StatusCode)
}
```

Run: `go test -v -run TestSetupRouteExists ./pkg/server/`
Expected: FAIL — route returns 404

- [ ] **Step 2: Add setup routes (always registered)**

In `server.go` `New()`, after building the chi router and before returning, add:

```go
// Setup endpoints — always registered, no auth.
r.Get("/api/v1/setup/status", srv.handleSetupStatus)
r.Post("/api/v1/setup", srv.handleFirstSetup)
```

- [ ] **Step 3: Add platform admin + tenant routes (require JWT)**

Inside the `if cfg.JWTSigningKey != nil` block, add a new route group:

```go
// Platform admin routes — require platform_admin JWT.
r.Route("/api/v1/platform", func(r chi.Router) {
    r.Use(JWTAuth(cfg.JWTPublicKey, s, srv.sessionCache))
    r.Use(BlockUntilPasswordChanged)
    r.Use(RequirePlatformAdmin)

    r.Get("/admins",          srv.handleListPlatformAdmins)
    r.Post("/admins",         srv.handleInvitePlatformAdmin)
    r.Delete("/admins/{id}",  srv.handleDeletePlatformAdmin)

    r.Get("/tenants",              srv.handleListPlatformTenants)
    r.Post("/tenants",             srv.handleCreatePlatformTenant)
    r.Get("/tenants/{id}",         srv.handleGetPlatformTenant)
    r.Post("/tenants/{id}/renew",  srv.handleRenewTenantLicence)
    r.Delete("/tenants/{id}",      srv.handleDeletePlatformTenant)
})
```

- [ ] **Step 4: Add TenantLicenceGate to the main API route group**

Inside `r.Route("/api/v1", ...)`, after `r.Use(RequestRateLimit(...))`:

```go
r.Use(srv.TenantLicenceGate)
```

- [ ] **Step 5: Start validator in New() after building srv**

```go
srv.startLicenceValidator(ctx)
```

- [ ] **Step 6: Run all tests**

Run: `go test -v ./pkg/server/ -count=1`
Expected: all tests pass (integration tests need -tags integration)

Run: `go build ./...`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add pkg/server/server.go
git commit -m "feat(server): wire setup + platform admin + tenant routes + licence gate + validator"
```

---

## Task 12: Integration Tests

**Files:**
- Create: `pkg/server/handlers_setup_test.go` (full version)
- Create: `pkg/server/handlers_platform_licence_test.go`

- [ ] **Step 1: Write full setup integration tests**

```go
// +build integration

package server_test

func TestSetup_FirstAdmin(t *testing.T) {
    ts := newIntegrationServer(t)
    
    // Status shows needsSetup
    resp := tsGET(t, ts, "/api/v1/setup/status")
    require.Equal(t, 200, resp.StatusCode)
    var status map[string]bool
    parseJSON(t, resp, &status)
    require.True(t, status["needsSetup"])
    
    // Create first admin
    resp = tsPOST(t, ts, "/api/v1/setup",
        `{"name":"Alice","email":"alice@example.com"}`, "")
    require.Equal(t, 201, resp.StatusCode)
    var created map[string]string
    parseJSON(t, resp, &created)
    require.NotEmpty(t, created["id"])
    require.NotEmpty(t, created["tempPassword"])
    
    // Second call is 409
    resp = tsPOST(t, ts, "/api/v1/setup",
        `{"name":"Bob","email":"bob@example.com"}`, "")
    require.Equal(t, 409, resp.StatusCode)
    
    // Status now shows ready
    resp = tsGET(t, ts, "/api/v1/setup/status")
    parseJSON(t, resp, &status)
    require.False(t, status["needsSetup"])
}

func TestLogin_PlatformAdmin(t *testing.T) {
    ts := newIntegrationServer(t)
    tempPw := createFirstAdmin(t, ts)
    
    resp := tsPOST(t, ts, "/api/v1/auth/login",
        fmt.Sprintf(`{"email":"alice@example.com","password":%q}`, tempPw), "")
    require.Equal(t, 200, resp.StatusCode)
    var body map[string]any
    parseJSON(t, resp, &body)
    token := body["token"].(string)
    claims := parseJWTClaims(t, token)
    require.Equal(t, "platform_admin", claims["role"])
    require.Empty(t, claims["org"])     // no org for platform admin
    require.True(t, claims["mcp"].(bool)) // must change password
}

func TestChangePassword_ClearsFlag(t *testing.T) {
    ts := newIntegrationServer(t)
    tempPw := createFirstAdmin(t, ts)
    jwt := loginAs(t, ts, "alice@example.com", tempPw)
    
    resp := tsPOST(t, ts, "/api/v1/auth/change-password",
        fmt.Sprintf(`{"current_password":%q,"new_password":"NewPassword123!"}`, tempPw), jwt)
    require.Equal(t, 200, resp.StatusCode)
    
    // New JWT does not have mcp flag
    var body map[string]any
    parseJSON(t, resp, &body)
    claims := parseJWTClaims(t, body["token"].(string))
    mcp, _ := claims["mcp"].(bool)
    require.False(t, mcp)
}

func TestCreateTenant_ValidLicence(t *testing.T) {
    lp := mockLicencePortal(t, "report") // returns product_scope=report
    ts := newIntegrationServerWithLP(t, lp.URL)
    jwt := adminJWT(t, ts)
    
    resp := tsPOST(t, ts, "/api/v1/platform/tenants",
        `{"licenceKey":"lic-001","adminName":"Bob","adminEmail":"bob@acme.com"}`, jwt)
    require.Equal(t, 201, resp.StatusCode)
    var org map[string]any
    parseJSON(t, resp, &org)
    require.NotEmpty(t, org["id"])
    require.Equal(t, "active", org["licenceStatus"])
}

func TestCreateTenant_WrongProductScope(t *testing.T) {
    lp := mockLicencePortal(t, "manage") // wrong scope
    ts := newIntegrationServerWithLP(t, lp.URL)
    jwt := adminJWT(t, ts)
    
    resp := tsPOST(t, ts, "/api/v1/platform/tenants",
        `{"licenceKey":"lic-001","adminName":"Bob","adminEmail":"bob@acme.com"}`, jwt)
    require.Equal(t, 422, resp.StatusCode)
}

func TestLicenceExpiry_GraceEnforcement(t *testing.T) {
    ts := newIntegrationServer(t)
    // Create org with grace licence (expired recently)
    org := seedOrg(t, ts, "active")
    setLicenceStatus(t, ts, org.ID, "grace", time.Now().Add(-5*24*time.Hour))
    
    // GET /api/v1/scans still works but has grace header
    jwt := orgAdminJWT(t, ts, org.ID)
    resp := tsGET_auth(t, ts, "/api/v1/scans", jwt)
    require.Equal(t, 200, resp.StatusCode)
    require.Equal(t, "true", resp.Header.Get("X-Licence-Grace"))
}

func TestLicenceExpiry_HardExpired(t *testing.T) {
    ts := newIntegrationServer(t)
    org := seedOrg(t, ts, "expired")
    jwt := orgAdminJWT(t, ts, org.ID)
    
    resp := tsGET_auth(t, ts, "/api/v1/scans", jwt)
    require.Equal(t, 403, resp.StatusCode)
}
```

- [ ] **Step 2: Run integration tests**

Run: `go test -v -tags integration -run TestSetup ./pkg/server/`
Expected: PASS

Run: `go test -v -tags integration -run TestCreateTenant ./pkg/server/`
Expected: PASS

Run: `go test -v -tags integration -run TestLicenceExpiry ./pkg/server/`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/server/handlers_setup_test.go pkg/server/handlers_platform_licence_test.go
git commit -m "test(server): setup + platform admin + tenant licence integration tests"
```

---

## Task 13: Frontend — Router, Nav, and App.vue Setup Guard

**Files:**
- Modify: `web/apps/report-portal/src/router.ts`
- Modify: `web/apps/report-portal/src/nav.ts`
- Modify: `web/apps/report-portal/src/App.vue`

- [ ] **Step 1: Write failing Vitest test for setup guard**

Create `web/apps/report-portal/tests/App.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHashHistory } from 'vue-router';
import { createTestingPinia } from '@pinia/testing';

describe('App setup guard', () => {
  it('redirects to /setup when needsSetup is true', async () => {
    const client = { setupStatus: vi.fn().mockResolvedValue({ needsSetup: true }) };
    // ... mount App with mocked client, assert router navigates to /setup
    expect(client.setupStatus).toHaveBeenCalled();
  });

  it('does not redirect when needsSetup is false', async () => {
    const client = { setupStatus: vi.fn().mockResolvedValue({ needsSetup: false }) };
    // ... mount App, assert current route is not /setup
    expect(client.setupStatus).toHaveBeenCalled();
  });
});
```

Run: `cd web && pnpm --filter report-portal test --run`
Expected: FAIL — no setupStatus method on client

- [ ] **Step 2: Add setup routes to router.ts**

```ts
const routes: RouteRecordRaw[] = [
  // --- existing routes ---
  { path: '/', name: 'overview', component: () => import('./views/Overview.vue') },
  // ... all existing routes ...

  // --- new platform routes ---
  { path: '/setup',                  name: 'setup',          component: () => import('./views/Setup.vue'),           meta: { public: true } },
  { path: '/change-password',        name: 'change-password', component: () => import('./views/ChangePassword.vue'), meta: { public: true } },
  { path: '/platform/admins',        name: 'platform-admins', component: () => import('./views/PlatformAdmins.vue') },
  { path: '/platform/tenants',       name: 'platform-tenants', component: () => import('./views/Tenants.vue') },
  { path: '/platform/tenants/:id',   name: 'platform-tenant-detail', component: () => import('./views/TenantDetail.vue') },
  { path: '/:pathMatch(.*)*',        redirect: '/' },
];
```

Also add a router navigation guard for the change-password interstitial:

```ts
router.beforeEach((to) => {
  const auth = useAuthStore();
  if (auth.claims?.mcp && to.name !== 'change-password') {
    return { name: 'change-password' };
  }
});
```

- [ ] **Step 3: Add Platform section to nav.ts**

```ts
{
  label: 'Platform',
  items: [
    { href: '#/platform/admins',  label: 'Platform Admins' },
    { href: '#/platform/tenants', label: 'Tenants' },
  ],
},
```

- [ ] **Step 4: Add setup guard to App.vue**

In `App.vue` `<script setup>`, add:

```ts
import { onMounted } from 'vue';

onMounted(async () => {
  try {
    const status = await api.client.setupStatus();
    if (status.needsSetup && router.currentRoute.value.name !== 'setup') {
      await router.replace({ name: 'setup' });
    }
  } catch {
    // Unreachable API — proceed normally (setup page will handle errors)
  }
});
```

Also add the `mustChangePassword` interstitial watch:

```ts
watch(() => auth.claims?.mcp, (mcp) => {
  if (mcp && router.currentRoute.value.name !== 'change-password') {
    router.push({ name: 'change-password' });
  }
});
```

- [ ] **Step 5: Add setupStatus to API client**

In `web/apps/report-portal/src/stores/apiClient.ts` (or wherever the API client is defined), add:

```ts
async setupStatus(): Promise<{ needsSetup: boolean }> {
  const resp = await this.get<{ needsSetup: boolean }>('/api/v1/setup/status');
  return resp;
},

async firstSetup(name: string, email: string): Promise<{ id: string; tempPassword: string }> {
  return this.post('/api/v1/setup', { name, email });
},
```

- [ ] **Step 6: Run tests**

Run: `cd web && pnpm --filter report-portal test --run`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add web/apps/report-portal/src/router.ts web/apps/report-portal/src/nav.ts
git add web/apps/report-portal/src/App.vue web/apps/report-portal/src/stores/apiClient.ts
git add web/apps/report-portal/tests/App.spec.ts
git commit -m "feat(report-portal): setup guard + platform routes + nav section"
```

---

## Task 14: Frontend — Setup.vue

**Files:**
- Create: `web/apps/report-portal/src/views/Setup.vue`

- [ ] **Step 1: Write failing test**

Create `web/apps/report-portal/tests/views/Setup.spec.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import Setup from '../../src/views/Setup.vue';

describe('Setup.vue', () => {
  it('shows form fields for name and email', () => {
    const wrapper = mount(Setup, {
      global: { stubs: { teleport: true } },
    });
    expect(wrapper.find('input[name="name"]').exists()).toBe(true);
    expect(wrapper.find('input[name="email"]').exists()).toBe(true);
  });

  it('calls firstSetup and redirects on success', async () => {
    const mockSetup = vi.fn().mockResolvedValue({ id: '1', tempPassword: 'p' });
    const wrapper = mount(Setup, {
      global: {
        provide: { apiClient: { firstSetup: mockSetup } },
        stubs: { teleport: true },
      },
    });
    await wrapper.find('input[name="name"]').setValue('Alice');
    await wrapper.find('input[name="email"]').setValue('alice@example.com');
    await wrapper.find('form').trigger('submit');
    await nextTick();
    expect(mockSetup).toHaveBeenCalledWith('Alice', 'alice@example.com');
  });
});
```

Run: `cd web && pnpm --filter report-portal test --run`
Expected: FAIL — Setup.vue doesn't exist

- [ ] **Step 2: Create Setup.vue**

```vue
<template>
  <div class="setup-page">
    <div class="setup-card">
      <h1>Welcome to Report Portal</h1>
      <p>Create the first platform administrator to get started.</p>
      <form @submit.prevent="submit">
        <label>
          Name
          <input name="name" v-model="form.name" type="text" required />
        </label>
        <label>
          Email
          <input name="email" v-model="form.email" type="email" required />
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <p v-if="done" class="success">
          Admin created. A temporary password was sent to {{ form.email }}.
          Please check your inbox and <a href="#/login">log in</a>.
        </p>
        <button type="submit" :disabled="loading">
          {{ loading ? 'Creating…' : 'Create admin account' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const form = reactive({ name: '', email: '' });
const loading = ref(false);
const error = ref('');
const done = ref(false);

async function submit() {
  loading.value = true;
  error.value = '';
  try {
    await api.client.firstSetup(form.name, form.email);
    done.value = true;
  } catch (e: any) {
    error.value = e?.message ?? 'Setup failed';
  } finally {
    loading.value = false;
  }
}
</script>
```

- [ ] **Step 3: Run tests**

Run: `cd web && pnpm --filter report-portal test --run`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add web/apps/report-portal/src/views/Setup.vue
git add web/apps/report-portal/tests/views/Setup.spec.ts
git commit -m "feat(report-portal): Setup.vue — first platform admin creation wizard"
```

---

## Task 15: Frontend — PlatformAdmins.vue + Tenants.vue + TenantDetail.vue

**Files:**
- Create: `web/apps/report-portal/src/views/PlatformAdmins.vue`
- Modify: `web/apps/report-portal/src/views/Tenants.vue` (implement existing stub)
- Create: `web/apps/report-portal/src/views/TenantDetail.vue`

- [ ] **Step 1: Write failing tests**

Create `web/apps/report-portal/tests/views/PlatformAdmins.spec.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import PlatformAdmins from '../../src/views/PlatformAdmins.vue';

const ADMINS = [
  { id: '1', name: 'Alice', email: 'alice@example.com', role: 'platform_admin' },
];

describe('PlatformAdmins.vue', () => {
  function makeMockClient() {
    return {
      listPlatformAdmins: vi.fn().mockResolvedValue(ADMINS),
      invitePlatformAdmin: vi.fn().mockResolvedValue({ id: '2', tempPassword: 'p' }),
      deletePlatformAdmin: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('renders admin list', async () => {
    const client = makeMockClient();
    const wrapper = mount(PlatformAdmins, {
      global: { provide: { apiClient: client }, plugins: [createTestingPinia()] },
    });
    await flushPromises();
    expect(wrapper.text()).toContain('Alice');
  });

  it('invite calls invitePlatformAdmin', async () => {
    const client = makeMockClient();
    const wrapper = mount(PlatformAdmins, {
      global: { provide: { apiClient: client }, plugins: [createTestingPinia()] },
    });
    await flushPromises();
    // Open invite modal, fill form, submit
    await wrapper.find('[data-testid="invite-btn"]').trigger('click');
    await wrapper.find('input[name="name"]').setValue('Bob');
    await wrapper.find('input[name="email"]').setValue('bob@example.com');
    await wrapper.find('[data-testid="invite-form"]').trigger('submit');
    await flushPromises();
    expect(client.invitePlatformAdmin).toHaveBeenCalledWith('Bob', 'bob@example.com');
  });

  it('cannot delete self', async () => {
    // ID '1' is the logged-in user
    const client = makeMockClient();
    // ... verify delete button is disabled for own ID
  });
});
```

Create `web/apps/report-portal/tests/views/Tenants.spec.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Tenants from '../../src/views/Tenants.vue';

const TENANTS = [
  { id: 't1', name: 'Acme', licenceStatus: 'active', expiresAt: '2027-01-01T00:00:00Z' },
  { id: 't2', name: 'Beta', licenceStatus: 'grace',  expiresAt: '2026-01-01T00:00:00Z' },
  { id: 't3', name: 'Gamma', licenceStatus: 'expired', expiresAt: '2025-01-01T00:00:00Z' },
];

describe('Tenants.vue', () => {
  it('renders tenants with status badges', async () => {
    const client = { listPlatformTenants: vi.fn().mockResolvedValue(TENANTS) };
    const wrapper = mount(Tenants, {
      global: { provide: { apiClient: client }, plugins: [createTestingPinia()] },
    });
    await flushPromises();
    expect(wrapper.text()).toContain('Acme');
    expect(wrapper.find('[data-testid="badge-active"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="badge-grace"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="badge-expired"]').exists()).toBe(true);
  });
});
```

Run: `cd web && pnpm --filter report-portal test --run`
Expected: FAIL — views not implemented

- [ ] **Step 2: Implement PlatformAdmins.vue**

```vue
<template>
  <div>
    <h1>Platform Administrators</h1>
    <button data-testid="invite-btn" @click="showInvite = true">Invite admin</button>
    <table>
      <thead>
        <tr><th>Name</th><th>Email</th><th>Actions</th></tr>
      </thead>
      <tbody>
        <tr v-for="admin in admins" :key="admin.id">
          <td>{{ admin.name }}</td>
          <td>{{ admin.email }}</td>
          <td>
            <button
              :disabled="admin.id === auth.claims?.sub"
              @click="deleteAdmin(admin.id)"
            >
              Remove
            </button>
          </td>
        </tr>
      </tbody>
    </table>

    <!-- Invite modal -->
    <dialog v-if="showInvite">
      <form data-testid="invite-form" @submit.prevent="invite">
        <input name="name" v-model="form.name" placeholder="Name" required />
        <input name="email" v-model="form.email" type="email" placeholder="Email" required />
        <button type="submit">Send invite</button>
        <button type="button" @click="showInvite = false">Cancel</button>
      </form>
    </dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const api = useApiClient();
const auth = useAuthStore();
const admins = ref<any[]>([]);
const showInvite = ref(false);
const form = reactive({ name: '', email: '' });

onMounted(async () => {
  admins.value = await api.client.listPlatformAdmins();
});

async function invite() {
  await api.client.invitePlatformAdmin(form.name, form.email);
  showInvite.value = false;
  admins.value = await api.client.listPlatformAdmins();
}

async function deleteAdmin(id: string) {
  await api.client.deletePlatformAdmin(id);
  admins.value = await api.client.listPlatformAdmins();
}
</script>
```

- [ ] **Step 3: Implement Tenants.vue (replace stub)**

```vue
<template>
  <div>
    <h1>Tenants</h1>
    <button @click="showCreate = true">Add tenant</button>
    <table>
      <thead>
        <tr><th>Name</th><th>Licence</th><th>Expires</th><th>Actions</th></tr>
      </thead>
      <tbody>
        <tr v-for="tenant in tenants" :key="tenant.id">
          <td>{{ tenant.name }}</td>
          <td>
            <span
              :data-testid="`badge-${tenant.licenceStatus}`"
              :class="`badge badge--${tenant.licenceStatus}`"
            >
              {{ tenant.licenceStatus }}
            </span>
          </td>
          <td>{{ tenant.expiresAt ? new Date(tenant.expiresAt).toLocaleDateString() : '—' }}</td>
          <td><router-link :to="`/platform/tenants/${tenant.id}`">Details</router-link></td>
        </tr>
      </tbody>
    </table>

    <!-- Create tenant modal -->
    <dialog v-if="showCreate">
      <form @submit.prevent="createTenant">
        <input v-model="form.licenceKey" placeholder="Licence key" required />
        <input v-model="form.adminName" placeholder="Admin name" required />
        <input v-model="form.adminEmail" type="email" placeholder="Admin email" required />
        <p v-if="createError" class="error">{{ createError }}</p>
        <button type="submit" :disabled="creating">
          {{ creating ? 'Activating…' : 'Create tenant' }}
        </button>
        <button type="button" @click="showCreate = false">Cancel</button>
      </form>
    </dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const tenants = ref<any[]>([]);
const showCreate = ref(false);
const creating = ref(false);
const createError = ref('');
const form = reactive({ licenceKey: '', adminName: '', adminEmail: '' });

onMounted(async () => {
  tenants.value = await api.client.listPlatformTenants();
});

async function createTenant() {
  creating.value = true;
  createError.value = '';
  try {
    await api.client.createPlatformTenant(form);
    showCreate.value = false;
    tenants.value = await api.client.listPlatformTenants();
  } catch (e: any) {
    createError.value = e?.message ?? 'Failed to create tenant';
  } finally {
    creating.value = false;
  }
}
</script>
```

- [ ] **Step 4: Create TenantDetail.vue**

```vue
<template>
  <div v-if="tenant">
    <h1>{{ tenant.name }}</h1>
    <dl>
      <dt>Licence status</dt>
      <dd :class="`badge badge--${tenant.licenceStatus}`">{{ tenant.licenceStatus }}</dd>
      <dt>Expires</dt>
      <dd>{{ tenant.expiresAt ? new Date(tenant.expiresAt).toLocaleDateString() : '—' }}</dd>
      <dt>Licence key</dt>
      <dd>{{ tenant.licenceId }}</dd>
    </dl>

    <button @click="showRenew = true">Renew licence</button>
    <router-link to="/platform/tenants">Back</router-link>

    <dialog v-if="showRenew">
      <form @submit.prevent="renew">
        <input v-model="newKey" placeholder="New licence key" required />
        <button type="submit" :disabled="renewing">
          {{ renewing ? 'Renewing…' : 'Renew' }}
        </button>
        <button type="button" @click="showRenew = false">Cancel</button>
      </form>
    </dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useApiClient } from '../stores/apiClient';

const route = useRoute();
const api = useApiClient();
const tenant = ref<any>(null);
const showRenew = ref(false);
const renewing = ref(false);
const newKey = ref('');

onMounted(async () => {
  tenant.value = await api.client.getPlatformTenant(route.params.id as string);
});

async function renew() {
  renewing.value = true;
  try {
    tenant.value = await api.client.renewTenantLicence(route.params.id as string, newKey.value);
    showRenew.value = false;
  } finally {
    renewing.value = false;
  }
}
</script>
```

- [ ] **Step 5: Add platform tenant API methods to apiClient.ts**

```ts
async listPlatformAdmins(): Promise<any[]> {
  return this.get('/api/v1/platform/admins');
},
async invitePlatformAdmin(name: string, email: string): Promise<any> {
  return this.post('/api/v1/platform/admins', { name, email });
},
async deletePlatformAdmin(id: string): Promise<void> {
  return this.delete(`/api/v1/platform/admins/${id}`);
},
async listPlatformTenants(): Promise<any[]> {
  return this.get('/api/v1/platform/tenants');
},
async createPlatformTenant(body: {licenceKey: string; adminName: string; adminEmail: string}): Promise<any> {
  return this.post('/api/v1/platform/tenants', body);
},
async getPlatformTenant(id: string): Promise<any> {
  return this.get(`/api/v1/platform/tenants/${id}`);
},
async renewTenantLicence(id: string, licenceKey: string): Promise<any> {
  return this.post(`/api/v1/platform/tenants/${id}/renew`, { licenceKey });
},
```

- [ ] **Step 6: Run all frontend tests**

Run: `cd web && pnpm --filter report-portal test --run`
Expected: all tests pass

Run: `cd web && pnpm --filter report-portal build`
Expected: builds successfully

- [ ] **Step 7: Commit**

```bash
git add web/apps/report-portal/src/views/PlatformAdmins.vue
git add web/apps/report-portal/src/views/Tenants.vue
git add web/apps/report-portal/src/views/TenantDetail.vue
git add web/apps/report-portal/src/stores/apiClient.ts
git add web/apps/report-portal/tests/views/PlatformAdmins.spec.ts
git add web/apps/report-portal/tests/views/Tenants.spec.ts
git commit -m "feat(report-portal): PlatformAdmins + Tenants + TenantDetail views"
```

---

## Self-Review Checklist

After completing all tasks, verify spec coverage:

| Spec requirement | Task |
|-----------------|------|
| Setup guard — redirect to /setup until platform_admin exists | Task 6, 13 |
| GET /api/v1/setup/status | Task 6, 11 |
| POST /api/v1/setup (first admin creation) | Task 6, 11 |
| Platform admin CRUD | Task 7, 11 |
| Cannot delete self | Task 7 |
| Tenant creation with licence activation | Task 8 |
| machineID = instanceID + "/" + tenantID | Task 4, 8 |
| product_scope validation | Task 8 |
| All-or-nothing (deactivate on failure) | Task 8 |
| Error responses (404/422/503) | Task 8 |
| GET/POST/DELETE /api/v1/platform/tenants/* | Task 8, 11 |
| Tenant licence renewal | Task 8 |
| Background validator (24h) | Task 10, 11 |
| status: active / grace / expired | Task 10 |
| Enforcement middleware | Task 9, 11 |
| X-Licence-Grace header | Task 9 |
| Missing row = active (backward compat) | Task 9 |
| JWT mustChangePassword flag | Existing (auth.UserClaims already has mcp) |
| Setup.vue | Task 14 |
| PlatformAdmins.vue | Task 15 |
| Tenants.vue with status badges | Task 15 |
| TenantDetail.vue with renew button | Task 15 |
| App.vue setup guard | Task 13 |
| Change-password interstitial | Task 13 |
| Integration tests from spec | Task 12 |
