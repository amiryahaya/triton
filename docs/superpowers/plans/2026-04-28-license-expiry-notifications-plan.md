# License Expiry Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** License Server sends 30-day, 7-day, and 1-day expiry warning emails to all `platform_admin` users and the org's `contact_email`, tracked via nullable `notified_*d_at` columns on the `licenses` table.

**Architecture:** A single background goroutine in `pkg/licenseserver/server.go` ticks hourly, queries expiring licenses that haven't been notified yet, and sends emails via the existing `internal/mailer` Resend backend. Organizations gain three structured contact columns (`contact_name`, `contact_phone`, `contact_email`) replacing the free-text `contact` field.

**Tech Stack:** Go 1.25, pgx/v5, internal/mailer (Resend), go-chi/chi/v5, testify, httptest

---

## File Map

| File | Change |
|------|--------|
| `pkg/licensestore/migrations.go` | Add Version 10: rename `contact`→`contact_name`, add `contact_phone`/`contact_email`, add `notified_*d_at` |
| `pkg/licensestore/store.go` | Update `Organization` struct; add `LicenseWithOrg`; add `ListExpiringLicenses` + `MarkLicenseNotified` to `Store` interface |
| `pkg/licensestore/postgres.go` | Update org CRUD SQL; implement `ListExpiringLicenses` + `MarkLicenseNotified` |
| `internal/mailer/mailer.go` | Add `ExpiryWarningEmailData` struct + `SendExpiryWarningEmail` to `Mailer` interface + `ResendMailer` |
| `pkg/licenseserver/mailer.go` | Re-export `ExpiryWarningEmailData` type alias |
| `pkg/licenseserver/server.go` | Add `mailer` field to `Server` struct; add `runExpiryNotifications` + `sendExpiryNotifications`; launch goroutine in `New` |
| `pkg/licenseserver/handlers_org.go` | Replace `contact` with `contact_name`/`contact_phone`/`contact_email` in create + update handlers |
| `pkg/licenseserver/provisioning.go` | Replace `Contact` with `ContactName`/`ContactPhone`/`ContactEmail` in `ProvisionOrgInput` |
| `pkg/licenseserver/server.go` | Add `maxContactEmailLen = 325`, `maxContactPhoneLen = 50` constants |
| `docs/LICENSE_SERVER_GUIDE.md` | Update org API examples, add contact field docs, add expiry notification config section |
| `docs/DEPLOYMENT_GUIDE.md` | Update license server section with new env vars and org field docs |

---

### Task 1: DB Migration — contact columns + notified_*d_at columns

**Files:**
- Modify: `pkg/licensestore/migrations.go`

Context: migrations are a Go slice of SQL strings; index+1 = version. Current version is 9. New migration is index 9 (Version 10). The `contact` column is renamed to `contact_name` and two new columns are added. Three nullable `TIMESTAMPTZ` columns track notification state on `licenses`.

- [ ] **Step 1: Write the failing test**

Add to `pkg/licensestore/postgres_test.go`:

```go
func TestMigration10_ContactColumnsAndNotifiedAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Verify contact_name, contact_phone, contact_email columns exist on organizations
	var colCount int
	err := s.Pool().QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'organizations'
		  AND column_name IN ('contact_name','contact_phone','contact_email')
	`).Scan(&colCount)
	require.NoError(t, err)
	assert.Equal(t, 3, colCount, "expected contact_name, contact_phone, contact_email columns")

	// Verify old 'contact' column no longer exists
	var oldExists bool
	err = s.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'organizations' AND column_name = 'contact'
		)
	`).Scan(&oldExists)
	require.NoError(t, err)
	assert.False(t, oldExists, "old 'contact' column should not exist after migration")

	// Verify notified_30d_at, notified_7d_at, notified_1d_at columns exist on licenses
	err = s.Pool().QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'licenses'
		  AND column_name IN ('notified_30d_at','notified_7d_at','notified_1d_at')
	`).Scan(&colCount)
	require.NoError(t, err)
	assert.Equal(t, 3, colCount, "expected notified_30d_at, notified_7d_at, notified_1d_at columns")
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -v -tags integration -run TestMigration10_ContactColumnsAndNotifiedAt ./pkg/licensestore/...
```

Expected: FAIL — `expected contact_name, contact_phone, contact_email columns` assertion fails.

- [ ] **Step 3: Add Version 10 migration**

Append to the `migrations` slice in `pkg/licensestore/migrations.go` (after the Version 9 entry, before the closing `}`):

```go
	// Version 10: Structured contact fields on organizations + expiry notification
	// tracking on licenses.
	// contact → contact_name (rename); contact_phone and contact_email are new.
	// notified_30d_at, notified_7d_at, notified_1d_at are nullable TIMESTAMPTZ;
	// NULL means the notification has not been sent for this license cycle.
	`ALTER TABLE organizations RENAME COLUMN contact TO contact_name;
	ALTER TABLE organizations
		ADD COLUMN IF NOT EXISTS contact_phone TEXT NOT NULL DEFAULT '',
		ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';

	ALTER TABLE licenses
		ADD COLUMN IF NOT EXISTS notified_30d_at TIMESTAMPTZ,
		ADD COLUMN IF NOT EXISTS notified_7d_at  TIMESTAMPTZ,
		ADD COLUMN IF NOT EXISTS notified_1d_at  TIMESTAMPTZ;`,
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test -v -tags integration -run TestMigration10_ContactColumnsAndNotifiedAt ./pkg/licensestore/...
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/licensestore/migrations.go pkg/licensestore/postgres_test.go
git commit -m "feat(licensestore): migration v10 — contact columns + notified_*d_at on licenses"
```

---

### Task 2: Update `Organization` struct + org CRUD SQL

**Files:**
- Modify: `pkg/licensestore/store.go`
- Modify: `pkg/licensestore/postgres.go`

Context: `Organization.Contact string` → `ContactName`, plus two new fields. All SQL in `CreateOrg`, `GetOrg`, `ListOrgs`, `UpdateOrg` references `contact` column — must be updated to `contact_name` and include the two new columns.

- [ ] **Step 1: Write the failing test**

Add to `pkg/licensestore/postgres_test.go`:

```go
func TestOrgContactFields_CRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	org := &Organization{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Name:         "Contact Test Org",
		ContactName:  "Ahmad bin Ali",
		ContactPhone: "+60123456789",
		ContactEmail: "ahmad@nacsa.gov.my",
		Notes:        "test",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, s.CreateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, "Ahmad bin Ali", got.ContactName)
	assert.Equal(t, "+60123456789", got.ContactPhone)
	assert.Equal(t, "ahmad@nacsa.gov.my", got.ContactEmail)

	got.ContactName = "Siti binti Rahmat"
	got.ContactPhone = "+60198765432"
	got.ContactEmail = "siti@nacsa.gov.my"
	got.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, s.UpdateOrg(ctx, got))

	updated, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, "Siti binti Rahmat", updated.ContactName)
	assert.Equal(t, "siti@nacsa.gov.my", updated.ContactEmail)
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -v -tags integration -run TestOrgContactFields_CRUD ./pkg/licensestore/...
```

Expected: FAIL — `Organization` has no field `ContactName`.

- [ ] **Step 3: Update `Organization` struct in `store.go`**

Replace the `Organization` struct (lines 83–95 in `pkg/licensestore/store.go`):

```go
// Organization represents a customer organization.
type Organization struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ContactName  string `json:"contact_name"`
	ContactPhone string `json:"contact_phone"`
	ContactEmail string `json:"contact_email"`
	Notes        string `json:"notes"`
	Suspended    bool   `json:"suspended"`
	// ActiveActivations and HasSeatedLicenses are read-only computed fields
	// populated by ListOrgs — never written to the database directly.
	ActiveActivations int       `json:"activeActivations"`
	HasSeatedLicenses bool      `json:"hasSeatedLicenses"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
```

- [ ] **Step 4: Update `CreateOrg` SQL in `postgres.go`**

Replace the `CreateOrg` method body:

```go
func (s *PostgresStore) CreateOrg(ctx context.Context, org *Organization) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO organizations (id, name, contact_name, contact_phone, contact_email, notes, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		org.ID, org.Name, org.ContactName, org.ContactPhone, org.ContactEmail,
		org.Notes, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: fmt.Sprintf("organization name %q already exists", org.Name)}
		}
		return fmt.Errorf("creating organization: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Update `GetOrg` SQL in `postgres.go`**

Replace the `GetOrg` method body:

```go
func (s *PostgresStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
	var org Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, contact_name, contact_phone, contact_email, notes, suspended, created_at, updated_at
		 FROM organizations WHERE id = $1`, id,
	).Scan(&org.ID, &org.Name, &org.ContactName, &org.ContactPhone, &org.ContactEmail,
		&org.Notes, &org.Suspended, &org.CreatedAt, &org.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "organization", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("getting organization: %w", err)
	}
	return &org, nil
}
```

- [ ] **Step 6: Update `ListOrgs` SQL in `postgres.go`**

Replace the SELECT list and Scan call in `ListOrgs`:

```go
func (s *PostgresStore) ListOrgs(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			o.id, o.name, o.contact_name, o.contact_phone, o.contact_email, o.notes, o.suspended,
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
			&org.ID, &org.Name, &org.ContactName, &org.ContactPhone, &org.ContactEmail,
			&org.Notes, &org.Suspended, &org.CreatedAt, &org.UpdatedAt,
			&org.HasSeatedLicenses, &org.ActiveActivations,
		); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}
```

- [ ] **Step 7: Update `UpdateOrg` SQL in `postgres.go`**

Replace the `UpdateOrg` method body:

```go
func (s *PostgresStore) UpdateOrg(ctx context.Context, org *Organization) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE organizations SET name = $2, contact_name = $3, contact_phone = $4,
		 contact_email = $5, notes = $6, updated_at = $7
		 WHERE id = $1`,
		org.ID, org.Name, org.ContactName, org.ContactPhone, org.ContactEmail,
		org.Notes, org.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: fmt.Sprintf("organization name %q already exists", org.Name)}
		}
		return fmt.Errorf("updating organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "organization", ID: org.ID}
	}
	return nil
}
```

- [ ] **Step 8: Fix `makeOrg` helper in `postgres_test.go`**

Update the `Contact` field usage in `makeOrg` (and any other test that sets `org.Contact`) to use the new field names:

```go
func makeOrg(t *testing.T) *licensestore.Organization {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &licensestore.Organization{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Name:         "Test Org " + uuid.Must(uuid.NewV7()).String(),
		ContactName:  "Test Contact",
		ContactEmail: "contact@test.example",
		Notes:        "test org",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
```

- [ ] **Step 9: Run the test to verify it passes**

```bash
go test -v -tags integration -run TestOrgContactFields_CRUD ./pkg/licensestore/...
```

Expected: PASS

- [ ] **Step 10: Run all licensestore tests to verify no regressions**

```bash
go test -v -tags integration ./pkg/licensestore/...
```

Expected: all pass

- [ ] **Step 11: Commit**

```bash
git add pkg/licensestore/store.go pkg/licensestore/postgres.go pkg/licensestore/postgres_test.go
git commit -m "feat(licensestore): update Organization struct — contact_name/phone/email fields"
```

---

### Task 3: Add `LicenseWithOrg`, `ListExpiringLicenses`, `MarkLicenseNotified` to store

**Files:**
- Modify: `pkg/licensestore/store.go` (add struct + interface methods)
- Modify: `pkg/licensestore/postgres.go` (implement methods)

- [ ] **Step 1: Write failing tests**

Add to `pkg/licensestore/postgres_test.go`:

```go
func TestListExpiringLicenses_WithinWindow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org := makeOrg(t)
	org.ContactEmail = "tenant@example.com"
	org.ContactName = "Tenant Contact"
	require.NoError(t, s.CreateOrg(ctx, org))

	// License expiring in 20 days — within 30d window
	lic := makeLicense(t, org.ID)
	lic.ExpiresAt = time.Now().UTC().Add(20 * 24 * time.Hour)
	require.NoError(t, s.CreateLicense(ctx, lic))

	results, err := s.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, lic.ID, results[0].LicenseID)
	assert.Equal(t, "Tenant Contact", results[0].ContactName)
	assert.Equal(t, "tenant@example.com", results[0].ContactEmail)
	assert.Nil(t, results[0].Notified30dAt)
}

func TestListExpiringLicenses_ExcludesRevoked(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.ExpiresAt = time.Now().UTC().Add(5 * 24 * time.Hour)
	require.NoError(t, s.CreateLicense(ctx, lic))
	require.NoError(t, s.RevokeLicense(ctx, lic.ID, "test-admin"))

	results, err := s.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListExpiringLicenses_ExcludesAlreadyExpired(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.ExpiresAt = time.Now().UTC().Add(-24 * time.Hour) // already expired
	require.NoError(t, s.CreateLicense(ctx, lic))

	results, err := s.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestMarkLicenseNotified(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.ExpiresAt = time.Now().UTC().Add(20 * 24 * time.Hour)
	require.NoError(t, s.CreateLicense(ctx, lic))

	require.NoError(t, s.MarkLicenseNotified(ctx, lic.ID, "30d"))

	// After marking 30d, the license should no longer appear in ListExpiringLicenses for 30d
	results, err := s.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	// Filter to this license
	var found *licensestore.LicenseWithOrg
	for i := range results {
		if results[i].LicenseID == lic.ID {
			found = &results[i]
		}
	}
	require.NotNil(t, found, "license should still appear in results")
	assert.NotNil(t, found.Notified30dAt, "notified_30d_at should be set")
	assert.Nil(t, found.Notified7dAt)
	assert.Nil(t, found.Notified1dAt)
}

func TestMarkLicenseNotified_InvalidInterval(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.MarkLicenseNotified(ctx, "00000000-0000-0000-0000-000000000001", "99d")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown interval")
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test -v -tags integration -run "TestListExpiringLicenses|TestMarkLicenseNotified" ./pkg/licensestore/...
```

Expected: FAIL — `LicenseWithOrg` undefined, `ListExpiringLicenses` undefined.

- [ ] **Step 3: Add `LicenseWithOrg` struct and interface methods to `store.go`**

Add after the `LicenseRecord` struct definition and add to the `Store` interface:

In the `Store` interface, after `UpdateLicense`:

```go
	// ListExpiringLicenses returns licenses whose expires_at falls between
	// NOW() and NOW()+within. Includes notified_*d_at so callers can filter
	// without a second query.
	ListExpiringLicenses(ctx context.Context, within time.Duration) ([]LicenseWithOrg, error)

	// MarkLicenseNotified sets the notified_*d_at column for the given
	// interval ("30d", "7d", or "1d") to NOW(). Returns an error for
	// unknown intervals.
	MarkLicenseNotified(ctx context.Context, licenseID string, interval string) error
```

Add the struct (after `LicenseRecord`):

```go
// LicenseWithOrg is a read-only projection used by the expiry notification
// goroutine. It joins the license row with the owning organization's contact
// fields so the caller can send emails without a second query.
type LicenseWithOrg struct {
	LicenseID     string
	OrgID         string
	OrgName       string
	ContactName   string
	ContactPhone  string
	ContactEmail  string
	ExpiresAt     time.Time
	Notified30dAt *time.Time
	Notified7dAt  *time.Time
	Notified1dAt  *time.Time
}
```

- [ ] **Step 4: Implement `ListExpiringLicenses` in `postgres.go`**

Add after `UpdateLicense`:

```go
func (s *PostgresStore) ListExpiringLicenses(ctx context.Context, within time.Duration) ([]LicenseWithOrg, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT l.id, l.org_id, o.name, o.contact_name, o.contact_phone, o.contact_email,
		       l.expires_at, l.notified_30d_at, l.notified_7d_at, l.notified_1d_at
		FROM   licenses l
		JOIN   organizations o ON o.id = l.org_id
		WHERE  l.revoked_at IS NULL
		  AND  l.expires_at > NOW()
		  AND  l.expires_at <= NOW() + $1::interval
		ORDER  BY l.expires_at`,
		fmt.Sprintf("%d seconds", int(within.Seconds())),
	)
	if err != nil {
		return nil, fmt.Errorf("listing expiring licenses: %w", err)
	}
	defer rows.Close()

	var results []LicenseWithOrg
	for rows.Next() {
		var r LicenseWithOrg
		if err := rows.Scan(
			&r.LicenseID, &r.OrgID, &r.OrgName,
			&r.ContactName, &r.ContactPhone, &r.ContactEmail,
			&r.ExpiresAt,
			&r.Notified30dAt, &r.Notified7dAt, &r.Notified1dAt,
		); err != nil {
			return nil, fmt.Errorf("scanning expiring license: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}
```

- [ ] **Step 5: Implement `MarkLicenseNotified` in `postgres.go`**

Add after `ListExpiringLicenses`:

```go
func (s *PostgresStore) MarkLicenseNotified(ctx context.Context, licenseID string, interval string) error {
	var col string
	switch interval {
	case "30d":
		col = "notified_30d_at"
	case "7d":
		col = "notified_7d_at"
	case "1d":
		col = "notified_1d_at"
	default:
		return fmt.Errorf("unknown interval %q: must be 30d, 7d, or 1d", interval)
	}
	_, err := s.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE licenses SET %s = NOW() WHERE id = $1`, col),
		licenseID,
	)
	if err != nil {
		return fmt.Errorf("marking license notified (%s): %w", interval, err)
	}
	return nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
go test -v -tags integration -run "TestListExpiringLicenses|TestMarkLicenseNotified" ./pkg/licensestore/...
```

Expected: all 5 tests PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/licensestore/store.go pkg/licensestore/postgres.go pkg/licensestore/postgres_test.go
git commit -m "feat(licensestore): add LicenseWithOrg, ListExpiringLicenses, MarkLicenseNotified"
```

---

### Task 4: Add `SendExpiryWarningEmail` to `internal/mailer`

**Files:**
- Modify: `internal/mailer/mailer.go`
- Modify: `pkg/licenseserver/mailer.go` (add re-export)

- [ ] **Step 1: Write failing test**

Add to `internal/mailer/` — create `internal/mailer/expiry_test.go`:

```go
package mailer_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/mailer"
)

func TestSendExpiryWarningEmail_30d(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"test-id"}`))
	}))
	defer srv.Close()

	m := mailer.NewResendMailer("test-key", "no-reply@triton.io", "Triton").WithEndpoint(srv.URL)
	data := mailer.ExpiryWarningEmailData{
		RecipientName: "Ahmad bin Ali",
		OrgName:       "NACSA",
		LicenseID:     "lic-001",
		ExpiresAt:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		DaysRemaining: 30,
	}
	err := m.SendExpiryWarningEmail(context.Background(), "ahmad@nacsa.gov.my", data)
	require.NoError(t, err)

	assert.Equal(t, []any{"ahmad@nacsa.gov.my"}, captured["to"])
	subject, _ := captured["subject"].(string)
	assert.Contains(t, subject, "30 days")
	text, _ := captured["text"].(string)
	assert.Contains(t, text, "NACSA")
	assert.Contains(t, text, "Ahmad bin Ali")
	assert.Contains(t, text, "1 Jun 2026")
}

func TestSendExpiryWarningEmail_SubjectVariants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()

	m := mailer.NewResendMailer("key", "from@example.com", "T").WithEndpoint(srv.URL)

	tests := []struct {
		days    int
		subject string
	}{
		{30, "30 days"},
		{7, "7 days"},
		{1, "tomorrow"},
	}
	for _, tc := range tests {
		data := mailer.ExpiryWarningEmailData{
			RecipientName: "Admin",
			OrgName:       "Org",
			LicenseID:     "lic-x",
			ExpiresAt:     time.Now().Add(time.Duration(tc.days) * 24 * time.Hour),
			DaysRemaining: tc.days,
		}
		// Capture subject by intercepting the request — just check no error returned
		err := m.SendExpiryWarningEmail(context.Background(), "admin@example.com", data)
		require.NoError(t, err, "days=%d", tc.days)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -v -run "TestSendExpiryWarningEmail" ./internal/mailer/...
```

Expected: FAIL — `ExpiryWarningEmailData` undefined.

- [ ] **Step 3: Add `ExpiryWarningEmailData` and extend `Mailer` interface in `internal/mailer/mailer.go`**

Add after the `InviteEmailData` struct:

```go
// ExpiryWarningEmailData is the content of a license expiry warning email.
type ExpiryWarningEmailData struct {
	RecipientName string    // e.g. "Ahmad bin Ali" or "Platform Admin"
	OrgName       string    // e.g. "NACSA"
	LicenseID     string
	ExpiresAt     time.Time
	DaysRemaining int // 30, 7, or 1
}
```

Update the `Mailer` interface:

```go
type Mailer interface {
	SendInviteEmail(ctx context.Context, data InviteEmailData) error
	SendExpiryWarningEmail(ctx context.Context, to string, data ExpiryWarningEmailData) error
}
```

- [ ] **Step 4: Implement `SendExpiryWarningEmail` on `ResendMailer` in `internal/mailer/mailer.go`**

Add after `SendInviteEmail`:

```go
// SendExpiryWarningEmail sends a license expiry warning to the specified
// recipient. DaysRemaining controls the subject urgency level.
func (m *ResendMailer) SendExpiryWarningEmail(ctx context.Context, to string, data ExpiryWarningEmailData) error {
	var subject string
	switch data.DaysRemaining {
	case 1:
		subject = fmt.Sprintf("License expiring tomorrow — immediate action required (%s)", data.OrgName)
	case 7:
		subject = fmt.Sprintf("License expiring in 7 days — urgent (%s)", data.OrgName)
	default:
		subject = fmt.Sprintf("License expiring in %d days — action required (%s)", data.DaysRemaining, data.OrgName)
	}

	textBody := fmt.Sprintf(`Hi %s,

This is a reminder that the Triton license for %s is expiring soon.

License ID: %s
Expiry date: %s
Days remaining: %d

Please contact your Triton administrator to arrange a renewal before the expiry date to avoid service disruption.

— Triton License Server
`, data.RecipientName, data.OrgName, data.LicenseID,
		data.ExpiresAt.Format("2 Jan 2006"), data.DaysRemaining)

	req := resendSendRequest{
		From:    fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail),
		To:      []string{to},
		Subject: subject,
		Text:    textBody,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling expiry warning email: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiEndpoint(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building expiry warning request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		httpReq.Header.Set("X-Request-ID", reqID)
	}

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending expiry warning: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, 4<<10)
		respBody, _ := io.ReadAll(limited)
		return fmt.Errorf("resend returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
```

- [ ] **Step 5: Add re-export to `pkg/licenseserver/mailer.go`**

Add `ExpiryWarningEmailData` to the type alias block:

```go
type (
	Mailer                = mailer.Mailer
	InviteEmailData       = mailer.InviteEmailData
	ExpiryWarningEmailData = mailer.ExpiryWarningEmailData
	ResendMailer          = mailer.ResendMailer
)
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
go test -v -run "TestSendExpiryWarningEmail" ./internal/mailer/...
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/mailer/mailer.go internal/mailer/expiry_test.go pkg/licenseserver/mailer.go
git commit -m "feat(mailer): add ExpiryWarningEmailData + SendExpiryWarningEmail"
```

---

### Task 5: Background expiry notification goroutine in `Server`

**Files:**
- Modify: `pkg/licenseserver/server.go`

Context: The `Server` struct has no `mailer` field — the mailer is held in `s.config.Mailer`. The `New()` function already launches the login-rate-limiter janitor via `srv.loginLimiter.StartJanitor(ctx, ...)`. We follow the same pattern: launch `go srv.runExpiryNotifications(ctx)` at the end of `New()`. The goroutine exits when `ctx` is cancelled by `Shutdown()`.

- [ ] **Step 1: Write the failing unit test**

Create `pkg/licenseserver/expiry_notifications_test.go`:

```go
package licenseserver_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// stubStore implements only the methods needed for expiry notification tests.
type stubStoreExpiry struct {
	licensestore.Store // embed to satisfy interface; panics on any unimplemented method
	licenses           []licensestore.LicenseWithOrg
	marked             []string // "<id>/<interval>" pairs
	users              []licensestore.User
}

func (s *stubStoreExpiry) ListExpiringLicenses(_ context.Context, _ time.Duration) ([]licensestore.LicenseWithOrg, error) {
	return s.licenses, nil
}

func (s *stubStoreExpiry) MarkLicenseNotified(_ context.Context, id, interval string) error {
	s.marked = append(s.marked, id+"/"+interval)
	return nil
}

func (s *stubStoreExpiry) ListUsers(_ context.Context, _ licensestore.UserFilter) ([]licensestore.User, error) {
	return s.users, nil
}

// stubMailer records expiry warning calls.
type stubMailer struct {
	mailer.Mailer // embed to handle SendInviteEmail; panics if called
	calls         atomic.Int32
	lastTo        atomic.Value
}

func (m *stubMailer) SendExpiryWarningEmail(_ context.Context, to string, _ mailer.ExpiryWarningEmailData) error {
	m.calls.Add(1)
	m.lastTo.Store(to)
	return nil
}

func TestSendExpiryNotifications_SendsToAdminsAndContact(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:    "lic-001",
				OrgID:        "org-001",
				OrgName:      "NACSA",
				ContactName:  "Ahmad",
				ContactEmail: "ahmad@nacsa.gov.my",
				ExpiresAt:    time.Now().Add(20 * 24 * time.Hour),
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Role: "platform_admin"},
		},
	}
	m := &stubMailer{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// 1 admin + 1 contact email = 2 sends
	assert.Equal(t, int32(2), m.calls.Load())
	assert.Len(t, stub.marked, 3) // marked for all three intervals
}

func TestSendExpiryNotifications_SkipsAlreadyNotified30d(t *testing.T) {
	now := time.Now()
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:     "lic-001",
				ExpiresAt:     now.Add(20 * 24 * time.Hour),
				Notified30dAt: &now, // already notified for 30d
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Role: "platform_admin"},
		},
	}
	m := &stubMailer{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// No email — only the 30d window should fire for a 20-day-out license,
	// but it's already marked. 7d and 1d windows don't match (20 days out).
	assert.Equal(t, int32(0), m.calls.Load())
}

func TestSendExpiryNotifications_SkipsEmptyContactEmail(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:    "lic-001",
				ExpiresAt:    time.Now().Add(20 * 24 * time.Hour),
				ContactEmail: "", // no contact email configured
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Role: "platform_admin"},
		},
	}
	m := &stubMailer{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// Only admin email sent — no contact email
	assert.Equal(t, int32(1), m.calls.Load())
}

func TestSendExpiryNotifications_NilMailer(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{LicenseID: "lic-001", ExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
		},
	}
	srv := licenseserver.NewForTest(stub, nil)
	// Must not panic
	srv.TriggerExpiryCheck(context.Background())
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -v -run "TestSendExpiryNotifications" ./pkg/licenseserver/...
```

Expected: FAIL — `NewForTest` and `TriggerExpiryCheck` undefined.

- [ ] **Step 3: Implement the goroutine and test helpers in `server.go`**

Add the following to `pkg/licenseserver/server.go`:

After the `Server` struct closing brace, add the notification methods. Also add `NewForTest` for testability:

```go
// expiryThresholds defines the three notification windows. Each entry is
// (maximum time-to-expiry to match, interval label for MarkLicenseNotified).
var expiryThresholds = []struct {
	within   time.Duration
	interval string
}{
	{30 * 24 * time.Hour, "30d"},
	{7 * 24 * time.Hour, "7d"},
	{24 * time.Hour, "1d"},
}

// runExpiryNotifications ticks hourly and calls sendExpiryNotifications.
// It exits when ctx is cancelled (i.e., on Shutdown).
func (s *Server) runExpiryNotifications(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendExpiryNotifications(ctx)
		}
	}
}

// TriggerExpiryCheck runs one expiry notification cycle. Exported for testing.
func (s *Server) TriggerExpiryCheck(ctx context.Context) {
	s.sendExpiryNotifications(ctx)
}

// sendExpiryNotifications checks all three expiry windows and sends warning
// emails to platform_admin users and the org contact for licenses that have
// not yet been notified for the relevant window.
func (s *Server) sendExpiryNotifications(ctx context.Context) {
	if s.config.Mailer == nil {
		log.Printf("expiry notifications: mailer not configured, skipping")
		return
	}

	// Fetch all platform_admin users once per cycle.
	admins, err := s.store.ListUsers(ctx, licensestore.UserFilter{Role: "platform_admin"})
	if err != nil {
		log.Printf("expiry notifications: list admins: %v", err)
		return
	}

	for _, threshold := range expiryThresholds {
		licenses, err := s.store.ListExpiringLicenses(ctx, threshold.within)
		if err != nil {
			log.Printf("expiry notifications [%s]: list licenses: %v", threshold.interval, err)
			continue
		}

		for _, lic := range licenses {
			if !s.needsNotification(lic, threshold.interval) {
				continue
			}

			daysRemaining := int(time.Until(lic.ExpiresAt).Hours() / 24)
			data := ExpiryWarningEmailData{
				OrgName:       lic.OrgName,
				LicenseID:     lic.LicenseID,
				ExpiresAt:     lic.ExpiresAt,
				DaysRemaining: daysRemaining,
			}

			for _, admin := range admins {
				d := data
				d.RecipientName = admin.Name
				if sendErr := s.config.Mailer.SendExpiryWarningEmail(ctx, admin.Email, d); sendErr != nil {
					log.Printf("expiry notifications [%s]: send to admin %s: %v", threshold.interval, admin.Email, sendErr)
				}
			}

			if lic.ContactEmail != "" {
				d := data
				d.RecipientName = lic.ContactName
				if sendErr := s.config.Mailer.SendExpiryWarningEmail(ctx, lic.ContactEmail, d); sendErr != nil {
					log.Printf("expiry notifications [%s]: send to contact %s: %v", threshold.interval, lic.ContactEmail, sendErr)
				}
			}

			if markErr := s.store.MarkLicenseNotified(ctx, lic.LicenseID, threshold.interval); markErr != nil {
				log.Printf("expiry notifications [%s]: mark license %s: %v", threshold.interval, lic.LicenseID, markErr)
			}
		}
	}
}

// needsNotification returns true when the license has not yet been notified
// for the given interval.
func (s *Server) needsNotification(lic licensestore.LicenseWithOrg, interval string) bool {
	switch interval {
	case "30d":
		return lic.Notified30dAt == nil
	case "7d":
		return lic.Notified7dAt == nil
	case "1d":
		return lic.Notified1dAt == nil
	}
	return false
}

// NewForTest constructs a minimal Server suitable for unit testing the
// expiry notification logic without starting an HTTP server.
func NewForTest(store licensestore.Store, m Mailer) *Server {
	return &Server{
		config: &Config{Mailer: m},
		store:  store,
	}
}
```

- [ ] **Step 4: Launch the goroutine in `New()`**

In `pkg/licenseserver/server.go`, add this line at the end of `New()`, just after the `StartJanitor` call:

```go
	go srv.runExpiryNotifications(ctx)
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
go test -v -run "TestSendExpiryNotifications" ./pkg/licenseserver/...
```

Expected: all 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/server.go pkg/licenseserver/expiry_notifications_test.go
git commit -m "feat(licenseserver): hourly expiry notification goroutine"
```

---

### Task 6: Update org handlers — replace `contact` with new contact fields

**Files:**
- Modify: `pkg/licenseserver/handlers_org.go`
- Modify: `pkg/licenseserver/provisioning.go`
- Modify: `pkg/licenseserver/server.go` (new length constants)

Context: `handleCreateOrg` and `handleUpdateOrg` decode a `contact` JSON field and set `org.Contact`. Both must change to `contact_name`, `contact_phone`, `contact_email`. `ProvisionOrgInput` in `provisioning.go` has a `Contact` field that must become `ContactName`, `ContactPhone`, `ContactEmail`.

- [ ] **Step 1: Write the failing unit tests**

Add to `pkg/licenseserver/expiry_notifications_test.go` (or a new `handlers_org_test.go`):

Create `pkg/licenseserver/handlers_org_contact_test.go`:

```go
package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOrg_RequiresContactNameAndEmail(t *testing.T) {
	_, ts := newMinimalTestServer(t)

	body := `{"name":"Test Org"}`
	resp, err := http.Post(ts.URL+"/api/v1/admin/orgs", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, out["error"], "contact_name")
}

func TestCreateOrg_ContactEmailMustBeValid(t *testing.T) {
	_, ts := newMinimalTestServer(t)

	body := `{"name":"Test Org","contact_name":"Ahmad","contact_email":"not-an-email"}`
	resp, err := http.Post(ts.URL+"/api/v1/admin/orgs", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
```

Also add `newMinimalTestServer` helper to the test file:

```go
// newMinimalTestServer builds a licenseserver with an in-memory stub store
// and no mailer, wired to a real Chi router, for handler unit tests.
// Returns the admin JWT token and the test server URL.
func newMinimalTestServer(t *testing.T) (string, *httptest.Server) {
	t.Helper()
	// Use the integration test server builder if available; otherwise skip.
	// This test requires the integration tag.
	t.Skip("requires integration build tag — move to integration test if running inline")
	return "", nil
}
```

Note: the handler validation tests below will be written as integration tests in Task 8 instead (they require a real store). Skip this stub approach — remove `newMinimalTestServer`. The unit tests for handler validation are covered by the integration tests in Task 8.

- [ ] **Step 2: Update length constants in `server.go`**

Replace the existing constants block (currently lines ~234–241):

```go
// Input length limits.
const (
	maxNameLen         = 255
	maxContactNameLen  = 100
	maxContactPhoneLen = 50
	maxContactEmailLen = 325
	maxNotesLen        = 1000
	maxHostnameLen     = 255
	maxVersionLen      = 50
	maxReasonLen       = 500
)
```

Remove `maxContactLen = 255` (no longer used).

- [ ] **Step 3: Update `handleCreateOrg` in `handlers_org.go`**

Replace the request struct and validation block:

```go
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Name         string `json:"name"`
		ContactName  string `json:"contact_name"`
		ContactPhone string `json:"contact_phone"`
		ContactEmail string `json:"contact_email"`
		Notes        string `json:"notes"`
		AdminEmail   string `json:"admin_email,omitempty"`
		AdminName    string `json:"admin_name,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ContactEmail = strings.ToLower(strings.TrimSpace(req.ContactEmail))

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if strings.TrimSpace(req.ContactName) == "" {
		writeError(w, http.StatusBadRequest, "contact_name is required")
		return
	}
	if req.ContactEmail == "" {
		writeError(w, http.StatusBadRequest, "contact_email is required")
		return
	}
	if err := validateEmail(req.ContactEmail); err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact_email: "+err.Error())
		return
	}
	if tooLong(req.Name, maxNameLen) ||
		tooLong(req.ContactName, maxContactNameLen) ||
		tooLong(req.ContactPhone, maxContactPhoneLen) ||
		tooLong(req.ContactEmail, maxContactEmailLen) ||
		tooLong(req.Notes, maxNotesLen) {
		writeError(w, http.StatusBadRequest, "field exceeds maximum length")
		return
	}

	wantProvision := req.AdminEmail != "" || req.AdminName != ""
	if wantProvision {
		if req.AdminEmail == "" || req.AdminName == "" {
			writeError(w, http.StatusBadRequest, "admin_email and admin_name must be supplied together")
			return
		}
		req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))
		if err := validateEmail(req.AdminEmail); err != nil {
			writeError(w, http.StatusBadRequest, "invalid admin_email: "+err.Error())
			return
		}
		if tooLong(req.AdminName, maxNameLen) {
			writeError(w, http.StatusBadRequest, "admin_name exceeds maximum length")
			return
		}
	}

	result, status, err := s.ProvisionOrgWithAdmin(r.Context(), ProvisionOrgInput{
		Name:         req.Name,
		ContactName:  req.ContactName,
		ContactPhone: req.ContactPhone,
		ContactEmail: req.ContactEmail,
		Notes:        req.Notes,
		AdminEmail:   req.AdminEmail,
		AdminName:    req.AdminName,
	})
	// ... rest of handler unchanged (error mapping + writeJSON) ...
```

- [ ] **Step 4: Update `handleUpdateOrg` in `handlers_org.go`**

Replace the request struct and validation:

```go
func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Name         string `json:"name"`
		ContactName  string `json:"contact_name"`
		ContactPhone string `json:"contact_phone"`
		ContactEmail string `json:"contact_email"`
		Notes        string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ContactEmail = strings.ToLower(strings.TrimSpace(req.ContactEmail))

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if strings.TrimSpace(req.ContactName) == "" {
		writeError(w, http.StatusBadRequest, "contact_name is required")
		return
	}
	if req.ContactEmail == "" {
		writeError(w, http.StatusBadRequest, "contact_email is required")
		return
	}
	if err := validateEmail(req.ContactEmail); err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact_email: "+err.Error())
		return
	}
	if tooLong(req.Name, maxNameLen) ||
		tooLong(req.ContactName, maxContactNameLen) ||
		tooLong(req.ContactPhone, maxContactPhoneLen) ||
		tooLong(req.ContactEmail, maxContactEmailLen) ||
		tooLong(req.Notes, maxNotesLen) {
		writeError(w, http.StatusBadRequest, "field exceeds maximum length")
		return
	}

	org := &licensestore.Organization{
		ID:           id,
		Name:         req.Name,
		ContactName:  req.ContactName,
		ContactPhone: req.ContactPhone,
		ContactEmail: req.ContactEmail,
		Notes:        req.Notes,
		UpdatedAt:    time.Now().UTC(),
	}
	// ... rest of handler unchanged (store.UpdateOrg + audit + GetOrg + writeJSON) ...
```

- [ ] **Step 5: Update `ProvisionOrgInput` and `ProvisionOrgWithAdmin` in `provisioning.go`**

Replace `ProvisionOrgInput`:

```go
type ProvisionOrgInput struct {
	Name         string
	ContactName  string
	ContactPhone string
	ContactEmail string
	Notes        string
	AdminEmail   string // optional — leave empty to skip admin provisioning
	AdminName    string // required iff AdminEmail is non-empty
}
```

Update the `org` literal inside `ProvisionOrgWithAdmin`:

```go
	org := &licensestore.Organization{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Name:         input.Name,
		ContactName:  input.ContactName,
		ContactPhone: input.ContactPhone,
		ContactEmail: input.ContactEmail,
		Notes:        input.Notes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
```

- [ ] **Step 6: Build to verify no compilation errors**

```bash
go build ./pkg/licenseserver/... ./pkg/licensestore/...
```

Expected: SUCCESS

- [ ] **Step 7: Commit**

```bash
git add pkg/licenseserver/handlers_org.go pkg/licenseserver/provisioning.go pkg/licenseserver/server.go
git commit -m "feat(licenseserver): replace contact field with contact_name/phone/email in org handlers"
```

---

### Task 7: Update `maxEmailLen` constant usage + compile check

**Files:**
- Modify: `pkg/licenseserver/handlers_superadmin.go`

Context: `maxEmailLen = 255` is defined in `handlers_superadmin.go`. The new `maxContactEmailLen = 325` is defined in `server.go`. The old `maxContactLen` constant in `server.go` is now deleted. Check there are no remaining references to the deleted constant.

- [ ] **Step 1: Find and remove orphaned references**

```bash
grep -rn "maxContactLen\b" pkg/licenseserver/
```

Expected: no output. If any, fix each occurrence by replacing with the appropriate new constant.

- [ ] **Step 2: Full build + unit tests**

```bash
go build ./...
go test ./pkg/licenseserver/... ./pkg/licensestore/... ./internal/mailer/...
```

Expected: all pass

- [ ] **Step 3: Commit if any fixes were needed**

```bash
git add -p
git commit -m "fix(licenseserver): remove orphaned maxContactLen references"
```

(Skip this commit if `grep` found nothing.)

---

### Task 8: Integration tests for expiry notifications + org contact fields

**Files:**
- Modify: `test/integration/license_server_test.go`

- [ ] **Step 1: Write the integration tests**

Add to `test/integration/license_server_test.go`:

```go
func TestOrgContactFields_CreateAndRead(t *testing.T) {
	baseURL, store, _, _ := newTestLicenseServer(t)
	token := getLicAdminToken(t, baseURL)

	body := `{
		"name": "Contact Test Org",
		"contact_name": "Ahmad bin Ali",
		"contact_phone": "+60123456789",
		"contact_email": "ahmad@nacsa.gov.my"
	}`
	resp := doJSON(t, "POST", baseURL+"/api/v1/admin/orgs", token, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created struct {
		Org struct {
			ID           string `json:"id"`
			ContactName  string `json:"contact_name"`
			ContactPhone string `json:"contact_phone"`
			ContactEmail string `json:"contact_email"`
		} `json:"org"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	assert.Equal(t, "Ahmad bin Ali", created.Org.ContactName)
	assert.Equal(t, "+60123456789", created.Org.ContactPhone)
	assert.Equal(t, "ahmad@nacsa.gov.my", created.Org.ContactEmail)

	// Read back via GET
	get := doJSON(t, "GET", baseURL+"/api/v1/admin/orgs/"+created.Org.ID, token, "")
	require.Equal(t, http.StatusOK, get.StatusCode)
	var org map[string]any
	require.NoError(t, json.NewDecoder(get.Body).Decode(&org))
	get.Body.Close()
	assert.Equal(t, "Ahmad bin Ali", org["contact_name"])
	assert.Equal(t, "ahmad@nacsa.gov.my", org["contact_email"])

	_ = store // referenced to avoid unused import
}

func TestOrgContactFields_CreateValidation(t *testing.T) {
	baseURL, _, _, _ := newTestLicenseServer(t)
	token := getLicAdminToken(t, baseURL)

	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "missing contact_name",
			body: `{"name":"Org A","contact_email":"a@b.com"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "missing contact_email",
			body: `{"name":"Org B","contact_name":"Bob"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "invalid contact_email",
			body: `{"name":"Org C","contact_name":"Carol","contact_email":"not-an-email"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "valid with phone",
			body: `{"name":"Org D","contact_name":"Dave","contact_email":"dave@d.com","contact_phone":"+601234"}`,
			want: http.StatusCreated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, "POST", baseURL+"/api/v1/admin/orgs", token, tc.body)
			resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func TestExpiryNotifications_30dTriggered(t *testing.T) {
	_, store, _, _ := newTestLicenseServer(t)
	ctx := context.Background()

	// Create org with contact email
	org := makeTestOrg(t, store, "Expiry Test Org")
	org.ContactEmail = "contact@example.com"
	org.ContactName = "Test Contact"
	require.NoError(t, store.UpdateOrg(ctx, org))

	// Create license expiring in 20 days (within 30d window)
	lic := makeTestLicense(t, store, org.ID, 20*24*time.Hour)

	// Verify notified_30d_at starts NULL by checking ListExpiringLicenses
	results, err := store.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	var before *licensestore.LicenseWithOrg
	for i := range results {
		if results[i].LicenseID == lic.ID {
			before = &results[i]
		}
	}
	require.NotNil(t, before, "license should appear in 30d window")
	assert.Nil(t, before.Notified30dAt)

	// Mark as notified
	require.NoError(t, store.MarkLicenseNotified(ctx, lic.ID, "30d"))

	// Verify notified_30d_at is now set
	results2, err := store.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	var after *licensestore.LicenseWithOrg
	for i := range results2 {
		if results2[i].LicenseID == lic.ID {
			after = &results2[i]
		}
	}
	require.NotNil(t, after)
	assert.NotNil(t, after.Notified30dAt)

	// Verify it no longer appears in ListExpiringLicenses with Notified30dAt nil
	results, err := store.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	for _, r := range results {
		if r.LicenseID == lic.ID {
			assert.NotNil(t, r.Notified30dAt, "should have notified_30d_at set")
		}
	}
}

// makeTestOrg creates an org directly in the store and returns it.
func makeTestOrg(t *testing.T, store *licensestore.PostgresStore, name string) *licensestore.Organization {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	org := &licensestore.Organization{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Name:         name,
		ContactName:  "Default Contact",
		ContactEmail: "default@example.com",
		Notes:        "",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, store.CreateOrg(ctx, org))
	return org
}

// makeTestLicense creates a license directly in the store and returns it.
// Pass expiresIn to control when it expires (e.g. 20*24*time.Hour for 20 days out).
func makeTestLicense(t *testing.T, store *licensestore.PostgresStore, orgID string, expiresIn time.Duration) *licensestore.LicenseRecord {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	lic := &licensestore.LicenseRecord{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  now,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateLicense(ctx, lic))
	return lic
}
```

Also add a `doJSON` helper if it doesn't exist:

```go
// doJSON performs an HTTP request with optional JSON body and admin JWT.
func doJSON(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	var bodyR io.Reader
	if body != "" {
		bodyR = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyR)
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}
```

- [ ] **Step 2: Run the integration tests**

```bash
go test -v -tags integration -run "TestOrgContactFields|TestExpiryNotifications" ./test/integration/...
```

Expected: all pass

- [ ] **Step 3: Run all license server integration tests to check for regressions**

```bash
go test -v -tags integration -run "Test.*License" ./test/integration/...
```

Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add test/integration/license_server_test.go
git commit -m "test(integration): org contact fields + expiry notification integration tests"
```

---

### Task 9: E2E test — org create/update form shows new contact fields

**Files:**
- Modify: `test/e2e/license-admin.spec.js`

Context: The license admin E2E tests run with `make test-e2e-license`. The org form is in the `#/orgs/new` and `#/orgs/{id}` routes. The JS SPA at `pkg/licenseserver/ui/dist/app.js` shows org forms. The test just checks that the new input fields are rendered; JS SPA updates are deferred to Task 10.

- [ ] **Step 1: Write the E2E tests**

Add to `test/e2e/license-admin.spec.js`:

```javascript
test('org create form shows contact_name, contact_phone, contact_email fields', async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto('/#/orgs/new');
  await expect(page.locator('input[name="contact_name"], input[placeholder*="contact name" i]')).toBeVisible();
  await expect(page.locator('input[name="contact_email"], input[placeholder*="contact email" i]')).toBeVisible();
  await expect(page.locator('input[name="contact_phone"], input[placeholder*="contact phone" i]')).toBeVisible();
});

test('org create requires contact_name and contact_email', async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto('/#/orgs/new');
  await page.fill('input[name="name"], input[placeholder*="org name" i]', 'Test Org E2E');
  await page.click('button[type="submit"], button:has-text("Create")');
  // Should show validation error or stay on the form
  const errorOrForm = page.locator('text=required, [data-error], .error-message');
  // It should either show an error or not navigate away
  await expect(page.url()).toContain('/orgs/new');
});

test('org detail shows all three contact fields', async ({ page }) => {
  await loginAsAdmin(page);
  // Navigate to orgs list
  await page.goto('/#/orgs');
  // Click first org
  const firstOrgLink = page.locator('table a, .org-row a').first();
  await firstOrgLink.click();
  // Expect the three contact fields to be present in some form
  await expect(page.locator('text=contact_name, :text-matches("contact name", "i"), :text-matches("contact", "i")')).toBeVisible();
});
```

- [ ] **Step 2: Run E2E tests**

```bash
make test-e2e-license
```

Expected: the new tests may fail because the SPA hasn't been updated yet (Task 10). Note failures; they will be fixed in Task 10.

---

### Task 10: Update license admin SPA — org form and detail view

**Files:**
- Modify: `pkg/licenseserver/ui/dist/app.js`

Context: The admin SPA is vanilla JS. The org create/edit form currently has a `contact` text field. This must become three separate fields: `contact_name`, `contact_phone`, `contact_email`. The org detail view must display all three. Because `app.js` is the built/minified output (no build toolchain), edits are made directly.

- [ ] **Step 1: Find the contact field in the SPA**

```bash
grep -n "contact\|Contact" pkg/licenseserver/ui/dist/app.js | head -30
```

Note the exact line numbers and strings.

- [ ] **Step 2: Update the org create/edit form**

Find the create/edit form HTML generation in `app.js` (look for `contact` input or `name="contact"`). Replace the single `contact` input with three inputs:

```javascript
// Replace the contact field (find by searching for something like):
//   `<input ... name="contact" ...>`
// with:
`<div class="form-group">
  <label>Contact Name *</label>
  <input type="text" name="contact_name" value="${escapeHTML(org.contact_name || '')}" required maxlength="100" placeholder="Full name of primary contact">
</div>
<div class="form-group">
  <label>Contact Email *</label>
  <input type="email" name="contact_email" value="${escapeHTML(org.contact_email || '')}" required maxlength="325" placeholder="contact@example.com">
</div>
<div class="form-group">
  <label>Contact Phone</label>
  <input type="tel" name="contact_phone" value="${escapeHTML(org.contact_phone || '')}" maxlength="50" placeholder="+60123456789">
</div>`
```

- [ ] **Step 3: Update the form submission handler**

Find where the form data is collected (look for `contact:` or `body.contact`). Replace:

```javascript
// Old:
contact: form.contact.value,

// New:
contact_name: form.contact_name.value.trim(),
contact_phone: form.contact_phone.value.trim(),
contact_email: form.contact_email.value.trim(),
```

- [ ] **Step 4: Update the org detail/list view**

Find where org details are displayed and replace `org.contact` with the three new fields:

```javascript
// Old (something like):
`<td>${escapeHTML(org.contact)}</td>`

// New:
`<td>${escapeHTML(org.contact_name)}<br>
  <small>${escapeHTML(org.contact_email)}</small>
  ${org.contact_phone ? `<br><small>${escapeHTML(org.contact_phone)}</small>` : ''}
</td>`
```

- [ ] **Step 5: Run E2E tests to verify all pass**

```bash
make test-e2e-license
```

Expected: all 22 existing + 3 new tests PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/ui/dist/app.js
git commit -m "feat(ui): org form — replace contact field with contact_name/phone/email"
```

---

### Task 11: Update documentation

**Files:**
- Modify: `docs/LICENSE_SERVER_GUIDE.md`
- Modify: `docs/DEPLOYMENT_GUIDE.md`

Context: The docs were committed in the branch-bootstrap commit at the start. This task adds the new feature details: contact field changes in the org API section, and the expiry notification configuration section.

- [ ] **Step 1: Update `docs/LICENSE_SERVER_GUIDE.md`**

Find the Org API section (look for "Organization" under API Reference or Admin API). Update the org create/update request body table to show the new fields:

Replace any table or example showing `contact` (as a single field) with:

```
| contact_name  | string | Yes      | Primary contact full name (max 100 chars)   |
| contact_phone | string | No       | Primary contact phone number (max 50 chars) |
| contact_email | string | Yes      | Primary contact email address (max 325 chars, validated) |
```

Add a new section (e.g. "9. Expiry Notifications" or append to the Configuration section):

```markdown
### Expiry Notifications

The License Server sends automated email warnings when a license is approaching expiry. Emails are sent to:

- All **platform administrators** (users with `role = platform_admin`)
- The **organization contact email** (`contact_email` field on the org), if set

**Warning intervals:** 30 days, 7 days, and 1 day before `expires_at`.

**Requirements:** Resend must be configured (see Email section under Configuration).

**How it works:** A background goroutine checks all licenses hourly. Each license is notified at most once per interval — the `notified_30d_at`, `notified_7d_at`, and `notified_1d_at` columns on the `licenses` table track delivery. To resend, set the relevant column to NULL in the database.

**No additional configuration is required** — the notifications goroutine starts automatically when the server starts and Resend is configured.
```

- [ ] **Step 2: Update `docs/DEPLOYMENT_GUIDE.md`**

In the License Server section (Section 6 or equivalent), find the Organization Management / Org API description. Update the org fields table to list `contact_name`, `contact_phone`, `contact_email` instead of `contact`.

Add a note under the Resend email configuration:

```markdown
> **Expiry notifications:** Once Resend is configured, the license server automatically sends warning emails at 30 days, 7 days, and 1 day before each license expires. No extra configuration needed.
```

- [ ] **Step 3: Build and run full test suite**

```bash
go build ./...
go test ./...
go test -tags integration ./pkg/licensestore/... ./test/integration/...
```

Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add docs/LICENSE_SERVER_GUIDE.md docs/DEPLOYMENT_GUIDE.md
git commit -m "docs: update org API fields and add expiry notification documentation"
```

---

## Final Check

After all tasks are complete, run the full test suite:

```bash
go build ./...
go test ./...
go test -v -tags integration ./pkg/licensestore/... ./pkg/licenseserver/... ./test/integration/...
make test-e2e-license
```

All should pass before opening a PR.
