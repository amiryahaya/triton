# License Expiry Notifications — Design Spec

**Date:** 2026-04-28
**Branch:** feat/license-expiry-notifications
**Status:** Approved

---

## 1. Overview

License Server sends proactive expiry warning emails at three intervals before a license reaches its `expires_at` date: 30 days, 7 days, and 1 day. Recipients are all `platform_admin` users (queried from the `users` table) plus the organization's `contact_email`. A single background goroutine running an hourly ticker handles all checks.

---

## 2. Database Schema Changes

### 2.1 Organizations table — new contact columns

The existing `contact` column (free-text notes) is renamed to `contact_name` and two new columns are added.

```sql
ALTER TABLE organizations RENAME COLUMN contact TO contact_name;
ALTER TABLE organizations ADD COLUMN contact_phone TEXT NOT NULL DEFAULT '';
ALTER TABLE organizations ADD COLUMN contact_email TEXT NOT NULL DEFAULT '';
```

Existing rows get empty strings via `DEFAULT ''`. Validation that `contact_name` and `contact_email` are non-empty is enforced at the API layer (not DB layer) to keep the migration backward-compatible.

### 2.2 Licenses table — notification tracking columns

```sql
ALTER TABLE licenses ADD COLUMN notified_30d_at TIMESTAMPTZ;
ALTER TABLE licenses ADD COLUMN notified_7d_at  TIMESTAMPTZ;
ALTER TABLE licenses ADD COLUMN notified_1d_at  TIMESTAMPTZ;
```

All three are nullable. A NULL means the notification has not yet been sent for this license cycle. When an email is dispatched the column is set to `NOW()`. This prevents resending on every hourly tick.

---

## 3. Store Layer

### 3.1 Updated `Organization` struct

```go
type Organization struct {
    ID           string
    Name         string
    ContactName  string  // renamed from Contact
    ContactPhone string
    ContactEmail string
    CreatedAt    time.Time
    UpdatedAt    time.Time
}
```

### 3.2 New `LicenseWithOrg` struct

Used only by the notification goroutine — joins the license row with the owning organization's contact fields.

```go
type LicenseWithOrg struct {
    LicenseID    string
    OrgID        string
    OrgName      string
    ContactName  string
    ContactPhone string
    ContactEmail string
    ExpiresAt    time.Time
    Notified30dAt *time.Time
    Notified7dAt  *time.Time
    Notified1dAt  *time.Time
}
```

### 3.3 New store methods

**`ListExpiringLicenses(ctx, within time.Duration) ([]LicenseWithOrg, error)`**

Returns licenses whose `expires_at` is between `NOW()` and `NOW() + within` and that are not revoked. The caller queries once per interval threshold.

```sql
SELECT l.id, l.org_id, o.name, o.contact_name, o.contact_phone, o.contact_email,
       l.expires_at, l.notified_30d_at, l.notified_7d_at, l.notified_1d_at
FROM   licenses l
JOIN   organizations o ON o.id = l.org_id
WHERE  l.revoked_at IS NULL
  AND  l.expires_at > NOW()
  AND  l.expires_at <= NOW() + $1::interval
```

**`MarkLicenseNotified(ctx, licenseID string, interval string) error`**

Sets the appropriate `notified_*_at` column to `NOW()`. `interval` is one of `"30d"`, `"7d"`, `"1d"`.

```sql
UPDATE licenses SET notified_30d_at = NOW() WHERE id = $1  -- for "30d"
UPDATE licenses SET notified_7d_at  = NOW() WHERE id = $1  -- for "7d"
UPDATE licenses SET notified_1d_at  = NOW() WHERE id = $1  -- for "1d"
```

### 3.4 Existing method used

**`ListUsers(ctx) ([]User, error)`** — already exists; filtered in-process to `role = 'platform_admin'` and `org_id IS NULL`.

---

## 4. Mailer Interface

### 4.1 `ExpiryWarningEmailData` struct

```go
type ExpiryWarningEmailData struct {
    RecipientName  string        // e.g. "Ahmad bin Ali" or "Platform Admin"
    OrgName        string        // e.g. "NACSA"
    LicenseID      string
    ExpiresAt      time.Time
    DaysRemaining  int           // 30, 7, or 1
}
```

### 4.2 New method on `Mailer` interface

```go
SendExpiryWarningEmail(ctx context.Context, to string, data ExpiryWarningEmailData) error
```

The subject line is generated from `DaysRemaining`:

- 30 → `"License expiring in 30 days — action required"`
- 7 → `"License expiring in 7 days — urgent"`
- 1 → `"License expiring tomorrow — immediate action required"`

The email body includes: org name, license ID, expiry date (formatted as `2 Jan 2006`), days remaining, and a call-to-action directing the recipient to contact their Triton administrator.

---

## 5. Background Goroutine

### 5.1 Structure

A single goroutine started in `pkg/licenseserver/server.go` alongside the existing `LoginRateLimiter` janitor. It ticks every hour and checks all three thresholds in sequence.

```go
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
```

### 5.2 `sendExpiryNotifications` logic

For each threshold `(30*24h, "30d")`, `(7*24h, "7d")`, `(24h, "1d")`:

1. Call `ListExpiringLicenses(ctx, within)` to get all qualifying licenses.
2. Filter the returned list to those whose `notified_*d_at` is NULL for this threshold.
3. Collect all platform_admin users (via `ListUsers`, filtered in-process).
4. For each qualifying license:
   a. Build `ExpiryWarningEmailData`.
   b. Send to each platform_admin (by `users.email`).
   c. If `org.contact_email` is non-empty and not already covered by an admin email, send to `org.contact_email` using `org.contact_name` as recipient name.
   d. After all sends for this license (regardless of individual errors), call `MarkLicenseNotified` to prevent repeat storms.
5. Log errors per-recipient without aborting the loop.

### 5.3 Startup wiring

In `pkg/licenseserver/server.go` `Start()` method, launch the goroutine after the existing janitor:

```go
go s.runExpiryNotifications(ctx)
```

No new configuration is needed — the mailer is already constructed in `cmd/licenseserver/main.go` and injected into `Server`.

### 5.4 Nil mailer guard

If `s.mailer == nil` (no `TRITON_LICENSE_SERVER_RESEND_API_KEY` configured), `sendExpiryNotifications` returns immediately after logging a warning. This preserves behavior for deployments that don't configure email.

---

## 6. Organization API Changes

### 6.1 Create and Update org validation

`POST /api/v1/admin/orgs` and `PATCH /api/v1/admin/orgs/{id}` handlers gain validation:

- `contact_name`: required (non-empty after trim), max 100 characters
- `contact_email`: required (non-empty after trim), max 325 characters, must be a valid RFC 5322 address
- `contact_phone`: optional, max 50 characters

Existing rows with empty `contact_name` or `contact_email` are not forced to update — they simply won't receive contact-email notifications until populated.

### 6.2 JSON field names

```json
{
  "contact_name": "Ahmad bin Ali",
  "contact_phone": "+60123456789",
  "contact_email": "ahmad@nacsa.gov.my"
}
```

The old `contact` JSON key is removed from create/update payloads. Read responses include all three new fields.

---

## 7. Testing

### 7.1 Unit tests (`pkg/licensestore/`, `pkg/licenseserver/`, `internal/mailer/`)

| Test | What it checks |
|------|----------------|
| `TestMarkLicenseNotified_30d` | Sets `notified_30d_at`, leaves others NULL |
| `TestMarkLicenseNotified_7d` | Sets `notified_7d_at`, leaves others NULL |
| `TestMarkLicenseNotified_1d` | Sets `notified_1d_at`, leaves others NULL |
| `TestMarkLicenseNotified_InvalidInterval` | Returns error for unknown interval |
| `TestListExpiringLicenses_WithinWindow` | Returns only licenses in window |
| `TestListExpiringLicenses_ExcludesRevoked` | Revoked licenses excluded |
| `TestListExpiringLicenses_ExcludesExpired` | Past-expiry licenses excluded |
| `TestSendExpiryNotifications_SkipsIfAlreadyNotified` | Does not re-send when column is set |
| `TestSendExpiryNotifications_SkipsEmptyContactEmail` | No send when `contact_email` is empty |
| `TestSendExpiryNotifications_NilMailer` | Returns early without panic |
| `TestOrgAPI_CreateValidation_RequiresContactNameAndEmail` | 400 on missing required fields |

### 7.2 Integration tests (`test/integration/`)

| Test | What it checks |
|------|----------------|
| `TestExpiryNotifications_30dTriggered` | License expiring in 25 days → 30d email sent to admins + contact |
| `TestExpiryNotifications_AlreadyNotified_NoResend` | `notified_30d_at` set → no second send |
| `TestExpiryNotifications_ContactEmailSkippedIfEmpty` | Org with no `contact_email` → only admin emails sent |
| `TestOrgContactFields_CRUD` | Create/read/update org with all 3 contact fields round-trip correctly |
| `TestOrgContactFields_Validation` | Missing `contact_name` or `contact_email` → 400 |
| `TestOrgContactFields_MigrationCompat` | Existing row with empty contact fields → readable without error |

### 7.3 E2E tests (`test/e2e/license-admin.spec.js`)

| Test | What it checks |
|------|----------------|
| `org create form shows contact_name, contact_phone, contact_email fields` | Form fields present |
| `org create requires contact_name and contact_email` | Validation error shown on submit without required fields |
| `org detail page shows all three contact fields` | Read path displays stored values |

---

## 8. Key Files

| File | Change |
|------|--------|
| `pkg/licensestore/migrations.go` | Add migration: rename `contact` → `contact_name`, add `contact_phone`, `contact_email`, add 3 `notified_*d_at` columns |
| `pkg/licensestore/types.go` | Update `Organization` struct, add `LicenseWithOrg` struct |
| `pkg/licensestore/store.go` | Add `ListExpiringLicenses`, `MarkLicenseNotified`; update org CRUD methods |
| `internal/mailer/mailer.go` | Add `ExpiryWarningEmailData`, `SendExpiryWarningEmail` to interface and `ResendMailer` |
| `pkg/licenseserver/server.go` | Add `runExpiryNotifications` goroutine, wire in `Start()` |
| `pkg/licenseserver/handlers_orgs.go` | Add `contact_name`/`contact_phone`/`contact_email` validation on create + update |
| `pkg/licenseserver/ui/dist/app.js` | Update org form and detail view with new contact fields |

---

## 9. Out of Scope

- Email templates stored in database (plain Go string templates are sufficient)
- Per-license notification opt-out
- Notification history in the admin UI
- Resend on partial failure (if one recipient fails, others still get it; `MarkLicenseNotified` is always called after all attempts)
- Rate limiting the notification goroutine beyond the hourly ticker
