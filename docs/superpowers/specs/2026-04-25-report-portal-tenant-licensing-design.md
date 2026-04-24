# Report Portal — Superadmin Setup + Tenant Licensing

**Date:** 2026-04-25
**Status:** Approved

---

## Summary

Report Portal is a free, self-hostable service (cloud or on-prem). To register a tenant on a Report Portal instance, a licence issued by the Licence Portal is required. This spec covers:

1. **Superadmin setup** — first platform_admin creation via setup page; invite-email flow with forced password change; superadmin CRUD.
2. **Tenant creation** — superadmin enters a licence key + first tenant admin details; Report Portal activates the licence against the Licence Portal; tenant and admin are provisioned.
3. **Licence lifecycle** — expiry warning + read-only grace period; auto and manual renewal; 7-day grace overlap for migrations between deployments.

Manage Portal and agent communication with Report Portal are out of scope and covered in a separate spec.

---

## Architecture

Report Portal gains a `platform_admin` role sitting above all tenants. Platform admins manage the Report Portal instance itself — they create tenants, manage licences, and invite other platform admins. Tenant users (`org_admin`, `org_user`, `org_officer`) remain unchanged.

Licence validation reuses the existing `internal/license/client.go` (`ServerClient.Activate` / `Validate` / `Deactivate`). No new Licence Portal endpoints are required. The Report Portal identifies itself to the Licence Portal using a stable **instance UUID** stored in the database.

The Licence Portal push mechanism (`report_client.go`) is retired — tenant provisioning is now initiated by the Report Portal superadmin, not the Licence Portal.

---

## Data Model

### Migration additions (Report Portal `pkg/store/`)

**`platform_admin` role** — added to the `role` CHECK constraint on the existing `users` table. `org_id` is `NULL` for platform admins (already nullable).

```sql
-- Version N: add platform_admin role and instance identity
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
    ADD COLUMN IF NOT EXISTS licence_id TEXT NOT NULL DEFAULT '';
```

### `report_instance` table

One row, generated on first boot. The `id` is used as the `machineID` prefix when activating licences: `machineID = instanceID + "/" + tenantID`. This makes each (instance, tenant) pair a unique activation seat.

### `tenant_licences` table

| Column | Description |
|--------|-------------|
| `org_id` | FK to `organizations.id` |
| `licence_id` | Licence UUID from Licence Portal |
| `token` | Signed token returned by Licence Portal on activation |
| `activated_at` | When this tenant was first activated |
| `expires_at` | Expiry from Licence Portal (refreshed on successful validate) |
| `renewed_at` | Last successful online renewal timestamp |
| `status` | `active` / `grace` / `expired` — updated by background validator |

---

## Superadmin Setup Flow

### Setup guard

On startup, the server checks if any `platform_admin` user exists. If not, all non-setup routes return `307 /setup`. The setup endpoint is blocked (returns `409`) once a platform_admin exists.

### Endpoints

**`GET /api/v1/setup/status`** — no auth. Returns `{"ready": true}` when a platform_admin exists, `{"ready": false}` otherwise. Used by the frontend to decide whether to show the setup page or redirect to login.

**`POST /api/v1/setup`** — no auth, blocked after first use. Body:
```json
{ "name": "Alice", "email": "alice@example.com" }
```
- Generates a random 16-character temp password
- Creates `platform_admin` user with `must_change_password = true`
- Sends invite email with temp password
- Returns `201` with user ID

### Invite email flow

All invited users (platform admins and tenant admins) receive the same email:
- From: configured SMTP sender
- Subject: "Your Triton Report Portal invitation"
- Body: login URL + temp password + instructions to change on first login

The JWT issued on login includes `"mustChangePassword": true` when the flag is set. The frontend intercepts this and routes the user to the change-password page before any other navigation.

**`POST /api/v1/auth/change-password`** — clears `must_change_password`. Requires `currentPassword` + `newPassword` (≥ 12 characters).

### Superadmin CRUD

All routes require a `platform_admin` JWT.

- `GET /api/v1/platform/admins` — list all platform admins
- `POST /api/v1/platform/admins` — invite a new platform admin (body: `name`, `email`). Same invite-email flow as setup.
- `DELETE /api/v1/platform/admins/{id}` — remove a platform admin. Returns `400` if attempting to delete self.

---

## Tenant Creation Flow

**`POST /api/v1/platform/tenants`** — platform_admin JWT required. Body:
```json
{
  "licenceKey": "019d...",
  "adminName": "Bob",
  "adminEmail": "bob@acme.com"
}
```

**Steps (all-or-nothing):**

1. Generate `tenantID = newUUIDv7()`
2. Call `LicencePortalClient.Activate(licenceKey, machineID = instanceID + "/" + tenantID)`
3. Validate response: licence must not be revoked, expired, or wrong `product_scope` (must be `report` or `bundle`)
4. Create row in `organizations` (`id = tenantID`, `licence_id = licenceKey`)
5. Insert row in `tenant_licences` (token + `expires_at` from activation response)
6. Create first tenant admin user (`role = org_admin`, `must_change_password = true`)
7. Send invite email to `adminEmail`
8. On any failure after step 2 — call `Deactivate(licenceKey, machineID)` to release the seat

**Error responses:**

| Condition | HTTP | Body |
|-----------|------|------|
| Licence not found | 404 | `"licence not found"` |
| Licence revoked | 422 | `"licence revoked"` |
| Licence expired | 422 | `"licence expired"` |
| Wrong product scope | 422 | `"licence not valid for Report Portal"` |
| Seats exhausted | 422 | `"no seats available"` |
| Already active (outside grace) | 422 | `"licence already in use"` |
| Licence Portal unreachable | 503 | `"licence server unavailable"` |

**Tenant management:**

- `GET /api/v1/platform/tenants` — list tenants with `licenceStatus` (`active`/`grace`/`expired`) and `expiresAt`
- `GET /api/v1/platform/tenants/{id}` — detail
- `POST /api/v1/platform/tenants/{id}/renew` — manual licence renewal (body: `licenceKey`). Deactivates old, activates new.
- `DELETE /api/v1/platform/tenants/{id}` — calls `Deactivate`, marks tenant deleted (data preserved)

---

## Licence Lifecycle

### Background validator

A goroutine starts at server boot and runs every 24 hours. For each tenant with status `active` or `grace`:

1. Call `LicencePortalClient.Validate(licenceID, token)`
2. On success: update `token`, `expires_at`, `renewed_at` in `tenant_licences`
3. On Licence Portal unreachable: no state change — cached token remains valid until `expires_at`
4. Recompute `status` based on `expires_at` and now:
   - `expires_at > now` → `active`
   - `expires_at < now` AND `expires_at > now - 30 days` → `grace`
   - `expires_at < now - 30 days` → `expired`

### Expiry enforcement middleware

A middleware applied to all tenant-scoped routes checks `tenant_licences.status` for the request's `org_id`:

| Status | Effect |
|--------|--------|
| `active` | Pass through |
| `grace` | Pass through + inject `X-Licence-Grace: true` header (frontend shows banner) |
| `expired` | Return `403 {"error": "licence expired"}` |

Warning banner appears 14 days before `expires_at` and throughout the grace period. Shown to all tenant users.

### Manual renewal

`POST /api/v1/platform/tenants/{id}/renew` with `{"licenceKey": "new-uuid"}`:
1. Activate new licence (same flow as creation)
2. Deactivate old licence
3. Update `tenant_licences` row with new `licence_id`, `token`, `expires_at`
4. Set `status = active`

Works offline if the new licence key is cryptographically self-contained (Ed25519 fallback).

### Migration / grace overlap

When a tenant moves to a new Report Portal deployment:

1. Superadmin on new deployment creates the tenant with the same licence key
2. Licence Portal records a second activation (new `machineID`)
3. Old deployment's token continues to validate for up to 7 days (Licence Portal grace window)
4. After 7 days, old token stops validating → old deployment enters `grace` then `expired` naturally
5. Vendor can force-deactivate the old instance from Licence Portal admin UI if needed

---

## Frontend

### New views

| View | Route | Auth |
|------|-------|------|
| `Setup.vue` | `/setup` | None |
| `ChangePassword.vue` | `/change-password` | JWT (any role) |
| `PlatformAdmins.vue` | `/platform/admins` | `platform_admin` |
| `Tenants.vue` | `/platform/tenants` | `platform_admin` |
| `TenantDetail.vue` | `/platform/tenants/:id` | `platform_admin` |

### Behaviour

- **Setup guard** — App.vue checks `/api/v1/setup/status` on load; if `ready: false`, redirects to `/setup` before rendering anything else
- **Change-password interstitial** — if JWT contains `mustChangePassword: true`, router redirects to `/change-password` on every navigation until cleared
- **Licence status badge** — `Tenants.vue` renders a `TPill` per row: `safe` (active), `warn` (grace), `unsafe` (expired)
- **Renew button** — on `TenantDetail.vue`, opens a modal to enter a new licence key

---

## Tests

### Backend integration

- `TestSetup_FirstAdmin` — setup creates platform_admin, blocks second call with 409
- `TestSetup_InviteEmail` — invite email sent with temp password, `must_change_password = true`
- `TestLogin_PlatformAdmin` — JWT contains `role=platform_admin`, `org_id` absent
- `TestLogin_MustChangePassword` — JWT issued but frontend flag set
- `TestChangePassword_ClearsFlag` — flag cleared after successful change
- `TestCreateTenant_ValidLicence` — org + tenant_licence row created, admin user invited
- `TestCreateTenant_InvalidLicence` — revoked, expired, wrong scope, seats exhausted
- `TestCreateTenant_LicencePortalUnreachable` — returns 503, no partial state left
- `TestLicenceExpiry_GraceEnforcement` — scans blocked, GET reads allowed, banner header present
- `TestLicenceExpiry_HardExpired` — 403 on all tenant routes
- `TestLicenceRenewal_Manual` — new key replaces old activation, status resets to active
- `TestLicenceMigration_GraceOverlap` — two activations coexist, old expires naturally

### Frontend (Vitest)

- `Setup.spec.ts` — form validation, success redirect to login
- `PlatformAdmins.spec.ts` — list, invite, delete (cannot delete self)
- `Tenants.spec.ts` — list with status badges, create modal, renew button

---

## Backward Compatibility

Existing tenants provisioned via the old Licence Portal push mechanism have no `tenant_licences` row. The expiry enforcement middleware treats a missing row as `active` (bypass). A future migration can backfill rows when tenants are re-registered with their licence keys. No forced migration is required at rollout.

---

## Out of Scope

- Manage Portal and agent communication with Report Portal (separate spec)
- Bulk tenant operations
- Tenant data export / deletion (GDPR)
- SSO for platform admins
- Licence Portal UI changes (no new Licence Portal endpoints required)
