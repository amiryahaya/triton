# Org Suspend Action + Activations Column

**Date:** 2026-04-24
**Status:** Approved

## Summary

Two additions to the Organisations view in the License Portal:

1. **Suspend action** — hard-suspend an organisation so that both new activations and validation of existing active machines are rejected immediately.
2. **Activations column** — show the count of active activations for the organisation, displayed only when the org has at least one seated (seats > 0) licence; otherwise shows `—`.

---

## Backend

### Migration 8

```sql
ALTER TABLE organizations ADD COLUMN suspended BOOLEAN NOT NULL DEFAULT FALSE;
```

Applied in `pkg/licensestore/migrations.go` as version 8.

### Data model

`Organization` in `pkg/licensestore/store.go` gains three fields:

```go
type Organization struct {
    ID                  string    `json:"id"`
    Name                string    `json:"name"`
    Contact             string    `json:"contact"`
    Notes               string    `json:"notes"`
    Suspended           bool      `json:"suspended"`
    ActiveActivations   int       `json:"activeActivations"`
    HasSeatedLicenses   bool      `json:"hasSeatedLicenses"`
    CreatedAt           time.Time `json:"createdAt"`
    UpdatedAt           time.Time `json:"updatedAt"`
}
```

`ActiveActivations` and `HasSeatedLicenses` are read-only computed fields populated by the `ListOrgs` query. They are never written to the database.

### Store interface

One new method added to `Store`:

```go
SuspendOrg(ctx context.Context, id string, suspended bool) error
```

Simple `UPDATE organizations SET suspended = $1, updated_at = NOW() WHERE id = $2`.

`ListOrgs` is enriched with two subqueries:

```sql
SELECT
    o.*,
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
```

### API endpoint

`POST /api/v1/admin/orgs/{id}/suspend`

Request body:
```json
{ "suspended": true }
```

Response: `204 No Content` on success.

Errors: `404` if org not found, `400` if body is malformed.

Writes an audit entry of type `org_suspended` or `org_unsuspended` accordingly.

### Suspend enforcement

Two existing handlers gain an org-suspension check after loading the licence:

- `handleActivate` (client `POST /api/v1/activate`) — returns `403 {"error":"organisation suspended"}` if `org.Suspended`.
- `handleValidate` (client `POST /api/v1/validate`) — returns `403 {"error":"organisation suspended"}` if `org.Suspended`.

The check requires one additional `GetOrg` call per request (licence is already loaded in both paths). No middleware layer is added; the check lives inside each handler to keep the logic co-located with the other licence validity checks.

---

## Frontend

### `web/packages/api-client/src/types.ts`

`Organisation` gains three fields:

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

### `web/packages/api-client/src/licenseServer.ts`

New method:

```ts
suspendOrg: (id: string, suspended: boolean) =>
  http.post<void>(`/v1/admin/orgs/${id}/suspend`, { suspended }),
```

### `Organisations.vue`

**Columns** (updated):

| Key | Label | Width |
|-----|-------|-------|
| `name` | Name | `1.5fr` |
| `contact` | Contact | `1.2fr` |
| `notes` | Notes | `1.5fr` |
| `activeActivations` | Activations | `0.9fr` |
| `createdAt` | Created | `1fr` |
| `updatedAt` | Updated | `1fr` |
| `id` | *(actions)* | `180px` |

**Activations cell**: renders the numeric count when `row.hasSeatedLicenses === true`; renders `—` otherwise.

**Actions cell**: two buttons side by side.
- **Suspend / Unsuspend** — `variant="warn"` / `variant="default"`. Calls `suspendOrg` then refreshes the row in-place (no full reload). Shows toast on success/error.
- **Delete** — unchanged, `variant="danger"`.

**Suspended row indicator**: a `TPill` badge ("Suspended", `variant="unsafe"`) rendered next to the org name in the name cell when `row.suspended === true`.

### `OrganisationDetail.vue`

- **Status** field added to the kv grid: `Active` (`safe` pill) or `Suspended` (`unsafe` pill).
- **Suspend / Unsuspend** button added to the `TPanel` `#action` slot, beside any future edit button.

---

## Tests

### Backend (Go)

- `TestSuspendOrg_StoreMethod` — round-trip suspend/unsuspend.
- `TestListOrgs_ComputedFields` — `active_activations` and `has_seated_licenses` populated correctly from fixture data.
- `TestHandleActivate_OrgSuspended` — returns 403 when org is suspended.
- `TestHandleValidate_OrgSuspended` — returns 403 when org is suspended.
- `TestHandleSuspendOrg_Handler` — 204 on success, 404 on missing org, 400 on bad body.

### Frontend (Vitest)

- `Organisations.spec.ts` — update fixture to include `suspended`, `activeActivations`, `hasSeatedLicenses`; add tests for: Activations cell shows count when seated, shows `—` when not; Suspend button calls API and updates row; Unsuspend button calls API and updates row.
- `OrganisationDetail.spec.ts` (new) — Status pill shows correct variant; Suspend button present.

---

## Out of scope

- Bulk suspend (multiple orgs at once).
- Suspend reason / notes field.
- Email notification on suspend.
- Automatic suspension on licence expiry (separate feature).
