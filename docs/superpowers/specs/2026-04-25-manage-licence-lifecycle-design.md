# Manage Portal — Licence Lifecycle Design

## Goal

Add full licence lifecycle management to the Manage Portal's `/admin/licence` page: one-click licence refresh, replace-key for genuine key changes, and queued deactivation with grace period for running scan jobs.

## Architecture

Three new admin endpoints on the Manage Server handle the lifecycle operations. A background deactivation watcher goroutine fires when a pending deactivation is scheduled. The Manage Portal gains three inline action buttons and two modals on the existing `Licence.vue` page.

**Tech Stack:** Go (Chi), PostgreSQL (pgx/v5), Vue 3 + Pinia, `@triton/api-client`

---

## Section 1: API Surface

All endpoints require JWT admin auth (existing `JWTAuth` middleware).

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/admin/licence/refresh` | Re-calls `Activate()` with stored key + URL; updates token; refreshes guard in-place |
| `POST` | `/api/v1/admin/licence/replace` | Body `{ "license_key": "…" }`; calls `Activate()` with stored URL + new key; updates key + token; refreshes guard |
| `POST` | `/api/v1/admin/licence/deactivate` | 0 active scans → immediate deactivate. N > 0 → set `pending_deactivation=true`, block new scan jobs |
| `DELETE` | `/api/v1/admin/licence/deactivation` | Cancel a pending deactivation (clears flag, resumes accepting scan jobs) |

`GET /api/v1/admin/licence` gains two new response fields:

```json
{
  "pending_deactivation": false,
  "active_scans": 0
}
```

### Error responses

| Scenario | Status | Body |
|----------|--------|------|
| License Server rejects key (expired, not found) | 422 | `{"error": "<reason from License Server>"}` |
| No activation stored (nothing to refresh) | 409 | `{"error": "no active licence to refresh"}` |
| Deactivation already pending | 409 | `{"error": "deactivation already pending"}` |
| License Server unreachable on deactivate | 200 | Local activation cleared anyway; seat orphaned on License Server (admin cleans up via License Portal) |

---

## Section 2: Data Model

### Migration (manage_setup)

```sql
ALTER TABLE manage_setup
  ADD COLUMN pending_deactivation boolean NOT NULL DEFAULT false;
```

No new tables. The deactivation watcher is an in-process goroutine — no additional DB state required.

### New Store Methods (`pkg/managestore`)

```go
// UpdateLicenseToken replaces the stored signed token after a refresh.
UpdateLicenseToken(ctx context.Context, token string) error

// UpdateLicenseKey replaces the stored license key and signed token after a replace.
UpdateLicenseKey(ctx context.Context, key, token string) error

// SetPendingDeactivation sets or clears the pending_deactivation flag.
SetPendingDeactivation(ctx context.Context, pending bool) error

// ClearLicenseActivation wipes key, token, license_server_url, and instance_id
// from manage_setup and clears pending_deactivation. Server enters setup mode
// on next guard read.
ClearLicenseActivation(ctx context.Context) error
```

`GetSetup()` already returns the full setup row; the new `pending_deactivation` column is included automatically once the migration runs.

---

## Section 3: Backend Handlers (`pkg/manageserver`)

### `handleLicenceRefresh` (POST /admin/licence/refresh)

1. Read setup state via `store.GetSetup()` — 409 if not activated
2. Call `license.NewServerClient(state.LicenseServerURL).Activate(state.LicenseKey)` — 422 on error with License Server reason
3. Call `store.UpdateLicenseToken(ctx, resp.Token)`
4. Call `s.refreshGuard(resp.Token)` — swaps guard in-place under `s.mu` without dropping the server into setup mode
5. Return 200 `{"ok": true, "tier": "…", "expires_at": "…"}`

### `handleLicenceReplace` (POST /admin/licence/replace)

1. Decode `{ "license_key": "…" }` — 400 if empty
2. Read setup state — 409 if not activated (must have active licence to replace)
3. Call `Activate(newKey)` against stored URL — 422 on error
4. Call `store.UpdateLicenseKey(ctx, newKey, resp.Token)`
5. Call `s.refreshGuard(resp.Token)`
6. Return 200 `{"ok": true, "tier": "…", "expires_at": "…"}`

### `handleLicenceDeactivate` (POST /admin/licence/deactivate)

1. Read setup state — 409 if not activated
2. Check `state.PendingDeactivation` — 409 if already pending
3. Count active scan jobs via `scanjobsStore.CountActive(ctx)`
4. If count == 0: call `s.deactivateNow(ctx)` (see watcher section), return 200
5. If count > 0:
   - Call `store.SetPendingDeactivation(ctx, true)`
   - Return 202 `{"pending": true, "active_scans": N}`

### `handleCancelDeactivation` (DELETE /admin/licence/deactivation)

1. Call `store.SetPendingDeactivation(ctx, false)`
2. Return 200 `{"ok": true}`

### `handleLicenceSummary` (GET /admin/licence) — extended

Existing handler gains:
- `pending_deactivation` from `state.PendingDeactivation`
- `active_scans` from `scanjobsStore.CountActive(ctx)` (0 if error, non-fatal)

### `refreshGuard(token string)` — new internal helper

```go
func (s *Server) refreshGuard(token string) {
    newGuard := license.NewGuardFromToken(token, s.cfg.PublicKey)
    s.mu.Lock()
    s.licenceGuard = newGuard
    s.mu.Unlock()
}
```

Called by both refresh and replace handlers. Does not restart the usage pusher (pusher keeps running with the existing config).

### `deactivateNow(ctx)` — new internal helper

```go
func (s *Server) deactivateNow(ctx context.Context) error {
    state, _ := s.store.GetSetup(ctx)
    client := license.NewServerClient(state.LicenseServerURL)
    if err := client.Deactivate(state.LicenseKey); err != nil {
        log.Printf("licence: deactivate remote: %v (clearing local anyway)", err)
    }
    if err := s.store.ClearLicenseActivation(ctx); err != nil {
        return err
    }
    s.stopLicence()
    return nil
}
```

Remote deactivation failure is non-fatal — local activation is always cleared. The orphaned seat on the License Server can be cleaned up by Triton via the License Portal.

---

## Section 4: Deactivation Watcher

A goroutine started in `Server.Run()` alongside the existing usage pusher.

```go
func (s *Server) runDeactivationWatcher(ctx context.Context) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            state, err := s.store.GetSetup(ctx)
            if err != nil || !state.PendingDeactivation {
                continue
            }
            n, err := s.scanjobsStore.CountActive(ctx)
            if err != nil || n > 0 {
                continue
            }
            if err := s.deactivateNow(ctx); err != nil {
                log.Printf("deactivation watcher: %v", err)
            }
            return
        }
    }
}
```

**Scan job gate:** `handleCreateScanJob` checks `state.PendingDeactivation` and returns `409 {"error": "deactivation pending; no new scan jobs accepted"}` while the flag is set.

---

## Section 5: Frontend

### `Licence.vue` changes

Remove the existing "Re-activate" button (currently routes to `/setup/license`).

Add a pending deactivation banner at the top of the page (visible when `summary.pending_deactivation`):

```
⚠ Deactivation pending — waiting for N active scan(s) to finish.  [Cancel]
```

Add three inline action buttons at the bottom of the page:

```
[↻ Refresh]   [Replace Key]   [⊘ Deactivate]
```

**Refresh** — no modal. On click: spinner on button, call `refreshLicence()`, show inline success/error for 3s, reload summary.

**Replace Key** — opens `TReplaceKeyModal`:
- Read-only field: License Server URL (from summary or config)
- Editable field: License Key (text input, monospace)
- Submit → `replaceLicenceKey({ license_key })` → close modal + reload summary on success, show inline error on failure

**Deactivate** — opens `TDeactivateModal` with two states:
- *No active scans (`active_scans == 0`):* Warning text + red "Deactivate" button → calls `deactivateLicence()` → redirect to `/setup/license` on success
- *Scans running (`active_scans > 0`):* Amber warning showing count + amber "Schedule Deactivation" button → calls `deactivateLicence()` → closes modal + banner appears

### Licence store (`src/stores/licence.ts`) changes

`LicenceSummary` type gains `pending_deactivation: boolean` and `active_scans: number`.

### API client additions (`@triton/api-client`)

```typescript
refreshLicence: () =>
  http.post<{ ok: boolean; tier: string; expires_at: string }>('/v1/admin/licence/refresh', {}),

replaceLicenceKey: (req: { license_key: string }) =>
  http.post<{ ok: boolean; tier: string; expires_at: string }>('/v1/admin/licence/replace', req),

deactivateLicence: () =>
  http.post<{ pending?: boolean; active_scans?: number }>('/v1/admin/licence/deactivate', {}),

cancelDeactivation: () =>
  http.delete<{ ok: boolean }>('/v1/admin/licence/deactivation'),
```

---

## Section 6: Testing

### Integration tests (`test/integration/`)

- `TestManageLicence_Refresh` — activate → refresh → guard still live, new token stored
- `TestManageLicence_ReplaceKey` — activate with key A → replace with key B → guard reflects new tier
- `TestManageLicence_Deactivate_Immediate` — activate → deactivate (no scans) → setup mode, 503 on admin routes
- `TestManageLicence_Deactivate_Queued` — activate → create running scan job → deactivate → 202 + pending flag → complete scan → watcher fires → setup mode
- `TestManageLicence_CancelDeactivation` — activate → queue deactivation → cancel → flag cleared, new scan jobs accepted

### Unit tests

- `TestDeactivationWatcher_FiresOnZeroScans`
- `TestDeactivationWatcher_CancelledContext`
- `TestHandleLicenceRefresh_RemoteError` — 422 propagated
- `TestHandleLicenceDeactivate_AlreadyPending` — 409

### Vitest component tests

- `Licence.vue` — pending banner renders when `pending_deactivation=true`
- `TDeactivateModal` — shows amber state when `active_scans > 0`
- `TReplaceKeyModal` — shows error message on 422 response

---

## Out of Scope

- Air-gapped / offline token activation (no current customers; separate future spec)
- Automatic token refresh via heartbeat (License Server returns refreshed token in `/validate` response)
- License Server expiry email notifications (separate future spec — see `project_license_expiry_notifications.md`)
