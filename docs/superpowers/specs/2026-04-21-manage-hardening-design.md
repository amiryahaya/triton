# Manage Server Hardening — Design

> **Status:** Approved 2026-04-21 (brainstorm transcript). One bundled PR shipping 6 XS/S-tier items surfaced as gaps after PR #85 (B2.2) and PR #86 (C). Branched from `feat/manage-password-change` (PR #87) so the hardening work depends on the password-change view + App.vue topbar changes; rebase onto main post-#87-merge.

## 1. Problem

After PR #86 (Manage Portal Vue UI) shipped, six small hardening items remain before the Manage Portal is comfortable for daily operator use:

1. `POST /setup/license` accepts `http://` License Server URLs, leaking the license key in plaintext on the wire.
2. The gateway `:8443` server-leaf is valid for 90 days and minted once at startup. No telemetry — operators learn about expiry when agent handshakes fail silently.
3. The gateway listener is a one-shot at `Server.Run()` entry. When setup completes post-`Run()`, the listener never comes up until a manual process restart.
4. Deleting a zone or host from the Vue portal shows a bland "are you sure?" modal without spelling out the cascade effects on hosts/scan-jobs.
5. The Licence view shows a placeholder "Active" string; no backing endpoint surfaces real guard state or cap usage.
6. The Settings view renders static config values compiled at build time; no backing endpoint reads the live runtime config.

This design ships all six as one cohesive PR.

### Goals

- Reject plaintext-HTTP License Server URLs at `/setup/license` unless explicit dev-escape env var is set.
- Expose gateway listener + cert state through a new `/api/v1/admin/gateway-health` endpoint, polled every 60s from the portal, with a warning pill visible ≤14 days before expiry.
- Gateway listener comes up automatically within 5s of CA bootstrap completion, without restart.
- Zone/host delete confirmation modals explain the cascade side-effects (static text, no live-count query).
- Real `/api/v1/admin/licence` endpoint returning tier + features + limits + last-heartbeat, with Licence.vue consuming it.
- Real `/api/v1/admin/settings` endpoint returning live runtime config, with Settings.vue consuming it.
- Full CI green (lint/unit/integration/web build + test/container).

### Non-goals

- **Live cascade-count query** for zone/host deletion. Static text per XS scope. Follow-up if operators ask.
- **Gateway cert auto-renewal.** The server leaf still re-mints only at process restart. Warning telemetry is the mitigation; automatic renewal is future work.
- **Dedicated Gateway Health view.** The new endpoint powers a small pill in the topbar when cert is near-expiry; a full view is overkill.
- **User management CRUD extensions.** Separate M-tier item.
- **Audit log** / password recovery / SSH-agentless credentials. All separate roadmap items.

## 2. Decisions captured from brainstorm

| # | Decision | Choice |
|---|---|---|
| 1 | Bundling | (a) Single PR covering all 6 items |
| 2 | Gateway self-recovery | (a) Background retry loop polling `caStore.Load` every 5s |
| 3 | Cert telemetry surface | (b) New dedicated `/api/v1/admin/gateway-health` endpoint + topbar pill when <14 days |

## 3. Architecture

One PR, six items, ~40 files, ~400–600 LOC net. Branches from `feat/manage-password-change` (currently PR #87 in review). Rebase onto main when #87 merges.

| # | Item | Backend files | Frontend files |
|---|---|---|---|
| 1 | HTTPS enforcement | `pkg/manageserver/handlers_setup.go` + test | — |
| 2 | Gateway-health endpoint | new `pkg/manageserver/handlers_gateway_health.go` + route + test | new `web/apps/manage-portal/src/stores/gatewayHealth.ts` + `App.vue` pill + test + api-client method |
| 3 | Gateway self-recovery | `pkg/manageserver/server.go::runGateway` refactor + test | — |
| 4 | Deletion cascade warning | — | `views/Zones.vue` + `views/Hosts.vue` (confirm dialog text) + test updates |
| 5 | Licence endpoint + rewire | new handler + route + test | `stores/licence.ts` + `views/Licence.vue` rewrite + api-client + test |
| 6 | Settings endpoint + rewire | new handler + route + test | `stores/settings.ts` + `views/Settings.vue` rewrite + api-client + test |

All items ship in one PR because:
- Each is small (3–8 files each).
- No deployment dependencies between them (order can be any).
- Review burden is low when reviewers can read 40 small files sectioned by item.

## 4. Backend items

### 4.1 Item 1 — HTTPS enforcement on `/setup/license`

**File:** `pkg/manageserver/handlers_setup.go::handleSetupLicense`.

After parsing the request body, before calling `license.NewServerClient`:

```go
if !strings.HasPrefix(req.LicenseServerURL, "https://") {
    if os.Getenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER") != "true" {
        writeError(w, http.StatusBadRequest,
            "license_server_url must use https:// "+
            "(set TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER=true for dev)")
        return
    }
}
```

**Tests** (`handlers_setup_test.go` append):
- `TestSetupLicense_RejectsHTTP` — POST `{license_server_url: "http://..."}` returns 400 with "https://" in body.
- `TestSetupLicense_AllowsHTTPWhenEnvSet` — same POST with env set returns happy path.
- `TestSetupLicense_RejectsMissingScheme` — POST `{license_server_url: "example.com"}` returns 400.

### 4.2 Item 2 — `/api/v1/admin/gateway-health`

**New file:** `pkg/manageserver/handlers_gateway_health.go`.

**Response shape:**
```json
{
  "ca_bootstrapped": true,
  "listener_state": "up",
  "cert_expires_at": "2026-07-21T00:00:00Z",
  "cert_days_remaining": 89
}
```

`listener_state` enum: `pending_setup` | `retry_loop` | `up` | `failed`. Matches the `gatewayState` field on `Server` (see §4.3).

Handler logic:
1. Read `gatewayState` atomic field on Server.
2. If `up`: read cached `serverLeaf` on Server (new field), extract `NotAfter`, compute days remaining.
3. Otherwise: `cert_expires_at` is `null`, `cert_days_remaining` is 0.
4. `ca_bootstrapped`: call `caStore.Load(ctx)` once (cheap — single row read); not-found → false, success → true.

**Route:** mount inside existing `/api/v1/admin` subtree after the `requireOperational + jwtAuth + injectInstanceOrg` middleware chain.

**Tests** (`handlers_gateway_health_test.go`, new file):
- `TestGatewayHealth_PendingSetup` — fresh DB, CA not bootstrapped, returns `listener_state=pending_setup`, `cert_expires_at=null`.
- `TestGatewayHealth_Up` — bootstrap CA + run retry loop + assert `listener_state=up`, `cert_expires_at` within 90-day window.

### 4.3 Item 3 — Gateway listener self-recovery

**File:** `pkg/manageserver/server.go`.

Current shape (approximate):
```go
func (s *Server) runGateway(ctx context.Context) error {
    ca, err := s.caStore.Load(ctx)
    if err != nil { return nil } // pending setup — skip
    // ... mint server leaf, start listener
}
```

New shape:
- New `gatewayState atomic.Int32` field on Server with constants `gatewayStatePendingSetup = 0`, `gatewayStateRetryLoop = 1`, `gatewayStateUp = 2`, `gatewayStateFailed = 3`.
- New `serverLeaf tls.Certificate` field on Server (updated when listener starts).
- `Server.Run(ctx)` spawns a goroutine `s.gatewayRetryLoop(ctx)` that:
  1. Sets `gatewayState = pending_setup`.
  2. Every 5s: tries `caStore.Load(ctx)`. On success → break.
  3. Sets `gatewayState = retry_loop`.
  4. Mints server leaf, starts `http.Server` on `cfg.GatewayListen`.
  5. Sets `gatewayState = up` + updates `serverLeaf`.
  6. Blocks until `ctx.Done()` or listener error. Sets `gatewayState = failed` on error.
- The 5s poll interval is a package constant; tests override via config for speed.

**Tests** (`server_gateway_retry_test.go`, new file):
- `TestGatewayRetry_BootstrapsMidRun` — start `Server.Run` without CA, verify `gatewayState == pending_setup`, bootstrap CA via `caStore.Bootstrap`, wait 6s, verify `gatewayState == up`.
- `TestGatewayRetry_CancelStopsRetryLoop` — start Run, cancel ctx, assert retry goroutine exits within 1s.
- `TestGatewayRetry_CancelStopsListener` — start Run with CA present, wait for `up`, cancel ctx, assert listener shuts down.

### 4.4 Item 5 — `/api/v1/admin/licence`

**New handler** in `pkg/manageserver/handlers_admin_licence.go`.

**Response shape:**
```json
{
  "tier": "enterprise",
  "features": { "manage": true },
  "limits": {
    "seats":  { "cap": 100, "used": 7 },
    "hosts":  { "cap": 1000, "used": 42 },
    "agents": { "cap": 50, "used": 3 },
    "scans":  { "cap": 100000, "used": 12345, "soft_buffer_ceiling": 110000 }
  },
  "license_server_url": "https://license.example.com",
  "instance_id": "<uuid>",
  "last_pushed_at": "2026-04-21T12:34:56Z",
  "last_push_error": "",
  "consecutive_failures": 0
}
```

Aggregates three sources:
- `Server.licenceGuard` (via the existing `guardSnapshot()` helper from PR #85 Batch H fix-up): `Tier()`, `HasFeature("manage")`, `LimitCap(metric, window)` × 4, `CurrentUsage(metric, window)` × 4, `SoftBufferCeiling("scans", "monthly")`.
- `managestore.GetSetup()`: `license_server_url`, `instance_id`.
- `scanresults.LoadLicenseState()` (existing B2.2 helper): `last_pushed_at`, `last_push_error`, `consecutive_failures`.

When `licenceGuard == nil`: return 503 with body `"licence inactive"`. Setup-mode users never see this; the `injectInstanceOrg` middleware blocks pre-setup traffic.

**Route:** `/api/v1/admin/licence` inside the admin subtree.

**Tests:**
- `TestLicence_Inactive` — guard nil → 503.
- `TestLicence_Active` — guard wired, seed some usage, assert all fields correct.

### 4.5 Item 6 — `/api/v1/admin/settings`

**New handler** in `pkg/manageserver/handlers_admin_settings.go`.

**Response shape:**
```json
{
  "parallelism": 10,
  "gateway_listen": ":8443",
  "gateway_hostname": "manage.example.com",
  "report_server_url": "https://report.example.com",
  "manage_listen": ":8082",
  "instance_id": "<uuid>",
  "version": "0.1.2-dev"
}
```

Sources:
- `Server.cfg`: `Parallelism`, `GatewayListen`, `GatewayHostname`, `ReportServer`, `Listen` (as `manage_listen`).
- `managestore.GetSetup()`: `instance_id`.
- `internal/version.Version`.

Read-only. No POST/PUT.

**Route:** `/api/v1/admin/settings`.

**Tests:**
- `TestSettings_ReturnsAllFields` — happy path, assert 7 fields present + non-empty (where applicable).

## 5. Frontend items

### 5.1 Item 2 — Gateway cert warning pill

**New store:** `web/apps/manage-portal/src/stores/gatewayHealth.ts`.
- `state`, `certExpiresAt`, `certDaysRemaining` refs.
- `startPolling()` / `stopPolling()` with 60s interval + `document.hidden` guard.

**App.vue:** import the store, start polling on mount (after auth gate passes), stop on unmount. Add a TPill adjacent to the Change-password button:

```vue
<TPill v-if="gatewayHealth.certDaysRemaining !== null && gatewayHealth.certDaysRemaining < 14" variant="warn">
  Gateway cert expires in {{ gatewayHealth.certDaysRemaining }}d
</TPill>
```

On hover, tooltip: "Restart `triton-manageserver` within this window to mint a fresh 90-day cert."

**Tests:** App.vue spec asserts pill present/absent based on store state.

### 5.2 Item 4 — Deletion cascade warning

**`views/Zones.vue`:** update the `TConfirmDialog` message prop:

```
Deleting zone '{name}' will set zone_id to NULL on any hosts in it
(they become unassigned) and on any scan jobs referencing this zone
(audit trail preserved). Zone memberships are cascaded-deleted.
This cannot be undone.
```

**`views/Hosts.vue`:**

```
Deleting host '{hostname}' will set host_id to NULL on scan jobs
referencing it. Historical scan results remain in the queue / Report
Server. This cannot be undone.
```

Static text; no live counts. Message strings reflect migration v6's `ON DELETE SET NULL` policy.

**Tests:** existing Zones/Hosts specs assert the new text is present in the rendered modal.

### 5.3 Item 5 — Licence view rewire

**api-client:** `manageServer.ts` gains:
```ts
getLicence: () => http.get<LicenceSummary>('/v1/admin/licence')
```
plus the `LicenceSummary` + `LimitPair` types in `manageServer.types.ts`.

**`stores/licence.ts`:** replace the placeholder `fetch()` with:
```ts
async function fetch() {
  loading.value = true;
  try { summary.value = await api.get().getLicence(); }
  finally { loading.value = false; }
}
```

**`views/Licence.vue`:** replace the current placeholder content with:
- **Tier card** at top (TStatCard with `label="Tier"`, `value=summary.tier`).
- **Limits table** (TDataTable-style or simple `<table>`): 4 rows (Seats/Hosts/Agents/Scans), columns cap/used/% remaining. For `scans`, include the soft-buffer ceiling in the cap column as a subtext.
- **Heartbeat panel** — last_pushed_at (humanised), license_server_url (shortened), instance_id (monospace + copy button via TCodeBlock).
- **Error panel** (only when `last_push_error != ""` OR `consecutive_failures > 0`): red-accented panel with excerpt truncated to 400 chars + failure count.
- **Re-activate button** stays.

**Tests:** view spec with fake store asserts all sections render; error panel hidden when push state is healthy.

### 5.4 Item 6 — Settings view rewire

**api-client:** `getSettings(): SettingsSummary`.

**`stores/settings.ts::fetch()`:** calls `api.get().getSettings()`.

**`views/Settings.vue`:** the existing `<dl>` structure stays; values now come from the store's real fetch response. Remove the "follow-up PR adds backend endpoint" note.

**Tests:** assert all 7 fields render.

## 6. Error handling

- HTTPS enforcement (item 1): 400 with clear message + env-var hint; no information leakage.
- Gateway-health endpoint (item 2): always returns 200 with best-effort data; DB read failure returns `ca_bootstrapped=false` + log-warning.
- Gateway self-recovery (item 3): retry loop logs every 5s if CA still missing (anti-spam: log only on state transitions or every N retries). Listener start failure → `gatewayState=failed`; admin can inspect via `/gateway-health`.
- Licence endpoint (item 5): 503 when guard nil; 500 only on unrecoverable DB failure (scanresults state or setup missing).
- Settings endpoint (item 6): 500 only on unrecoverable DB failure reading `instance_id`.

## 7. Testing summary

| Layer | New tests |
|---|---|
| Backend (handlers) | `TestSetupLicense_RejectsHTTP`, `TestSetupLicense_AllowsHTTPWhenEnvSet`, `TestSetupLicense_RejectsMissingScheme`, `TestGatewayHealth_PendingSetup`, `TestGatewayHealth_Up`, `TestLicence_Inactive`, `TestLicence_Active`, `TestSettings_ReturnsAllFields` |
| Backend (server) | `TestGatewayRetry_BootstrapsMidRun`, `TestGatewayRetry_CancelStopsRetryLoop`, `TestGatewayRetry_CancelStopsListener` |
| Frontend (views) | Zones/Hosts cascade-warning text, Licence full render, Settings full render, App.vue cert-pill visibility |
| Frontend (api-client) | `getLicence`, `getSettings`, `getGatewayHealth` request-shape tests |

Target: ~15 new backend tests + ~8 new frontend tests. All existing tests continue to pass unchanged.

## 8. Acceptance criteria

- [ ] `POST /setup/license` rejects `http://` URLs unless env var set.
- [ ] `GET /admin/gateway-health` returns shape from §4.2.
- [ ] Gateway listener auto-starts within 5s of CA bootstrap post-Run, without restart.
- [ ] Zones/Hosts delete confirm modal shows the new cascade warning text.
- [ ] `GET /admin/licence` returns shape from §4.4; Licence.vue renders it.
- [ ] `GET /admin/settings` returns shape from §4.5; Settings.vue renders it.
- [ ] Topbar pill visible when cert_days_remaining < 14, absent otherwise.
- [ ] `go build ./...` + `go vet ./...` + `golangci-lint run ./...` clean.
- [ ] `pnpm --filter manage-portal build` + `pnpm --filter manage-portal test` green.
- [ ] CI all green.

## 9. Risks / collision surface

- **PR #87 dependency.** This branch is based on `feat/manage-password-change`. If #87 ships unchanged, rebase onto main after merge is trivial. If #87 requires fixes, those fixes propagate forward; no conflict because both PRs modify disjoint sections of `App.vue` (password-change edits the `onLogin` comment + adds a Change-password button; hardening adds a gateway-cert warning pill next to it).
- **`gatewayState` + `serverLeaf` on Server struct** — new fields accessed from both the retry goroutine and the admin handler. Must use `atomic.Int32` for state + `atomic.Value` or `sync.RWMutex`-guarded reads for `serverLeaf`.
- **Licence endpoint + guard lifecycle.** `Server.licenceGuard` is nil until `startLicence` completes. `guardSnapshot()` from PR #85 Batch H returns nil safely; handler returns 503 in that case.
- **Gateway retry loop + test flakiness.** The 5s default is too slow for tests; make it configurable via `cfg.GatewayRetryInterval` (default 5s, tests override to 100ms).

## 10. Known deferrals

- Live cascade-count query on zone/host delete (item 4 deeper). Static text ships.
- Gateway cert auto-renewal. Warning telemetry ships; auto-renewal is future.
- Dedicated Gateway Health view. Pill in topbar is the UX; no new view.
- Retry-loop failure alerting (e.g., PagerDuty integration when cert expires). Follow-up.
