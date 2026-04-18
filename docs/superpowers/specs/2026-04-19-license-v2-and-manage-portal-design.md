# License Server v2 + Manage Portal standalone — Design Spec

- **Date:** 2026-04-19
- **Status:** Draft — awaiting user review
- **Scope:** (1) Expand the License Server to support feature flags, per-metric limits (windows: total · monthly · daily), usage-tracking, soft-buffer grace, and online activation for both Report Portal and Manage Portal. (2) Stand up the Manage Portal as a standalone containerised binary with its own auth, users, scanner capabilities, and License Server integration. (3) Migrate the existing vanilla-JS manage UI (`pkg/server/ui/dist/manage/`) to a Vue 3 app consuming `@triton/ui`, ship under the new Manage Server binary.
- **Out of scope:** Rewriting scan handler logic (re-mounted as-is), new scanner algorithms, changes to agent-side licence code (`agent.yaml` flow unchanged), third Manage binary variants (single production binary), compliance content (NACSA Arahan 9 rules stay as-is).

---

## 1. Problem

Triton's licence model today supports a 3-tier gating system (`free`/`pro`/`enterprise`) with one dimension: agent seats, bound to a single org. This doesn't express:

- **Per-product entitlements** — a customer might buy Report-only, Manage-only, or both.
- **Volume-based metering** — scans run, reports generated, report downloads, hosts onboarded. Each has distinct unit-economics.
- **Windowed caps** — "10 000 scans per month, 1 M total" needs both a rolling-window cap and a lifetime cap.
- **Compliance retention** — customers need licence-driven retention (SOC 2 / HIPAA / NACSA windows).
- **Near-real-time enforcement** — today, licence validation is install-time and daily; we need sub-minute enforcement to reject over-cap activations and scan jobs.
- **Multi-tenant entitlement** — the current licence doesn't cap how many tenants a Report Portal deployment can host.

Simultaneously, the Manage-Portal-as-a-subfolder pattern (`pkg/server/ui/dist/manage/` served by the Report Server) means:

- Network engineers and security officers share an auth surface they don't share use-cases for.
- Manage-specific roles (`network_engineer`, `network_admin`) and setup flows are bolted onto a tenant-scoped auth model that doesn't fit.
- The natural deployment topology (Manage per-customer on-prem, Report cloud-or-on-prem) is blocked by tight coupling.

### Goals

1. One licence schema describes **any** product + limit combination, extensible via JSONB without schema migrations.
2. Report Portal and Manage Portal both **require online licence activation**; both **report near-real-time usage** back to License Server.
3. Licence enforcement is **hard** on allocation metrics (seats, hosts, tenants) and **soft** on activity metrics (scans, reports, downloads) with a uniform `soft_buffer_pct` grace.
4. Manage Portal ships as its own binary (`cmd/manageserver/`), own Vue UI, own auth, own DB schema. Deployable via Podman/Docker on a configurable port.
5. Manage Portal performs network-port and SSH-agentless scans and pushes results to Report Server over mTLS, reusing the existing engine enrolment pattern (`bundle.tar.gz`).
6. Feature flags (`comprehensive_profile`, `diff_trend`, `custom_policy`, `export_formats`) move from hard-coded tier gates to per-licence flags, preserving current tier behaviour as defaults.

### Non-goals

- **No changes to scan handler logic.** `pkg/server/{scanjobs,engine,agentpush,credentials,discovery,groups,hosts}` handlers are re-mounted by the Manage Server; bodies stay untouched.
- **No vendor-hosted multi-customer cloud Report Portal.** Each customer (cloud or on-prem) stands up their own Report Portal; only the `tenants` cap differs.
- **No SSO in this spec.** `features.sso` is declared but implementation is deferred.
- **Manage Portal is single-tenant.** It does not carry a tenants cap; it is owned by exactly one customer.
- **Legacy tier field stays backward-compatible** — existing tokens with only `tier: "pro"` resolve to feature flags via a compatibility mapping until they're re-issued.

---

## 2. Product architecture (as ratified by this spec)

```
┌───────────────────────────────────────────────────────────────────────┐
│ License Server  (vendor-operated, :8081)                              │
│ ─ issues licences with features[] + limits[] + soft_buffer_pct        │
│ ─ accepts usage reports every ~60s from Report + Manage instances     │
│ ─ enforces caps in activate / validate / usage responses              │
│ ─ Vue admin UI (shipped — updated by this spec)                       │
└───────────────────────▲─────────────────▲─────────────────────────────┘
                        │ activate/       │ activate/
                        │ validate/usage  │ validate/usage
                        │ (mTLS)          │ (mTLS)
            ┌───────────┴────────┐  ┌─────┴───────────────┐
            │ Report Portal      │  │ Manage Portal       │
            │ (:8080, per-cust.) │  │ (:8082, per-cust.)  │
            │ ─ multi-tenant     │  │ ─ single-tenant     │
            │ ─ Vue UI (shipped) │  │ ─ Vue UI (PR C)     │
            │ ─ JWT auth, roles  │  │ ─ JWT auth, roles   │
            │ ─ users table      │  │ ─ separate users    │
            │ ─ scan ingestion   │  │ ─ zones + hosts     │
            │ ─ analytics        │  │ ─ scan orchestrator │
            │ ─ NACSA reports    │  │ ─ port + SSH scans  │
            └────────────▲───────┘  └────────┬────────────┘
                         │ scan results      │
                         │ (mTLS, enrolment) │
                         └───────────────────┘
                                             │
        ┌────────────────────────────────────┼──────────────┐
        │ Agents (in-host, per-host licence via agent.yaml) │
        │ ─ push scan results direct to Report (over mTLS)  │
        │ ─ also consume tenant seats + scans caps          │
        └───────────────────────────────────────────────────┘
```

### Deployment rules (updated from the 2026-04-17 memo)

1. **License Server** — vendor-operated, single instance, 8081.
2. **Report Portal** — customer owns, cloud or on-prem, single deployment per customer, 8080. Multi-tenant (cap per licence).
3. **Manage Portal** — optional, single-tenant, on-prem (customer network), 8082 default. Adds value for large fleets; small fleets run agents direct-to-Report.
4. **Agents** — per-host, push scan results direct to Report over mTLS.
5. All three portals validate online against License Server at startup + periodically. Cache a 7-day offline grace.

---

## 3. License Server v2

### 3.1 Licence schema changes

Current `licenses` row:

```sql
id UUID, org_id UUID, key TEXT, tier TEXT, seats INT,
issued_at, expires_at, bound BOOLEAN, machine_id TEXT,
revoked_at, revoked_by
```

Add:

```sql
-- New columns
features          JSONB       NOT NULL DEFAULT '{}',
limits            JSONB       NOT NULL DEFAULT '[]',
soft_buffer_pct   SMALLINT    NOT NULL DEFAULT 10,
product_scope     TEXT        NOT NULL DEFAULT 'legacy',  -- 'legacy' | 'report' | 'manage' | 'bundle'
```

**`features`** (object):

```json
{
  "report": true,
  "manage": true,
  "comprehensive_profile": true,
  "diff_trend": true,
  "custom_policy": false,
  "sso": false,
  "export_formats": ["html", "pdf", "csv", "json", "sarif"]
}
```

`agent` is **always implicit** given any licence exists (free with any Report or Manage entitlement). We do not store it.

**`limits`** (array of limit entries):

```json
[
  { "metric": "seats",             "window": "total",   "cap": 50 },
  { "metric": "tenants",           "window": "total",   "cap": 3 },
  { "metric": "hosts",             "window": "total",   "cap": 1000 },
  { "metric": "scans",             "window": "monthly", "cap": 10000 },
  { "metric": "scans",             "window": "total",   "cap": 1000000 },
  { "metric": "reports_generated", "window": "total",   "cap": 5000 },
  { "metric": "report_downloads",  "window": "total",   "cap": 50000 },
  { "metric": "retention_days",    "window": "total",   "cap": 365 }
]
```

- `metric` ∈ {`seats`, `tenants`, `hosts`, `scans`, `reports_generated`, `report_downloads`, `retention_days`}. Extensible — adding new metrics never requires schema migration.
- `window` ∈ {`total`, `daily`, `monthly`}. For `retention_days`, window is always `total` (it's a duration, not a count).
- `cap` — integer. Absent entry ⇒ unlimited.

**`soft_buffer_pct`** — uniform grace percentage applied to all soft-enforced metrics (see §3.4). Range 0–25, default 10.

**`product_scope`** (enum):
- `legacy` — licence pre-dates v2, `features`/`limits` derived via compatibility mapping (see §3.6).
- `report` — Report Portal entitlement only.
- `manage` — Manage Portal entitlement only.
- `bundle` — both Report and Manage enabled.

Primarily used in the Admin UI and in the activation protocol's `product` field, not in enforcement.

### 3.2 Usage-tracking table

New table:

```sql
CREATE TABLE license_usage (
    license_id      UUID        NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    instance_id     UUID        NOT NULL,              -- Report/Manage instance that reported
    metric          TEXT        NOT NULL,
    window          TEXT        NOT NULL,              -- matches limits[].window
    value           BIGINT      NOT NULL,              -- current count for the window
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (license_id, instance_id, metric, window)
);

CREATE INDEX ON license_usage (reported_at);
```

**Write semantics:** `INSERT ... ON CONFLICT (license_id, instance_id, metric, window) DO UPDATE SET value = EXCLUDED.value, reported_at = NOW()`.

**Retention:** raw rows kept 30 days. For long-term trend / billing, a rolled-up view per (license_id, metric, window, day) in `license_usage_daily`.

### 3.3 Activation + validation protocol

#### `POST /v1/license/activate`

Consumer sends:
```json
{
  "license_key": "ACME-BUNDLE-2026-A",
  "instance_id": "uuid-v4",
  "product": "manage",       // report | manage
  "fingerprint": "sha3-256(hostname|GOOS|GOARCH)"
}
```

Server responds:
```json
{
  "ok": true,
  "features": {...},
  "limits": [...],
  "soft_buffer_pct": 10,
  "usage": {                        // current usage (for the consumer's instance)
    "seats": { "total": 12 },
    "scans": { "monthly": 147, "total": 14203 }
  },
  "grace_seconds": 604800,
  "signed_token": "base64url.eyJ..."    // consumer caches for offline grace
}
```

Activation validates: licence not expired, not revoked, `product` matches features (e.g., `product=manage` requires `features.manage=true`), no hard-cap metric currently above limit.

#### `POST /v1/license/usage`

Consumer pushes every 60 s + on limit-sensitive events:
```json
{
  "license_key": "ACME-BUNDLE-2026-A",
  "instance_id": "uuid-v4",
  "metrics": [
    { "metric": "seats",  "window": "total",   "value": 13 },
    { "metric": "scans",  "window": "monthly", "value": 148 },
    { "metric": "scans",  "window": "total",   "value": 14204 },
    { "metric": "hosts",  "window": "total",   "value": 245 }
  ]
}
```

Server responds:
```json
{
  "ok": true,
  "remaining": {
    "seats":            { "total":   37 },
    "scans":            { "monthly": 9852, "total": 985796 },
    "hosts":            { "total":   755 },
    "reports_generated":{ "total":   5000 },
    "report_downloads": { "total":   50000 }
  },
  "over_cap": [],                     // array of {metric, window} currently over hard cap
  "in_buffer": []                     // array of {metric, window} currently in soft buffer
}
```

If `over_cap` non-empty for a hard-cap metric, the consumer **must** reject new allocations for that metric until usage drops below cap. The response is advisory; the consumer is the enforcement point.

#### `GET /v1/license/validate`

Unchanged purpose — a lightweight heartbeat to keep the 7-day offline cache fresh. Returns same shape as activate minus `signed_token`.

### 3.4 Enforcement semantics

| Metric | Enforcement | Behaviour at cap | Behaviour at cap + buffer |
|--------|-------------|------------------|----------------------------|
| `seats` | Hard | Reject new activation | — |
| `tenants` | Hard | Reject tenant creation | — |
| `hosts` | Hard | Reject host onboarding | — |
| `scans` | Soft | Running scans complete; warn | New scan jobs rejected |
| `reports_generated` | Soft | Warn | New reports rejected |
| `report_downloads` | Soft | Warn | Download returns `429 Too Many` |
| `retention_days` | Hard | N/A — this is a duration, not a count. Prune job uses the cap as its age cutoff. | — |

Consumers read `remaining[metric][window]` from the usage response and enforce locally. License Server returns definitive over-cap flags but doesn't block — it's an advisory, the consumer does the blocking so enforcement is immediate (no round-trip on the hot path).

### 3.5 Soft-buffer semantics

`soft_buffer_pct = 10` means:
- Soft-enforced metric with `cap = 10000` and current value `10050` → **in buffer**, allowed to continue but surface a warning to operators.
- Same metric with current value `11001` → **over buffer**, hard block on new work.
- `floor(cap * (1 + pct/100))` is the ceiling.

For `tenants = 3`, buffer gives `ceil(3 * 1.1) = 4`, functionally a hard cap (good for on-prem which should not accumulate stray tenants silently).

### 3.6 Backward compatibility with v1 tier-only tokens

Legacy tokens (issued pre-v2) carry `tier` only. Report Server and Manage Server both need to interpret them consistently. Compatibility mapping performed by `internal/license/guard.go` at decode time:

| Legacy tier | Synthesised features | Synthesised limits |
|-------------|----------------------|--------------------|
| `free` | `{report: true}` | `[{metric: seats, window: total, cap: 5}, {metric: export_formats, …}, …]` |
| `pro` | `{report: true, diff_trend: true, comprehensive_profile: true}` | `[{metric: seats, window: total, cap: 50}]` |
| `enterprise` | `{report: true, manage: true, diff_trend: true, comprehensive_profile: true, custom_policy: true}` | `[{metric: seats, window: total, cap: 500}, {metric: tenants, window: total, cap: 10}]` |

Once a customer re-activates, the License Server issues a v2 token with explicit `features`/`limits`.

### 3.7 Admin UI updates

The Vue License Admin Portal (shipped in PR #76) needs:

- **Create-licence form** — feature toggles (6 checkboxes) + limits editor (`TDataTable` with add-row + inline edit for metric/window/cap) + `soft_buffer_pct` slider (0–25).
- **Licence-detail page** — live usage gauges reading from `/v1/license/usage-summary/:id` (reads from `license_usage`). Colour bands: green ≤ cap, amber ∈ (cap, cap + buffer], red > cap + buffer.
- **Org-detail page** — roll-up of tenants/hosts/scans across that org's licences.

No new components required beyond the existing `@triton/ui` library; this is view work.

---

## 4. Manage Portal standalone

### 4.1 Binary + package layout

```
cmd/manageserver/
  main.go                     entrypoint — reads env, constructs server
pkg/manageserver/
  server.go                   Chi router, middleware stack, mount existing handlers
  auth.go                     JWT issuance/validation (copy of pattern from pkg/server/auth.go)
  setup.go                    first-admin setup flow
  license.go                  License Server client integration (wrapper over internal/license/client.go)
  scan_orchestrator.go        job queue + worker pool for port/SSH scans
  report_push.go              mTLS push of scan results to Report Server
pkg/managestore/
  postgres.go                 separate users/sessions/setup tables + Manage-side zones/hosts
  migrations/                 separate migration sequence from pkg/licensestore + pkg/store
```

Re-used from existing `pkg/server/*`:
- `pkg/server/scanjobs/*` — scan-job CRUD + status (mounted under Manage router)
- `pkg/server/engine/*` — engine registration (mounted; conceptually engines-within-Manage)
- `pkg/server/agentpush/*` — remote agent deployment
- `pkg/server/credentials/*` — SSH credential storage
- `pkg/server/discovery/*` — network discovery jobs
- `pkg/scanner/{network, protocol, ssh_cert, ...}` — the actual scan engines

### 4.2 Configuration (env vars)

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRITON_MANAGE_PORT` | `8082` | HTTP port |
| `TRITON_MANAGE_DB_URL` | `postgres://triton:triton@postgres:5432/manage` | Postgres DSN |
| `TRITON_MANAGE_JWT_SIGNING_KEY` | (required) | JWT HS256 key |
| `TRITON_MANAGE_LICENSE_SERVER` | `https://license.triton.example` | License Server URL |
| `TRITON_MANAGE_LICENSE_KEY` | (required after setup) | Licence key for this instance |
| `TRITON_MANAGE_REPORT_SERVER` | (required after setup) | Report Server URL for scan-result push |
| `TRITON_MANAGE_REPORT_MTLS_CERT` | (required) | Client cert from Report enrolment bundle |
| `TRITON_MANAGE_REPORT_MTLS_KEY` | (required) | Client key |
| `TRITON_MANAGE_REPORT_CA_CERT` | (required) | CA cert to verify Report Server |
| `TRITON_MANAGE_TLS_CERT` / `_KEY` | optional | HTTPS termination on Manage listener (else plain HTTP for reverse proxy) |

### 4.3 First-run setup wizard

When the Manage instance has no admin user and no licence activated (`manage_setup_state` table empty), the server responds to any `/ui/*` navigation with a `/ui/#/setup` redirect. Setup wizard flow (delivered by Vue UI in PR C):

1. **Admin account** — email + password + display name (creates first user with role `admin`).
2. **License Server URL** — validated by GET `/health` before accepting.
3. **Licence key activation** — POST `/v1/license/activate` with `product=manage`; stores the returned signed token in `manage_setup_state`.
4. **Report Server URL + enrolment** — admin pastes URL, Manage GETs `/api/v1/enrol/manage` with the licence-verified tenant ID; Report responds with `bundle.tar.gz` (client cert + key + CA). Cert is written to `TRITON_MANAGE_REPORT_MTLS_*` env-var equivalents stored in the DB (actually in a credential table, encrypted at rest).
5. **Done** — Manage Server flags setup complete, routes normally from here.

### 4.4 Users + roles

Separate `manage_users` / `manage_sessions` tables (not shared with Report Server users).

Roles:
- `admin` — full access; can manage users, zones, profiles, credentials; can delete hosts.
- `network_engineer` — read + bulk action (run scans, deploy agents, edit zones/hosts). Cannot manage users or rotate credentials.

No `viewer` / read-only role in this cut (user confirmed).

### 4.5 Scan orchestrator

Ships as a goroutine pool inside the Manage Server process (not a separate worker binary).

```
POST /api/v1/scan-jobs
  body: { zones: [...], profile: "quick", credentials: "...", target_filter: "..." }
  →
  enqueue jobs, one per host matching filter
  respond 202 Accepted with job list
```

Worker pool size = `max(10, licence.limit(scan_jobs_concurrent).cap ?? 10)`. Per the user's last call: **concurrent jobs are tenant-config, not licence-gated.** Admin UI has a "parallelism" setting (range 1–50, default 10).

Job states: `queued`, `running`, `completed`, `failed`. Completion writes to `scan_results_queue` then `report_push.go` pushes to Report Server.

### 4.6 Report Server ⇄ Manage Server mTLS channel

Report Server exposes `/api/v1/enrol/manage` (admin-gated via Report's existing JWT + role check for `admin`). Request:

```json
{ "manage_instance_id": "uuid", "license_key": "...", "public_key": "pem-encoded-csr" }
```

Report Server validates the licence against License Server (shared-licence check — see §5.2 below, the same licence key enables both), then issues:

```json
{
  "bundle.tar.gz": "...",  // contains: client.crt, client.key, ca.crt, config.yaml (report_url, tenant_id)
}
```

Manage Server uses this on every subsequent scan-push. Report Server's ingestion endpoint `POST /api/v1/scans` validates the mTLS client cert against the tenant it was issued for.

This **reuses** the existing engine enrolment code in `pkg/server/` (currently scoped to native engines). Enrolment becomes polymorphic — `engine` or `manage` — identifiable in the cert's CN field.

### 4.7 Scan-result push to Report

When a scan completes on Manage:

1. Worker writes results to `scan_results_queue` (local PG table, durable).
2. A separate goroutine drains the queue: batches up to 100 results, POSTs `/api/v1/scans` on Report Server over mTLS.
3. On success, row deleted from queue. On failure, exponential backoff with cap at 5 min retry interval.
4. If the queue grows above 10 000 rows (backpressure signal), Manage pauses new scan-job enqueueing and surfaces a warning in the UI.

### 4.8 Container + compose

New `Containerfile.manageserver` (three-stage: Node builds Vue, Go builds binary, scratch runtime). Compose profile `manage-server` on port 8082, shares the Postgres service but on a different database (`manage` vs `triton` vs `license`).

---

## 5. Report Portal integration

### 5.1 Licence required

Report Server today runs with a best-effort licence check that degrades gracefully to free-tier. This spec upgrades to **licence required**:

- On startup: if `TRITON_REPORT_LICENSE_KEY` is unset, Report refuses to serve non-setup endpoints (returns 503 with a "configure licence" payload).
- Setup endpoint `POST /api/v1/setup/license` — admin pastes key, server activates online against License Server, persists signed token.
- Every 60 s: Report pushes `{seats, tenants, scans (monthly+total), reports_generated, report_downloads}` to License Server.
- On 401/403 from License Server: Report falls back to cached token (7-day grace). After 7 days with no successful validation: Report drops to read-only mode (existing data queryable, no new scan ingestion).

### 5.2 Single licence for Report + Manage (bundle case)

A customer buying both Report and Manage receives **one licence** with `features.report=true, features.manage=true`. The same key activates from both Report Server and Manage Server, each with its own `instance_id`. License Server tracks usage per instance-id but sums for per-licence caps.

E.g., if `scans.monthly.cap = 10000`, that's 10 000 across **Report + Manage + agents** combined, not 10 000 per instance.

### 5.3 Feature-flag migration (profile, diff, trend, exports, custom policy)

Currently these are hard-coded behind `tier == "pro"` / `tier == "enterprise"` in `internal/license/guard.go`. Migration:

1. PR A extends `guard.go` to read `features.*` first, then fall back to the tier-compat mapping (§3.6) if `features` is empty.
2. Existing callers (`EnforceProfile`, `EnforceFormat`, `LicenceGate` middleware) consult feature flags via new helpers: `guard.HasFeature("comprehensive_profile")` etc.
3. No call-site semantics change — existing enterprise customers continue to have every feature via the compat mapping.

### 5.4 Retention pruner

Report Server gains a daily cron (simple `time.Ticker` goroutine):

```go
retentionDays := licence.Limit("retention_days", "total").CapOr(365)
DELETE FROM scans WHERE submitted_at < NOW() - INTERVAL '1 day' * $retentionDays;
DELETE FROM findings WHERE scan_id NOT IN (SELECT id FROM scans);
DELETE FROM reports WHERE generated_at < NOW() - INTERVAL '1 day' * $retentionDays;
```

7-day-before-purge warning toast surfaced in UI (analytics backfill pattern already handles this kind of status flag).

Manage Server gets an identical pruner for its `scan_results_queue` (though in practice results drain quickly to Report).

---

## 6. PR split

### PR A — License Server v2 + Report Portal integration

**Scope**:
- License Server DB migration (new columns + `license_usage` table).
- New activation / usage / validation endpoints; legacy `/v1/license/*` kept for back-compat.
- Admin Vue UI updates (limits editor, feature toggles, usage gauges).
- Report Portal: licence-required startup, setup endpoint, usage pusher, feature-flag reads, retention pruner.
- Integration tests for both.
- Backward-compat: legacy tier-only tokens resolve via compat mapping; no existing customer breaks.

**Out of scope**: Manage Server binary, Vue UI migration.

**Delivers**: customers can run Report Portal with v2 licence flow; License Server admin can issue bundle licences (but nothing consumes the `manage` feature yet).

### PR B — Manage Portal standalone backend + scanner

**Scope**:
- `cmd/manageserver/` binary + `pkg/manageserver/` package.
- Separate DB schema + migrations (`manage_users`, `manage_sessions`, `manage_setup`, plus Manage-side zones/hosts/scan_jobs tables — or reuse shared schema via federated handler mount).
- Re-mount scan handlers from `pkg/server/*` under Manage's Chi router with JWT + role middleware.
- License client (activate on startup, push usage, cache 7-day offline).
- Scan orchestrator goroutine pool.
- mTLS Report-push channel + Report Server enrolment endpoint (`/api/v1/enrol/manage`).
- `Containerfile.manageserver` + compose profile + CI job.
- Existing vanilla-JS UI at `pkg/server/ui/dist/manage/` remains served by Report Server (Report Server routes `/ui/manage/*` to the old SPA) as a transitional fallback.

**Delivers**: Manage Server is live as a standalone deployable, authenticates its own users, enforces licence caps, performs scans, reports to Report. No Vue UI yet — operators use the vanilla JS fallback served by the Report Server.

### PR C — Manage Portal Vue UI + cutover

**Scope**:
- `@triton/ui` additions: `TFileDrop`, `TEmptyState`, `TZoneBadges`.
- `@triton/auth` additions: JWT adapter + first-run setup-wizard primitives.
- `@triton/api-client` additions: Manage Server endpoints + license-activation helpers.
- `apps/manage-portal` Vue app → `pkg/manageserver/ui/dist/`.
- 8 views migrated: Dashboard, Zones (was Groups in API), Hosts, Discovery, Credentials, Profiles, SSH keys, Agents, Jobs, Audit.
- Setup wizard (admin account → License Server URL → licence activation → Report Server URL + enrolment).
- Playwright E2E for setup wizard + core flows.
- Delete `pkg/server/ui/dist/manage/` vanilla JS. Report Server's `/ui/manage/*` returns `301` redirect to Manage Server URL (configured at Report Server deploy time via `TRITON_REPORT_MANAGE_URL` env var).

**Delivers**: full Manage Portal end-to-end in Vue; legacy vanilla UI gone.

---

## 7. Testing

### PR A
- Unit tests for `limits[]` parsing, window arithmetic, soft-buffer math, compat mapping.
- Integration tests for `/v1/license/activate`, `/v1/license/usage`, `/v1/license/validate` round-trip.
- Integration test for Report Portal usage-push → License Server consumption.
- Report Portal retention pruner: seed scans at various ages, run pruner, assert correct deletion.
- License Admin E2E (Playwright): create a bundle licence, view live usage, edit limits.

### PR B
- Integration tests for Manage binary startup (licence required, setup flow).
- mTLS enrolment happy path + CA-mismatch path.
- Scan orchestrator: queue fills, completes, results push to fake Report.
- Licence enforcement: reject host-add over cap, reject new scan when over scan cap + buffer.

### PR C
- Vitest units for new `@triton/ui` components.
- Playwright: setup wizard end-to-end, CRUD flows on zones/hosts.

---

## 8. Open decisions / deferred

- **Manage Server users in a shared DB with Report Server?** — Rejected. Separate tables for audit isolation. Decision ratified 2026-04-19.
- **`scan_jobs_concurrent` as licence-gated cap?** — Rejected. Tenant configuration only (admin-editable 1–50, default 10). Ratified 2026-04-19.
- **Cloud multi-customer Report Portal?** — Not in scope. Each customer stands up their own Report. Ratified 2026-04-19.
- **Per-metric enforcement strictness overrides per licence?** — Not in v2. Hard/soft assignments are universal (§3.4). If a customer needs exception, it's a licence-issuer manual configuration outside this spec.
- **Usage pusher failure resilience across restarts** — deferred to PR B implementation detail. Intent: persist last-reported counters in a local `license_state` table so a Manage restart doesn't reset pending usage pushes.

---

## 9. Acceptance criteria

**Per PR A**:
- [ ] License Server issues bundle licences with feature flags + limits; legacy tokens continue to validate.
- [ ] Admin Vue UI lets operators create/edit a licence with both features and limits.
- [ ] Report Server refuses to start (or serves setup-only) without `TRITON_REPORT_LICENSE_KEY`.
- [ ] Report Server pushes usage every 60 s; License Server persists; Admin UI shows live gauges.
- [ ] Retention pruner deletes scans older than `retention_days.cap`.
- [ ] `features.comprehensive_profile` / `features.diff_trend` / `features.custom_policy` drive the existing guard checks; legacy `tier` compat mapping preserves current behaviour.

**Per PR B**:
- [ ] `make container-build-manageserver` produces an image.
- [ ] Empty DB → Manage serves `/setup`; completing the wizard unlocks `/` routes.
- [ ] Manage refuses new hosts when `hosts` cap reached; refuses new scan job when `scans.monthly` over cap + buffer.
- [ ] mTLS push to Report Server succeeds; certificate rotation path works.
- [ ] Existing vanilla UI at `/ui/manage/` on Report Server remains accessible.

**Per PR C**:
- [ ] Vue app loads at Manage Server's `/ui/`; setup wizard completes end-to-end.
- [ ] All 8 views render with real data from Manage's API.
- [ ] `pkg/server/ui/dist/manage/` deleted; Report Server redirects `/ui/manage/*` to `TRITON_REPORT_MANAGE_URL`.
- [ ] Playwright E2E covers setup + zone/host CRUD + scan enqueue + audit.
