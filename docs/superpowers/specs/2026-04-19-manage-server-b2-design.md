# Manage Server B2 — Scanner Orchestrator + mTLS Push Design

> **Status:** Approved 2026-04-19. Parent spec: [`2026-04-19-license-v2-and-manage-portal-design.md`](./2026-04-19-license-v2-and-manage-portal-design.md) §4.5–4.8 + §6 PR B. This doc expands PR B into concrete subsystem designs and a two-way PR split (B2.1 + B2.2).
>
> **Preceding work (already merged):** PR #81 (B1 backend shell) — standalone Manage binary, auth, setup, licence activation, usage pusher, 501 stub for `/api/v1/admin/enrol/manage` on Report Server.

## 1. Problem

B1 shipped a runnable Manage Server binary that authenticates users, completes a setup wizard, and activates against the License Server — but it has no scans, no hosts, no agents. The 501 stub for Report-side enrolment is a placeholder.

B2 makes Manage actually do its job: own the on-prem scan surface (zones, hosts, credentials, discovery, scan jobs, agents), run scans in-process, and push results upstream to Report over a real mTLS channel. Agents registered to Manage phone home over a second mTLS channel signed by Manage's own CA, independent of Report's CA, so air-gapped deployments still enrol agents while the Report link is down.

### Goals

- Replace the 501 stub on Report Server with real `bundle.tar.gz` issuance for Manage instances.
- Refactor 4 existing Report Server scan-related packages to accept an external Postgres pool so Manage can mount the handlers against its own DB without forking CRUD code.
- Mount those handlers + 2 new Manage-native packages (`hosts`, `zones`) on Manage's Chi router.
- Ship an in-process scanner orchestrator that runs `pkg/scanner` in a worker-pool goroutine group.
- Ship a durable `scan_results_queue` + drain goroutine that POSTs to Report over mTLS with exponential backoff and backpressure.
- Ship Manage's own CA for agent certificate issuance, plus the admin endpoint to enrol agents and the gateway endpoint for agents to phone home.
- Enforce licence caps at the right request points (hard on seats/hosts/agents, soft-buffered on `scans.monthly`).

### Non-goals

- No Vue UI. That ships in PR C.
- No changes to agents' existing direct-to-Report path; agents that target the Report Server directly continue to work unchanged.
- No HSM or encrypted-at-rest CA key storage; deferred to a hardening pass.
- No batched `/api/v1/scans` ingest endpoint on Report; drain pushes sequentially.

## 2. Architecture

```
┌───────────────── CUSTOMER HQ / CLOUD ─────────────────┐
│                                                         │
│   Report Server (multi-tenant)                          │
│   ├── existing: scans/findings/analytics/diff/trend    │
│   ├── NEW (B2.2): /api/v1/admin/enrol/manage real      │
│   │   → issues bundle.tar.gz {client.crt, client.key,  │
│   │                           ca.crt, config.yaml}     │
│   │     signed by Report's engine CA                   │
│   └── existing: /api/v1/scans mTLS ingest              │
│       (NEW: accepts CN prefixed "manage:" in addition  │
│        to existing "engine:")                          │
└────────────────────────┬────────────────────────────────┘
                         ▲
                mTLS push│(Report CA trust chain)
                         │
┌────────────────────────┴──────── ON-PREM NETWORK ──────┐
│                                                         │
│   Manage Server (single-tenant)                        │
│   ├── existing (B1): auth, setup, licence, users       │
│   ├── NEW (B2.2): zones, hosts, credentials,           │
│   │               discovery, scanjobs, agentpush       │
│   ├── NEW (B2.2): scanner orchestrator (goroutine pool)│
│   │               → runs pkg/scanner in-process        │
│   ├── NEW (B2.2): scan_results_queue + drain goroutine │
│   │               → pushes to Report over mTLS         │
│   ├── NEW (B2.2): Manage-side CA for its agents        │
│   │               → mints agent certs (separate chain  │
│   │                 from Report CA)                    │
│   └── own Postgres DB: triton_manage                   │
│                  ▲                                      │
│                  │agent phone-home (Manage CA trust)   │
│         ┌────────┴────────┐                            │
│         │                  │                            │
│      Agent-A          Agent-B     + SSH/HTTPS probes   │
│      (host-resident)  (host)        (direct from       │
│                                      Manage to         │
│                                      network hosts)    │
└─────────────────────────────────────────────────────────┘
```

**Two independent trust chains, intentionally:**
- **Report CA** (existing engine CA) — signs `manage:<uuid>` cert for the Manage ⇄ Report push channel.
- **Manage CA** (new in B2.2) — signs `agent:<uuid>` certs for agents that phone home to Manage. Independent of Report's CA; if Report is unreachable, Manage can still enrol new agents.

**Scan-origin provenance:** scans arriving at Report via the Manage push channel carry transport-level attribution `manage:<uuid>` via the mTLS client cert. The original scanner source (in-process scan vs agent-relayed scan) is preserved inside the JSON payload as `submitted_by: {type, id}` metadata. Report's existing scan model requires no schema change — the metadata rides in the existing `result_json` JSONB blob.

## 3. PR Split

### PR B2.1 — pool-injection refactor (~3k LOC)

**Scope:** 4 existing packages (`scanjobs`, `credentials`, `discovery`, `agentpush`) gain two exported helpers alongside their current constructor:

```go
// Existing constructor — kept for Report Server, no behaviour change.
func NewPostgresStore(ctx context.Context, dbURL string) (*PostgresStore, error) { ... }

// New: pool-injectable constructor.
func NewPostgresStoreFromPool(pool *pgxpool.Pool) *PostgresStore { ... }

// New: exportable migration runner (runs package's migrations against the pool's DB).
func Migrate(ctx context.Context, pool *pgxpool.Pool) error { ... }
```

`NewPostgresStore` becomes a thin wrapper over `pgxpool.New` + `Migrate` + `NewPostgresStoreFromPool`.

**Per-test schema isolation** is mirrored onto each package (following the `managestore.NewPostgresStoreInSchema` pattern from B1) for parallel-safe integration tests.

**No new endpoints, migrations, columns, or handler logic.** Report Server behaviour is literally unchanged.

**Gate:** all existing Report Server unit + integration tests pass unchanged; `golangci-lint` clean. One new unit test per package: "store constructed via `NewPostgresStoreFromPool` + `Migrate` behaves identically to `NewPostgresStore(dbURL)`."

**Branch:** `feat/manage-b2.1-pool-injection`. Merges to main before B2.2 branches.

### PR B2.2 — Manage-side scanner + mTLS (~7–8k LOC)

**Scope:** everything described in sections 4–10 below. Branched from main after B2.1 merges. Delivered via subagent-driven development with spec + code review loops per batch.

**Batch plan** (final order decided during implementation):
- **A** — managestore migrations: `zones`, `hosts`, `scan_jobs`, `scan_results_queue`, `scan_results_dead_letter`, `manage_ca`, `agent_cert_revocations`, `manage_push_creds`, `license_state`.
- **B** — `pkg/manageserver/zones/` + `pkg/manageserver/hosts/` packages (native CRUD).
- **C** — handler re-mount: router composition, tenancy shim middleware, admin route mounting for scanjobs + credentials + discovery + agentpush.
- **D** — scanner orchestrator: worker pool, pkg/scanner integration, state machine, stale reaper, cancellation.
- **E** — drain goroutine: queue table handling, backoff, dead-letter, backpressure.
- **F** — Manage CA + agent enrol: `pkg/manageserver/ca/`, admin `/enrol/agent`, gateway :8443 listener, mtlsCNAuth middleware, rotation + revocation endpoints.
- **G** — Report-side real enrolment: new `pkg/server/manage_enrol/` package on Report, extend engine mTLS middleware to accept `manage:` CN prefix, setup-wizard extension on Manage to auto-call the Report enrol endpoint.
- **H** — licence enforcement call sites + `license_state` persistence.
- **I** — Containerfile/compose updates (add :8443 port, env var for gateway listen), end-to-end integration test, PR open.

## 4. Router Composition

**Two listeners, one binary**, because TLS client-cert requirement is TCP-level:

```
Port :8082  — admin listener (plain HTTP or optional TLS)
            JWT + role middleware
            ├── existing B1 routes
            │   /api/v1/health
            │   /api/v1/setup/{status,admin,license}
            │   /api/v1/auth/{login,logout,refresh}
            │   /api/v1/me
            ├── NEW Manage-native admin routes
            │   /api/v1/admin/zones/*
            │   /api/v1/admin/hosts/*
            │   /api/v1/admin/enrol/agent       → mints agent bundle
            │   /api/v1/admin/push-status       → drain/queue diagnostics
            └── mounted from pkg/server/* packages (via B2.1 refactor)
                /api/v1/admin/scan-jobs/*        ← scanjobs admin routes
                /api/v1/admin/credentials/*      ← credentials admin routes
                /api/v1/admin/discovery/*        ← discovery admin routes
                /api/v1/admin/agents/*           ← agentpush admin routes

Port :8443  — agent-gateway listener (TLS + RequireAndVerifyClientCert)
            Trust anchor: Manage's own CA (NOT Report's CA)
            Chi mtlsCNAuth middleware → asserts CN starts with "agent:"
            └── mounted from pkg/server/agentpush gateway routes + Manage CA rotation
                /api/v1/gateway/agents/phone-home
                /api/v1/gateway/agents/scans     → writes to scan_results_queue
                /api/v1/gateway/agents/findings  → writes to scan_results_queue
                /api/v1/gateway/agents/rotate-cert → Manage CA signs new cert
```

**Tenancy shim middleware** — sits before any `/api/v1/admin/*` package mount:

```go
func (s *Server) injectInstanceOrg(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := orgctx.WithOrgID(r.Context(), s.instanceID)  // from manage_setup
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

The 4 mounted packages already read `orgID` from context (Report's tenancy model). On Manage we synthesise a constant `orgID = manage_setup.instance_id`, so the same handler code runs unchanged. No fork of handler logic.

**Middleware chain summary:**

| Layer | Applied to |
|---|---|
| `SetupOnly` | `/api/v1/setup/admin`, `/api/v1/setup/license` |
| `requireOperational` | everything except `/health` and `/setup/*` |
| `jwtAuth` | all `/api/v1/admin/*`, `/api/v1/me` |
| `requireRole("admin")` | licence, enrol, destructive admin routes |
| `injectInstanceOrg` | `/api/v1/admin/{scan-jobs,credentials,discovery,agents,zones,hosts}/*` |
| `mtlsCNAuth(prefix="agent:")` | everything on `:8443` |

## 5. Scanner Orchestrator

**Worker pool model:** N goroutines started at Manage boot. N = admin-configurable `parallelism` setting (range 1–50, default 10). Tenant config, not licence-gated (ratified in parent spec §8). Each worker runs the same loop: pull-a-job → run-it → write-results → heartbeat.

**Pull-a-job primitive** (durable, concurrency-safe):

```sql
UPDATE scan_jobs
   SET status = 'running',
       started_at = NOW(),
       running_heartbeat_at = NOW(),
       worker_id = $1
 WHERE id = (
    SELECT id FROM scan_jobs
     WHERE status = 'queued'
     ORDER BY enqueued_at
     LIMIT 1
     FOR UPDATE SKIP LOCKED
 )
 RETURNING *;
```

`FOR UPDATE SKIP LOCKED` lets N workers pull concurrently without blocking each other. Poll interval 2s when the queue is empty; zero delay when a worker just finished a job.

**Job state machine:**

```
queued ──worker pulls──> running ──scan finishes──> completed
                            │                             │
                            │ cancel_requested set        │
                            ├──────> cancelled            │
                            │                             │
                            │ scanner error / crash       │
                            └──────> failed               │
                                                          ▼
                             results → scan_results_queue → drain → Report
```

**`scan_jobs` table:**

```sql
CREATE TABLE scan_jobs (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           UUID NOT NULL,           -- always = instance_id
  zone_id             UUID NOT NULL REFERENCES zones(id),
  host_id             UUID NOT NULL REFERENCES hosts(id),
  profile             TEXT NOT NULL,            -- quick | standard | comprehensive
  credentials_ref     UUID REFERENCES credentials(id),
  status              TEXT NOT NULL CHECK (status IN
                      ('queued','running','completed','failed','cancelled')),
  cancel_requested    BOOLEAN NOT NULL DEFAULT FALSE,
  worker_id           TEXT,                     -- hostname:pid:goroutine-id for diagnostics
  enqueued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at          TIMESTAMPTZ,
  finished_at         TIMESTAMPTZ,
  running_heartbeat_at TIMESTAMPTZ,
  progress_text       TEXT,                     -- "scanning host 3 of 10"
  error_message       TEXT
);
CREATE INDEX ON scan_jobs (status, enqueued_at);
CREATE INDEX ON scan_jobs (running_heartbeat_at) WHERE status='running';
```

**Cancellation:** durable flag, not an in-memory cancel-func map. `PATCH /scan-jobs/{id}/cancel` sets `cancel_requested=true`. Worker checks the flag between scanner modules (cooperative, every few seconds inside the scan) and bails with status=cancelled. Survives Manage restart.

**Stale-job reaper:** one background goroutine, interval 60s:

```sql
UPDATE scan_jobs
   SET status='queued', worker_id=NULL, started_at=NULL, running_heartbeat_at=NULL
 WHERE status='running' AND running_heartbeat_at < NOW() - INTERVAL '5 minutes';
```

Covers Manage crashes mid-scan. Workers emit heartbeats every 60s during scan.

**`pkg/scanner` integration:** worker builds a `scanner.Config` from the job row (profile, target from `hosts`, credentials from `credentials_ref`), then `engine := scanner.NewEngine(cfg); findings, err := engine.Scan(jobCtx, target)`. The engine's internal goroutine+semaphore concurrency is unchanged — we layer *job*-level parallelism over scanner-*module*-level parallelism. `parallelism=10` × comprehensive profile (16 modules) max = 160 module goroutines; network-I/O-bound, OK for typical on-prem networks.

**Licence enforcement at enqueue** — see §8.

**Target expansion:** `POST /scan-jobs` body `{zones:[], target_filter, profile, credentials_ref}` → handler queries `hosts` joined to `zone_memberships` + filter → inserts N rows into `scan_jobs` in a single transaction. Idempotency-key header optional (request-id) to survive retries.

## 6. Scan-Result Queue + Drain

**`scan_results_queue` table** (one row per completed scan):

```sql
CREATE TABLE scan_results_queue (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_job_id      UUID NOT NULL REFERENCES scan_jobs(id),
  source_type      TEXT NOT NULL CHECK (source_type IN ('manage','agent')),
  source_id        UUID NOT NULL,        -- instance_id or agent_uuid
  payload_json     JSONB NOT NULL,       -- full scan envelope, ready to POST
  enqueued_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempt_count    INT NOT NULL DEFAULT 0,
  last_error       TEXT
);
CREATE INDEX ON scan_results_queue (next_attempt_at) WHERE attempt_count < 10;
```

**One scan = one row.** Each row's `payload_json` is a complete `/api/v1/scans` request body including `submitted_by: {type, id}` provenance. Report's existing ingest treats this as a scan with extra JSONB fields — no Report-side schema change.

**Drain goroutine loop:**

```
every 5s (or immediately after a worker writes):
  SELECT * FROM scan_results_queue
   WHERE next_attempt_at <= NOW() AND attempt_count < 10
   ORDER BY enqueued_at
   LIMIT 100;
  for each row:
    POST Report /api/v1/scans with mTLS client cert (Report CA trust chain)
    on 2xx → DELETE row
    on 4xx (non-retryable) → move row to scan_results_dead_letter, log, DELETE
    on 5xx / network error →
       attempt_count++
       next_attempt_at = NOW() + backoff(attempt_count)  -- 10s, 20s, 40s, ..., 300s cap
       last_error = err.String()
```

**Sequential POSTs, not batched.** Report's existing `/api/v1/scans` accepts one scan per request. Batching would require a new Report endpoint — out of scope for B2.2. 100 sequential POSTs with HTTP/2 keep-alive drain in ~10s against a healthy Report.

**Dead letter after 10 attempts** (~30 min of retries: 10s + 20s + 40s + 80s + 160s + 300s × 5 = ~30 min). Row moves to `scan_results_dead_letter` with columns identical to `scan_results_queue` plus `dead_lettered_at`, `dead_letter_reason`. Prevents queue bloat from permanently-rejected scans.

**Backpressure** (parent spec §4.7):

- When `SELECT COUNT(*) FROM scan_results_queue >= 10_000`: `POST /scan-jobs` returns 503 with body `"scan result queue saturated; upstream Report Server unreachable — see /api/v1/admin/push-status"`.
- UI banner (PR C) reads `/api/v1/admin/push-status` which returns `{queue_depth, oldest_row_age_seconds, last_push_error, consecutive_failures}`.
- Scanner workers keep draining their in-flight jobs (queue may transiently exceed 10k — soft line). Workers STOP pulling NEW jobs when threshold is breached, preventing unbounded growth from in-flight work.

**Provenance preserved end-to-end:** Report's existing `result_json` JSONB blob carries `submitted_by`. Queryable via `WHERE result_json->'submitted_by'->>'type' = 'agent'` for audit. No Report schema change.

## 7. Manage CA + Agent Enrolment

**New package `pkg/manageserver/ca/`** — forked from `pkg/server/engine/{ca,bundle,mtls_middleware}.go` with Manage-appropriate schema. Separate package so B2.2 doesn't touch engine's tested code on Report.

**CA key lifecycle:**

- **Generated at setup-wizard completion.** After `/setup/license` succeeds (and after the setup wizard automatically calls Report's `/api/v1/admin/enrol/manage`), `ca.Bootstrap(ctx, pool)` generates a 256-bit ECDSA-P256 keypair, creates a self-signed root cert (10-year expiry, CA=true, Subject CN = `Triton Manage CA — <instance_id>`), writes the single row to `manage_ca`.
- **Stored in Postgres** (plaintext, protected by DB access controls — same threat model as `manage_setup.signed_token` and JWT signing env var today).
- **HSM / encrypted-at-rest deferred** to a hardening pass.

```sql
CREATE TABLE manage_ca (
  id           SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
  ca_cert_pem  TEXT NOT NULL,
  ca_key_pem   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_cert_revocations (
  cert_serial    TEXT PRIMARY KEY,
  agent_id       UUID NOT NULL,
  revoked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoke_reason  TEXT
);
```

### Agent enrolment (admin-initiated)

```
Admin UI / curl
    │  POST /api/v1/admin/enrol/agent
    │  body: {name, zone_id}
    ▼
Manage handleEnrolAgent
    │  1. licence check: guard.HasFeature("manage") + agents count < cap (hard)
    │  2. ca.LoadCA(pool) → CA cert + key
    │  3. generate agent keypair (ECDSA-P256)
    │  4. sign cert: CN="agent:<uuid>", expiry=1y,
    │                KU=DigitalSignature+KeyEncipherment, EKU=ClientAuth
    │  5. INSERT INTO agents (id, name, zone_id, cert_serial, cert_expires_at,
    │                         status='pending')  -- uses agentpush schema
    │  6. ca/bundle.go builds bundle.tar.gz:
    │        client.crt, client.key, ca.crt (Manage's root),
    │        config.yaml {manage_gateway_url, agent_id, phone_home_interval}
    ▼
bundle.tar.gz (application/x-gzip, Content-Disposition: attachment)

Operator transfers bundle to target host (SSH scp, config mgmt, USB if air-gapped)

Agent daemon startup on target host
    │  loads bundle, starts triton-agent with manage's gateway URL
    │  TLS handshake with Manage :8443 using client cert
    ▼
Manage gateway mtlsCNAuth middleware
    │  extracts CN prefix → must be "agent:"
    │  extracts agent UUID, looks up in agents table
    │  checks agent_cert_revocations for serial → if revoked → 401
    │  handler updates agents.status='active', last_seen_at=NOW()
```

### Cert rotation

Agent cert lives 1 year. At each phone-home, agent reads its cert expiry; if `< 30 days remaining`, it POSTs `/api/v1/gateway/agents/rotate-cert` (mTLS — the current still-valid cert authenticates). Manage signs a new cert (same CN, new serial, new expiry), returns it; agent swaps on-disk, reloads. No admin interaction needed as long as the agent stays reachable.

### Revocation

Admin UI: "Revoke agent X" → `DELETE /api/v1/admin/agents/{id}`. Handler:
1. Inserts row into `agent_cert_revocations (cert_serial, agent_id, revoked_at, reason)`.
2. Marks `agents.status='revoked'`.

`mtlsCNAuth` middleware consults `agent_cert_revocations` (cached in-memory, refreshed every 30s) on every gateway request. **Eventually consistent** revocation with 30s maximum staleness — documented tradeoff.

### Report-side: 501 stub becomes real

**New package `pkg/server/manage_enrol/`** on Report — parallel to `pkg/server/engine/` but with its own `manage_instances` table. Reuses Report's existing engine CA (same Ed25519 key) via a small `engine.IssueCert(cn, duration)` helper extracted during B2.2.

`POST /api/v1/admin/enrol/manage` handler body:

```json
{
  "manage_instance_id": "<uuid>",
  "license_key": "...",
  "public_key": "pem-csr"
}
```

Flow:
1. `ServiceKeyAuth` gate (from B1).
2. Validate licence key against License Server — must have `features.manage=true`. Report's guard enforces `HasFeature`.
3. Extract public key from CSR, sign cert: `CN="manage:<license_key_hash>:<manage_instance_id>"`, expiry=1y, EKU=ClientAuth.
4. `INSERT INTO manage_instances` (cert serial, licence ref, tenant attribution).
5. Build bundle.tar.gz: `client.crt`, `ca.crt` (Report root), `config.yaml` with Report's `/api/v1/scans` URL and the tenant attribution Report should apply.
6. Return 200 with bundle.

Manage's `/setup/license` handler (from B1) already stores `signed_token` + `instance_id`. B2.2 extends setup: after licence activation succeeds, the setup handler generates a CSR locally, calls Report's `/api/v1/admin/enrol/manage` automatically, and persists the returned bundle in a new `manage_push_creds` table (single row: `client_cert_pem`, `client_key_pem`, `ca_cert_pem`, `report_url`, `tenant_id`). Drain goroutine loads from this table.

### Gateway mTLS extension on Report

Report's existing `/api/v1/scans` ingest (guarded by `pkg/server/engine/mtls_middleware.go`) accepts any cert signed by Report's engine CA. B2.2 extends the middleware to accept CNs starting with either `engine:` or `manage:`. For `manage:` CNs, scan tenant attribution comes from the cert's embedded licence-key hash (looked up in `manage_instances`). For `engine:` CNs the existing path is unchanged.

## 8. Licence Enforcement

| Metric | Who reports to LS | Who enforces | Strictness |
|---|---|---|---|
| `seats` (manage_users count) | Manage | Manage (at user-create) | Hard |
| `hosts` (hosts-table count) | Manage | Manage (at host-create / discovery-import) | Hard |
| `scans.monthly` | **Report only** (authoritative ingest) | Manage (at scan-job-enqueue) | Soft (cap + buffer) |
| `agents` (agents-table count) | Manage | Manage (at enrol) | Hard when cap present |
| `reports_generated`, `report_downloads`, `tenants`, `retention_days` | Report | Report | — (Manage doesn't touch) |

**Why Manage doesn't report `scans.monthly`:** every Manage scan eventually pushes to Report where it's counted at ingest. Double-reporting would double-count. Report is the single source of truth. Manage's enqueue check reads Report's aggregate via `guard.CurrentUsage("scans","monthly")` — populated from the cached License Server `/validate` response (refreshed every 60s by the existing usage pusher from B1).

**Three enforcement call sites:**

```go
// 1. POST /api/v1/admin/users — seat check
if cap := guard.LimitCap("seats", "total"); cap >= 0 {
    count, _ := userStore.Count(ctx)
    if count + 1 > cap {
        return 403 "licence seat cap exceeded"
    }
}

// 2. POST /api/v1/admin/hosts  (and discovery batch import)
if cap := guard.LimitCap("hosts", "total"); cap >= 0 {
    count, _ := hostsStore.Count(ctx)
    if count + newCount > cap {
        return 403 "licence host cap exceeded"
    }
}

// 3. POST /api/v1/admin/scan-jobs — soft-buffered scans check
if cap := guard.LimitCap("scans", "monthly"); cap >= 0 {
    used    := guard.CurrentUsage("scans", "monthly")
    ceiling := guard.SoftBufferCeiling("scans", "monthly")
    if used + expectedJobs > ceiling {
        return 403 "licence scan cap exceeded"
    }
}
```

**Discovery import is all-or-nothing:** `POST /api/v1/admin/discovery/{id}/import` with N candidate hosts; if `N + existing > cap`, the whole import rejects with shortfall in the error body so the admin can filter.

**Licence-state persistence** (answers parent spec §8 open decision): new tiny table

```sql
CREATE TABLE license_state (
  id                    SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
  last_pushed_at        TIMESTAMPTZ,
  last_pushed_metrics   JSONB,
  last_push_error       TEXT,
  consecutive_failures  INT NOT NULL DEFAULT 0
);
```

Usage pusher writes after each successful push (and on failure, bumps `consecutive_failures`). Primarily for operator diagnostics and the admin UI "last heartbeat" indicator; NOT load-bearing for correctness — all metrics are absolute counts (not deltas), so a restarted Manage re-reports current truth on the next tick.

**Offline grace behaviour** (reused from B1, no new work): `/validate` fails → Manage uses cached response for up to 7 days. During that window enforcement proceeds against cached caps + last-known Report count. After 7 days: UI shows "licence expired"; all write endpoints return 402; read-only mode preserved for existing data.

**In-flight at cap breach:** when `scans.monthly` tips into cap+buffer mid-day, already-`queued` jobs keep running (no retroactive cancellation). Only NEW enqueues are refused. The soft buffer exists exactly for this — absorbing mid-window overshoot without blocking in-flight work.

## 9. New Tables (Manage-side) summary

All created by B2.2 migrations on Manage's `triton_manage` DB:

- `zones` — id, name, description, created_at, updated_at.
- `hosts` — id, hostname, ip, zone_id (FK), os, last_seen_at, created_at, updated_at.
- `zone_memberships` — (host_id, zone_id) PK — or folded into `hosts.zone_id` if 1:1 suffices (decision during implementation).
- `scan_jobs` — §5.
- `scan_results_queue` — §6.
- `scan_results_dead_letter` — same shape as queue + `dead_lettered_at`, `dead_letter_reason`.
- `manage_ca` — §7.
- `agent_cert_revocations` — §7.
- `manage_push_creds` — §7.
- `license_state` — §8.

Mounted packages (`scanjobs`, `credentials`, `discovery`, `agentpush`) create their own tables via `Migrate` exported in B2.1. Manage's DB ends up with the union.

## 10. Testing

### B2.1 tests

**Risk: zero behaviour change; gate is "Report CI green."**

- All existing Report Server unit + integration tests pass unchanged. Any test diff is a red flag.
- One new unit test per refactored package: "store constructed via `NewPostgresStoreFromPool` + `Migrate` behaves identically to `NewPostgresStore(dbURL)`."
- `golangci-lint run ./pkg/server/...` clean.
- PR body explicitly frames the gate: "no new features; reviewers confirm by Report CI green."

### B2.2 unit tests (fast, no DB)

- Scanner orchestrator: state-machine transitions, cancellation flag, stale-heartbeat reaper with mocked clock.
- Drain goroutine: backoff calculation, dead-letter cutoff, backpressure threshold.
- Licence enforcement: cap math, soft-buffer ceiling, over-cap rejection paths.
- CA primitives: key generation, cert signing, CN validation, revocation list lookup.

### B2.2 integration tests (`//go:build integration`, real Postgres)

Per subsystem:

- `TestOrchestrator_EnqueueToCompletion` — stub `pkg/scanner` returns canned findings; enqueue job, assert queued → running → completed, row written to `scan_results_queue`.
- `TestOrchestrator_Cancellation` — set `cancel_requested=true` mid-scan; worker bails with status=cancelled.
- `TestOrchestrator_StaleHeartbeatReaper` — insert job with stale heartbeat; reaper reverts to queued.
- `TestDrain_HappyPath` — seed 250 queue rows; stub Report via `httptest.Server`; run drain; assert all rows deleted and stub received 250 POSTs.
- `TestDrain_BackoffOnFailure` — stub returns 500; `attempt_count` grows, `next_attempt_at` shifts exponentially.
- `TestDrain_DeadLetterAfter10` — stub returns 400; row moves to dead-letter after 10 attempts.
- `TestBackpressure_QueueOver10k_Rejects` — seed 10k rows; POST `/scan-jobs` returns 503.
- `TestLicence_ScansCapBlocksEnqueue` — mock guard `used=9900, cap=10000, buffer=10%`; POST 500 jobs → 403, POST 100 jobs → 200.
- `TestLicence_HostsCapBlocksAdd` — cap=50, seed 50 hosts, POST new host → 403.

### mTLS integration tests

- `TestManageCA_Bootstrap` — on setup completion, `manage_ca` row has a valid self-signed root.
- `TestEnrolAgent_IssuesValidBundle` — POST `/enrol/agent`; unzip bundle; parse client.crt; verify chain against bundle's ca.crt; assert CN = `agent:<uuid>`; expiry ≈ 1y.
- `TestGateway_AcceptsValidAgentCert` — spin Manage :8443 listener; dial with bundle's client cert; POST phone-home → 200.
- `TestGateway_RejectsRevokedCert` — enrol agent; revoke via API; dial gateway with same cert → 401 within 30s.
- `TestGateway_RejectsUntrustedCA` — dial with cert signed by a different CA → TLS handshake fails.
- `TestGateway_RejectsWrongCNPrefix` — dial with `manage:`-prefixed cert at agent gateway → 401.
- `TestReportEnrolManage_RealBundle` — Report-side: POST with `features.manage=true` licence + CSR → valid bundle returned. With `features.manage=false` → 403.

### End-to-end integration test

`test/integration/manage_e2e_scan_flow_test.go` — extends B1's setup-flow test:

1. Fresh Manage DB → setup admin → activate licence against stub LS.
2. Setup wizard calls stub Report's `/api/v1/admin/enrol/manage` → Manage gets push bundle.
3. Admin enrols agent via Manage → gets agent bundle.
4. Simulated agent dials Manage :8443 with bundle → phone-home succeeds.
5. Admin creates zone + host; enqueues scan job.
6. Orchestrator worker processes job with stub scanner returning canned findings.
7. Drain goroutine POSTs to stub Report → stub asserts payload has `submitted_by: {type:"manage"}` and mTLS client cert CN = `manage:...`.
8. `scan_results_queue` drains to empty.
9. `/api/v1/admin/scan-jobs/{id}` shows status=completed.

### CI + Container

- **B2.1**: no CI changes; existing `integration-test` job's `./...` already covers refactored packages.
- **B2.2**: no new CI job. `integration-test` picks up new Manage packages. The existing `build` job validates `Containerfile.manageserver` still builds with B2.2's new imports.
- `compose.yaml`: `manageserver` service gains `"8443:8443"` port mapping and env var `TRITON_MANAGE_GATEWAY_LISTEN` (default `:8443`). Documented in `.env.example`.

## 11. Acceptance Criteria

### PR B2.1

- [ ] All existing Report Server tests pass unchanged.
- [ ] Each of `scanjobs`, `credentials`, `discovery`, `agentpush` packages exposes `NewPostgresStoreFromPool` + `Migrate`.
- [ ] Each of those 4 packages has a "pool-constructed ≡ URL-constructed" unit test.
- [ ] `golangci-lint` clean.

### PR B2.2

- [ ] `make container-build-manageserver` produces an image with the :8443 listener wired.
- [ ] Fresh Manage DB: admin creates first user → activates licence → setup wizard automatically calls Report's `/api/v1/admin/enrol/manage` → push bundle persisted; Manage transitions to operational.
- [ ] Admin creates zone + host; enqueues scan job; orchestrator processes job; drain pushes result to stub Report over valid mTLS.
- [ ] Admin enrols agent → downloads bundle → simulated agent phones home successfully.
- [ ] Revoking an agent blocks further phone-homes within 30s.
- [ ] Licence enforcement: seat / host / scan caps block their respective create paths.
- [ ] Scan-result queue reaches 10k → new enqueues return 503.
- [ ] Dead-letter queue captures permanently-rejected scans after 10 retries.
- [ ] Existing vanilla JS manage UI at `/ui/manage/` on Report Server remains untouched.

## 12. Open Questions / Deferred

- **Batched `/api/v1/scans` ingest on Report** — not in B2.2; drain POSTs sequentially. Revisit if drain throughput becomes a bottleneck.
- **Encrypted-at-rest Manage CA key** — deferred to a hardening pass after B2.2 lands.
- **HSM / KMS-backed Manage CA** — not in B2.2. Future plugin interface.
- **Batch cancellation** of jobs by filter (e.g., "cancel all queued jobs for zone X") — per-job cancel only in B2.2.
- **Priority queues** — all jobs FIFO in B2.2. Priority field can be added later without schema rewrite.

## 13. Collision Risk

A parallel developer is working on SSH-agentless scans. B2.1 refactors `scanjobs`, `credentials`, `discovery`, `agentpush` — overlap possible. Recommend WORKLOG.md or CODEOWNERS coordination before opening B2.1. If the SSH-agentless work merges first, rebase B2.1 on top; the refactor is shallow enough to cleanly replay.
