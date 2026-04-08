# Multi-Tenant Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform Triton into a multi-tenant platform where the license server is the identity authority and the triton server is a stateless scan data plane.

**Architecture:** License server owns orgs, licenses, users, and auth (JWT). Triton server validates every request against the license server (with TTL cache), extracts org_id, and scopes all data access. Agents authenticate via license tokens; humans via JWT.

**Tech Stack:** Go 1.25, Chi v5, pgx v5, Ed25519 JWT, bcrypt, PostgreSQL 18

**Design doc:** `docs/plans/2026-03-07-multi-tenant-design.md`

---

## Status (2026-04-08) — Phases 1 through 4 functionally complete

**As of 2026-04-08, 51 commits beyond main on `feat/multi-tenant`:**

| Phase | Status | Notes |
|---|---|---|
| **Phase 1** (1.1–1.6) | ✅ Closed | License server identity, JWT, superadmin CRUD, seed, validate enrichment |
| **Phase 1.5** (1.5a–1.5e) | ✅ Closed | Report server identity tables, provisioning receiver, auth, user CRUD, mcp gate |
| **Phase 1.7** | ✅ Closed | License server org provisioning client → report server |
| **Phase 1.8** | ✅ Closed | Resend mailer + invite email flow |
| **Phase 1.9** | ✅ API-complete | Org create form gained admin_email/admin_name fields; web UI is 3.5 |
| **Phase 2.1** | ✅ Closed | ValidationCache (TTL, thread-safe, singleflight deferred) — not yet wired |
| **Phase 2.3** | ✅ Closed | UnifiedAuth + TenantContext + RequireTenant middleware |
| **Phase 2.4** | ✅ Closed | UnifiedAuth wired onto /api/v1; scan routes now tenant-scoped |
| **Phase 2.5** | Obsolete | Auth proxy — subsumed by report server's own auth handlers |
| **Phase 2.6** | ✅ Closed | Server tests absorbed into each phase's test deliverables |
| **Phase 2.7** | ✅ Closed | At-rest AES-256-GCM encryption for scan_data |
| **Phase 3.1** | ✅ Closed | Report server login page |
| **Phase 3.2** | ✅ Closed | License server admin UI: superadmins page |
| **Phase 3.3** | ✅ Closed | Report server UI: org-scoped user CRUD |
| **Phase 3.4** | ✅ Closed | Forced password change screen |
| **Phase 3.5** | ✅ Closed | License server org create form with admin_email + temp password reveal |
| **Phase 4.1** | ✅ Closed | API key auth removed |
| **Phase 4.2** | Deferred | Full DEPLOYMENT_GUIDE.md rewrite — substantial, awaits review |
| **Phase 4.3/4.4** | ✅ Absorbed | E2E and integration tests updated incrementally in each phase |
| **Phase 4.5** | Deferred | "Triton Server" → "Report Server" user-facing rename — awaits review |
| **Phase 4.6** | ✅ Closed | Agent `--report-server` flag added; `--server` kept as alias |

**Review rounds completed:**
- Phase 1 — 2 rounds (bug hunting + architecture) — 13 findings fixed
- Phase 1.5 — 2 rounds — 9 findings fixed
- Phase 1.7/1.8 — 2 rounds — 9 findings fixed (incl. D1 rollback-cancel bug, D2 admin field validation)
- Phase 2 — 2 rounds — 8 findings fixed (incl. CRITICAL D1: tenant isolation bypass from missing RequireTenant wire)
- Phase 3+4 — 1 round (code-reviewer + architecture-reviewer) — Tier 1+2 fixed: C1 XSS (single-quote escape + data-attrs), H1 server.New returns error on bad enc key, H2 `--server` MarkDeprecated, F1 POST /scans rejects cross-org body, M1 clear stale JWT on change-pw, M2 mcp gate defence-in-depth, M3 drop dead submitScan param, M4 auth.spec.js E2E, F2 requireServer godoc.
- **Phase 5 Sprint 1** — 2 review rounds. Round 1 (internal) — fixed D1 memory leak, D2 migration comment, D4 credential oracle (403→401), D5 dead truncation branch, D6 coverage gap. Round 2 (full review) — fixed D7 stale comments, D8 janitor-delete race, D9 deterministic janitor shutdown, D10 expired-invite RecordFailure doc, M1 config symmetry (pkg/server.Config now has LoginRateLimiterConfig), S3 no-store header on resend-invite + TODO for mailer integration, S4 moved inviteExpiryWindow to internal/auth.

**Phase 5 deferrals (from full review, to be addressed in Sprint 2 or later):**
- **M2** — migration v5 full-table UPDATE not chunked; safe at current scale but must be split before a million-user deployment.
- **S1** — write an ADR documenting the in-memory rate limiter's split-brain semantics in multi-replica deploys (effective MaxAttempts = 5 × replicas × (deploys+1)).
- **S2** — cross-server email correlation gap: an attacker alternating between license server and report server login gets 2× budget. Log failed-login events with a structured email key so a future SIEM layer can correlate even before the limiter itself becomes shared.
- **N1** — plumb `Server.ctx` that cancels on Shutdown and pass it to `StartJanitor` (currently `context.Background()` with TODO comment).
- **N2** — consider exposing `LoginRateLimiter.Stats()` for /metrics observability (replaces test-only `entryCount` helper).
- **N4** — audit whether any code path ever writes `users.created_at` from a client clock (migration v5 backfills `invited_at` from it, so client-clock skew would propagate to the security-critical expiry anchor).
- **Sprint 2 mailer integration** — report server should push temp passwords via the license server's Resend mailer on resend-invite instead of returning them in the JSON body.

**Still deferred (unchanged from Phase 3+4):** saga/orphan reconciliation, encryption envelope → bytea migration, the DEPLOYMENT_GUIDE rewrite, and the Triton → Report Server user-facing rename.

**Sprint 4 architectural hygiene (from Phase 5 Sprint 3 full-review architecture-reviewer pass):**
- **Arch #1** — Split the report server's audit store to its own PostgreSQL schema (default same DSN, optional `REPORT_SERVER_AUDIT_DB_URL` override). Current co-location means a `DROP SCHEMA` during disaster recovery obliterates the forensic record. License server already has a separate audit store — make the report server match.
- **Arch #2** — Replace the per-event goroutine model in `pkg/server/audit.go::writeAudit` with a single-writer goroutine consuming from a buffered channel and batching `INSERT ... VALUES (...), (...), (...)`. Current semaphore stop-gap is acceptable for Sprint 3 but goroutine-per-event will be a latency cliff under sustained load. Estimate: ~80 LOC, drops memory churn, preserves ordering within a writer.
- **Arch #3** — Add a `keyKind` label (`tenant` vs `ip`) to the rate-limiter metrics path so operators can separate tenant-keyed buckets from the `ip:`-prefixed fallback in dashboards. Observability-only; no behavior change.
- **Arch #4** — Introduce a short-TTL LRU cache (30–60 s) keyed by `sha256(token)` → `(userID, orgID, expiry)` on the `JWTAuth` session lookup so the per-request PG round-trip is amortized. Revocation becomes eventually-consistent within one TTL. Pair with an admin "flush session cache" endpoint for instant-kill scenarios. Do NOT ship to production multi-tenant without this — the current per-request DB cost caps p99 at around 500 req/s.
- **Arch #5** — Switch `/api/v1/metrics` from the hand-written text writer to `prometheus/client_golang` the first time a histogram requirement lands (request latency distribution, audit-write latency). ~2MB binary bloat, negligible.
- **Arch #6** — Refactor the 15 `REPORT_SERVER_*` env vars into a struct-tag driven config parser (`caarlos0/env` or `kelseyhightower/envconfig`) with optional YAML overlay via `REPORT_SERVER_CONFIG_FILE`. Single source of truth, auto-generated `--help`, startup validation. Do this BEFORE adding the 16th env var.
- **Arch #10** — Split `internal/auth/` into sub-packages: `jwt`, `password`, `ratelimit` (or `internal/middleware/ratelimit`), `events`. Four concerns in one flat package is the "utils → graph" trajectory; pure code-motion, ~1 hour, prevents future import cycles.

**Sprint 3 full-review deferrals that are NOT architectural** (all closed in feat/phase5-sprint3 follow-up commit): N1 env var rename + RequestRateLimiter env wiring, N2 `/auth/refresh` + `/auth/change-password` rate-limited, N3 misleading comment clarification, N4 dead `NewGuardWithPubKey` deleted, N5 per-DB cleanup registration, N6 bounded audit semaphore (32 in-flight), N7 503 on transient DB error, N8 change-password sibling-session semantics documented.

**Sprint 3 agent+xlsx+UI full-review round 2 deferrals (added 2026-04-09):**
- **SF1 (Sprint 4)** — Rename or merge `internal/agentconfig` with `internal/config` to avoid two packages named "config". Split identity fields (license_key, report_server) from runtime fields (profile, output_dir, formats) into two files so credential rotation doesn't require touching tuning.
- **SF2 (Sprint 4)** — Introduce `ScanSink` interface in the agent so `Submit(scan)` has pluggable implementations (server, local-FS, future S3/webhook). Today's `if reportServer != "" { submit } else { write local }` branch is shallow but will widen with every new destination.
- **SF3 (Sprint 4)** — Extract `applyTierFiltering` from cmd/agent.go into `internal/license.ResolveEffective(tier, requested)` so license-domain policy lives in the license package and can be reused by `triton scan` + the server-side report handler.
- **SF5 (Sprint 4)** — xlsx generator on the report server does per-request 2× file I/O of the ~10MB template. Cache the template bytes once at startup; consider `excelize.WriteTo(w)` to stream directly to the HTTP response; add a max-concurrent-report-generation semaphore.
- **SF6 (Sprint 4)** — Add `GET /api/v1/capabilities` returning `{tier, allowedFormats, features}` so the UI can show/hide tier-gated buttons rather than relying on server 403s to surface upgrade prompts.
- **NH7** — shared `internal/banner` package so every subcommand (agent, scan, server, license show) uses a consistent "config / license / mode" startup banner.
- **NH8** — ADR documenting the silent-downgrade vs hard-fail policy: degrade when possible, hard-fail only when the requested mode is structurally impossible (e.g., server submission on free tier).
- **NH9** — `compose.prod.yaml` variant with every `${VAR:-default}` stripped to empty string so production operators can't silently fall back to the dev defaults. Rotate the committed dev-signed enterprise token to a 1-year expiry on next release.

**Sprint 3 full-review round 2 items closed** (commit aa43735 → HEAD follow-up): F1 CLI+yaml license conflict warning, F2 license_key whitespace trim on block-scalar paste, F3 invalid profile is a hard error with attribution, F4 default case in handler format dispatch, F5/F6/F7 compose.yaml dev-only banner with rotation recipe, SF4 local `activeGuard` variable replaces package-global mutation throughout runAgent call chain.

---

## Historical status (2026-04-07)

**Active path:** Self-managed auth (this plan, as written + amendments below). Phase 1 Tasks 1.1–1.3 complete on `feat/multi-tenant` (commits `2c82ff9`, `827eb1a`, `4bca111`). Resuming at Task 1.4.

**Parked work:** A Keycloak OIDC integration was prototyped and reviewed but shelved by management decision pending revisit. The full pivot — `pkg/auth/` (oidc, claims, mock), license server admin gating via `RequireRole`, agent client-credentials grant, and a PQC hybrid verifier (ML-DSA) WIP — lives on branch `feat/multi-tenant-keycloak` (commits `4019dfa`, `1cdccc2`, `1e9c460`, `f479cbc`). When Keycloak is greenlit again, rebase or cherry-pick from that branch. Note: reviving Keycloak makes Tasks 1.1, 1.3, 1.4, 1.5, 2.5, 3.1 obsolete.

---

## Amendments (2026-04-07) — Reporting Server, Split Identity, Org Provisioning

The original design assumed a single identity authority (license server) holding all users. Management direction has revised this. The new architecture is:

### Architectural changes

1. **Triton server is renamed "Report Server"** (user-facing only — Go package paths stay as `pkg/server`). Its purpose is now explicit: a central collection point where multiple agents in an organization submit scan reports for aggregation and analysis. Without it, customers would manually collect agent output one machine at a time.

2. **Split identity stores.** The license server and report server now have **separate user populations**:
   - **License server** — superadmins only (multiple allowed). Manages orgs, licenses, seats. No org-level users.
   - **Report server** — org users (org_admin + org_user). Org-scoped data access. Each org has its own admin who can manage users within their org.
   - This supersedes the design doc's "users live in license server" statement. Update the design doc accordingly when convenient.

3. **Cross-server org provisioning (push model).** When a superadmin creates an org in the license server, the license server pushes the new org to the report server via a service-to-service API call. The provisioning payload includes a first-org-admin email; the report server creates the org row, creates the admin user with `must_change_password=true`, and returns an activation link. The license server then emails the link to the admin via Resend.

4. **Agent flow changes.** Agents now take two flags relevant to the server side:
   - `--license-key` — already exists; mandatory for comprehensive scans (already enforced by `Guard.FilterConfig`).
   - `--report-server URL` — **new**, optional. If supplied, agent submits scan output to the report server after scanning. `--server` is deprecated as an alias for one release cycle.
   - The report server validates the license token by calling the license server `/validate` endpoint (with the Phase 2.1 cache).

5. **Transport security.** Agent → report server submissions use TLS in transit. Sensitive scan data is column-encrypted at rest in PostgreSQL. No end-to-end payload encryption (would defeat the report server's ability to aggregate).

6. **Email delivery via Resend API.** New dependency, new env var (`RESEND_API_KEY`). Used for invite emails and (future) password reset emails.

### Status of existing tasks under amendment

| Task | Status | Note |
|---|---|---|
| 1.1 | ✅ Done — **needs follow-up migration v6** | License server users table now scoped to superadmins. Add CHECK constraint to enforce `role = 'platform_admin' AND org_id IS NULL`. Add `must_change_password BOOLEAN DEFAULT FALSE` column (used by report server users table; license server admins don't need it but column added for store-layer reuse). |
| 1.2 | ✅ Done — no change | JWT signing remains generic. |
| 1.3 | ✅ Done — needs amendment in 1.4 era | Login handler must check `must_change_password` and return a flag in the response so the UI can redirect to password change. |
| 1.4 | **Next — scope reduced** | Only handles superadmin CRUD now. Drop org_admin/org_user creation paths. Simpler validation (single role). |
| 1.5 | Amended | Seed initial superadmin (role = `platform_admin`). |
| 1.6 | Amended | `/validate` returns `{org_id, org_name, tier}` — used by report server's validation cache (Task 2.1). Same shape as original plan. |
| 2.1 | No change | Validation cache still needed. |
| 2.2 | No change | Report server's HTTP client to the license server. |
| 2.3 | Simplified | JWT auth on the report server now verifies the **report server's own JWT** (issued by report server, not license server). License token auth still validates against license server. |
| 2.4 | Simplified | RBAC roles on the report server: `org_admin`, `org_user`, `agent`. No `platform_admin` (lives in license server). |
| 2.5 | **Obsolete** | Auth proxy not needed — report server has its own auth handlers (new Task 1.5d). Mark as removed. |
| 2.6 | No change | Update server tests for new auth. |
| 3.1 | Renamed | "Report server login page" instead of "Triton server login page". |
| 3.2 | Amended | License server admin UI: superadmin management page (CRUD on platform admins) + org create form with admin email field. |
| 4.1 | No change | Remove API key auth. |
| 4.2 | Amended | Docs must reflect new naming, two-server topology, Resend setup, env vars. |
| 4.3 | No change | Update E2E tests. |
| 4.4 | No change | Update integration tests. |

### New tasks added by these amendments

**Phase 1 additions (license server):**
- **Task 1.7** — License server: org provisioning client (push to report server)
- **Task 1.8** — License server: Resend email integration + invite email template
- **Task 1.9** — License server: org create form accepts admin email, triggers provisioning + invite

**Phase 1.5: Report Server Identity & Org Tables (NEW PHASE)**
- **Task 1.5a** — Report server: add `organizations`, `users`, `sessions` tables (new migrations in `pkg/store/`)
- **Task 1.5b** — Report server: org provisioning receiver endpoint (`POST /api/v1/admin/orgs`, service-to-service auth)
- **Task 1.5c** — Report server: auth handlers (login, logout, refresh, change-password)
- **Task 1.5d** — Report server: org-scoped user CRUD for org admins
- **Task 1.5e** — Report server: first-login forced password change flow (block all routes except change-password until cleared)

**Phase 2 additions:**
- **Task 2.7** — TLS hardening + at-rest column encryption for `scan_data` JSONB

**Phase 3 additions:**
- **Task 3.3** — Report server UI: org admin user management page
- **Task 3.4** — Report server UI: forced password change screen
- **Task 3.5** — License server UI: org create form + superadmin management

**Phase 4 additions:**
- **Task 4.5** — Cross-cutting rename: "Triton Server" → "Report Server" (user-facing only — docs, CLI help, env var prefix `TRITON_SERVER_*` → `REPORT_SERVER_*`, container/binary names, deployment guide)
- **Task 4.6** — Agent CLI: rename `--server` to `--report-server`, keep `--server` as deprecated alias

### Cross-cutting infrastructure changes

- **New shared secret**: `LICENSE_TO_REPORT_SHARED_KEY` — used by license server to authenticate to the report server's `/admin/orgs` endpoint, and validated by the report server's service-to-service middleware.
- **New encryption key**: `REPORT_SERVER_DATA_ENCRYPTION_KEY` — 32-byte hex, used to column-encrypt `scan_data` at rest.
- **Two JWT signing keys** (one per server): license server already has `TRITON_LICENSE_SERVER_SIGNING_KEY`. Report server gets `REPORT_SERVER_JWT_SIGNING_KEY` (Ed25519 hex).
- **Resend API key**: `RESEND_API_KEY` — license server only.
- **Sender identity**: `RESEND_FROM_EMAIL` and `RESEND_FROM_NAME` for invite emails.

See `.env.example` at the repo root for the full env var list.

### Detailed task specs

The new tasks above are listed at outline level only. Each will be expanded to full TDD detail (red→green→refactor steps, file paths, code samples, commit messages) when it's about to be worked on, following the same structure as Tasks 1.1–1.6. This avoids upfront over-specification of work that may shift as earlier tasks reveal constraints.

---

## Deferred items from Phase 1 reviews (2026-04-08)

Two architecture/API reviews were run after Phase 1 implementation closed (Tasks 1.1–1.6 + their fix sweeps). All Tier 1 (correctness/security) and Tier 2 (architectural cleanup) findings have been fixed in-phase. The following Tier 3 items have been **explicitly deferred** to specific later phases with rationale, so they don't get lost.

### Tier 3 — deferred to target phase

| ID | Source | What | Defer to | Rationale |
|---|---|---|---|---|
| **Arch-2.2** | Architecture review | Move `internal/license/jwt.go` and `UserClaims` into a new `internal/auth/` package. The `internal/license` package is becoming a grab-bag of license-token, JWT, machine fingerprint, HTTP client, and offline cache. Splitting will let the report server import only what it needs. | Phase 1.5 or 2.3 | No second consumer exists yet. Premature extraction risks designing for hypothetical use. Revisit when Phase 1.5c (report server auth handlers) actually imports JWT signing. |
| **Arch-3.1 / 8.4** | Architecture review | Do **not** reuse `licensestore.User` for the report server. Create a separate `User` type in `pkg/store` with non-null `OrgID`, role in `(org_admin, org_user)`, and `must_change_password`. | Phase 1.5a (when adding the report server users table) | Schemas will diverge by design. Sharing the type would force a discriminator on every caller. |
| **Arch-7.2** | Architecture review | Add structured `reason` codes to `/validate` failure responses (`revoked`, `expired`, `inactive`, `token_mismatch`, `not_found`) gated on service-to-service auth. Currently all failures return generic "validation failed". | Phase 2.2 | Requires the `LICENSE_TO_REPORT_SHARED_KEY` infrastructure that Phase 1.5/2.2 will introduce. Adding now would be untested. |
| **A4** | API review | `handleRevokeLicense` decodes `reason` from request body but only writes it to audit, never persists in licenses row. Either persist in a `revoke_reason` column or remove from request body. | When a real consumer needs it | No client currently reads the revoke reason; the persistence work is speculative. |
| **T3** | Test review | The race-condition test (`TestSeedInitialSuperadmin_ConcurrentCallsAreRaceSafe`) is timing-dependent: 20 goroutines released by a sync.WaitGroup barrier, but DB-level concurrency depends on machine speed. Could pass on a slow runner without actually hitting the race. | Low priority | The test does verify the invariant; the timing concern is structural. Mitigated by `make test-integration-race`. |
| **T4** | Test review | Boundary test for `maxNameLen` (255/256 chars) not present for create or update. | Low priority | The `tooLong` helper is shared and tested implicitly by the existing length-rejection paths. |
| **T5** | Test review | The hard-coded `LIMIT 1000` in `ListUsers` SQL is not exercised. A table with 1001+ users silently truncates. | Low priority | Population is expensive in integration tests; would need a store-level mock. Document the cap in handler godoc when it becomes a real concern. |
| **T6** | Test review | `TestListSuperadmins` would break if `setupTestServer` ever started calling `SeedInitialSuperadmin`. | Tracking only | The fragility is a hypothetical; current code doesn't seed in test setup. |

## Deferred items from Phase 2 reviews (2026-04-08)

Phase 2 (Tasks 2.1, 2.3, 2.4, 2.7) was reviewed by both code-reviewer and architecture-reviewer agents. The review found 1 CRITICAL bug (D1: RequireTenant not wired, complete tenant isolation bypass) and 7 other findings. Tier 1 (D1, D2, D3, D4, Arch #6, #7, #1) were fixed in-phase across 3 commits. The following are explicitly deferred.

| ID | Source | What | Defer to | Rationale |
|---|---|---|---|---|
| **D5 (Phase 2)** | Code review | enc_v1 envelope false-positive risk: a legacy plain row whose JSON happens to have a top-level `enc_v1` key would be misinterpreted as encrypted. | When migrating to bytea column (Arch #4 below) | Theoretical only — `pkg/model.ScanResult` has no such field today, and the schema is controlled. The eventual bytea migration eliminates the discriminator entirely. |
| **D6 (Phase 2)** | Code review | ValidationCache thundering herd: concurrent misses on the same key all call upstream. Should use `golang.org/x/sync/singleflight`. | If license server load becomes a real concern | Currently the cache is not wired into any production path. Add singleflight when wiring lands and load profile is known. |
| **D7 (Phase 2)** | Code review | TestScans_AgentSubmitViaLicenseToken misnamed — actually tests unauthenticated single-tenant submit, not the license-token path. Add a real license-token submit test with the X-Triton-License-Token header. | Phase 2.x or with Phase 4 cleanup | Test rename is cosmetic. The license-token submit path IS exercised by the integration suite (via TenantScope's old wiring, now via UnifiedAuth) — just not by this specific named test. |
| **D8 (Phase 2)** | Code review | JWTAuth doesn't write tenant context keys, only userContextKey/claimsContextKey. Inconsistent with UnifiedAuth which writes all three. | Phase 4 deprecation cleanup | JWTAuth is only used on /api/v1/users where handlers read UserFromContext, not TenantFromContext. Inconsistency is real but doesn't cause bugs today. Phase 4 deletes JWTAuth entirely in favor of UnifiedAuth + RequireOrgAdmin. |
| **Arch #2 (Phase 2)** | Architecture | /api/v1/users uses JWTAuth not UnifiedAuth — needs documentation that this is intentional (JWT-only for control-plane vs UnifiedAuth for data-plane). | Phase 3 with web UI work | Architectural distinction needs to be written down somewhere. Phase 3's UI design doc is the natural home. |
| **Arch #3 (Phase 2)** | Architecture | ValidationCache is built but not wired. Either wire it or delete it; don't let it linger as dead code. | Phase 4 entry decision | Phase 3 web UI may not need it; Phase 4 (deprecation cleanup) is the natural decision point. |
| **Arch #4 (Phase 2)** | Architecture | Encryption envelope-inside-JSONB has trade-offs: opaque to JSON queries, base64 expansion defeats TOAST compression, theoretical false-positive on `enc_v1` collision. Migrate to dedicated bytea column. | When server-side JSONB queries on encrypted columns become needed | Pragmatic choice for v1. The trade-offs are real but acceptable until a feature actually needs server-side encrypted-row queries. Track in ADR. |
| **Arch #8 (Phase 2)** | Architecture | Saga framework / orphan reconciliation across the cross-server boundary. Phase 2's encryption work increases the consistency surface (encrypted scan rows that outlive their org). Add an admin endpoint `GET /api/v1/admin/orgs/:id/stats` for ops visibility, even without full reconciliation. | Phase 4 ADR + minimal admin endpoint | The minimal stats endpoint is a small Phase 4 task. Full saga framework remains deferred until the second cross-server write lands. |
| **Arch #9 (Phase 2)** | Architecture | Test infrastructure converging — `mountTenantContextTest`, `seedScanInOrg`, `testServerWithJWT`, `testServer`, `testServerWithGuard`, `testServerWithAuth`, `testServerWithMailer`, `testServerWithReport`. Factor into a `server.NewForTest(...)` constructor with options. | Phase 3 entry | Each new helper is a copy of the prior one with one delta. Refactor before adding more. |
| **D5 alt — Resend retention** | Architecture observation | Verify Resend dashboard's content storage policy and disable if possible. | Ops config | Not a code task. |

---

## Deferred items from Phase 1.7/1.8 reviews (2026-04-08)

Phase 1.7 (report server HTTP client) and Phase 1.8 (Resend mailer) were reviewed by both `pensive:code-reviewer` and `pensive:architecture-reviewer` after implementation closed. Tier 1 (correctness/security) and Tier 2 (architectural alignment) were fixed in-phase in 5 commits. Tier 3 items are deferred to specific future phases.

| ID | Source | What | Defer to | Rationale |
|---|---|---|---|---|
| **Arch #4 (1.7/1.8)** | Architecture | Saga framework / orphan reconciliation. Both servers currently use best-effort rollback instead of real transactions across the cross-server boundary. The instant Phase 2 adds a second cross-server side effect (e.g., "create license too"), the ad-hoc compensating actions will become unreliable. | Phase 2.x | The trigger is the second cross-server write. Current approach (rollback + logged-orphan signal) is acceptable for one cross-server step. Add an orphan-reconciliation scheduled job before the second cross-server write lands. |
| **Arch #5 (1.7/1.8)** | Architecture | Temp password delivery flag. Add `delivery: "email" \| "response" \| "both"` request flag. When `"email"`, response omits `admin_temp_password`. Reduces the plaintext surface area from 3 places (report server request body, license server response, email) to 1-2. | Phase 2 | Current flow is acceptable for v1 API; plaintext in response is necessary as a fallback when email delivery fails. The security improvement is real but not urgent. |
| **Resend content retention** | Architecture observation | Verify Resend's data retention policy — email content may be stored in the Resend dashboard for ~30 days for delivery debugging. If so, turn off content storage via Resend config. | Ops check, not code | Config-only task for the operator deploying the license server. Not in the code's scope. |

## Deferred items from Phase 1.5 reviews (2026-04-08)

Phase 1.5 (report server identity layer — Tasks 1.5a–e) was reviewed by both `pensive:code-reviewer` and `pensive:architecture-reviewer` after implementation closed. The reviews returned 0 critical findings and confirmed that Phase 1 lessons were applied prophylactically. Tier 1 (correctness/security) and Tier 2 (architectural alignment) were fixed in-phase. The following Tier 3 items are explicitly deferred to specific later phases.

### Tier 3 — deferred to target phase

| ID | Source | What | Defer to | Rationale |
|---|---|---|---|---|
| **Arch #10 (1.5)** | Architecture | Unified `TenantContext` resolver. Today there are two separate context keys (`tenantOrgIDKey` for license-token paths, `userContextKey.OrgID` for JWT paths). Phase 2 routes that accept BOTH JWT users and license-token agents on the same URL will need a unified resolver and a single canonical context key. | Phase 2 prep (before any Phase 2 handler is wired) | The design depends on Phase 2's routing decisions. Doing it now would be speculative. |
| **Arch #4 (1.5)** | Architecture | The `Jti` claim added in Phase 1.5c papers over the `sessions.token_hash UNIQUE` design choice. The cleaner long-term model is `sid` claim + sessions PK (drop the token_hash UNIQUE constraint, key sessions on a UUID stamped into the JWT as `sid`). | Phase 2.x cleanup | Substantial refactor across both servers. The current jti fix is correct and ships fine. |
| **L5 (1.5)** | Code review | Concurrent change-password calls have no mutual exclusion — two simultaneous calls can both verify the same current password, both succeed, leaving two valid sessions. Self-inflicted, low-risk for Phase 1.5. | Phase 2.x | Requires DB-level advisory locks or a versioned `password_changed_at` column. |
| **Invite expiry** | Architecture | A 7-day-old temp password is a leaked-credentials hazard. Add `invited_at` and have `handleLogin` reject login for users with `must_change_password = true AND invited_at < now() - 7 days`. | Phase 1.7 | The natural place is alongside email delivery (Phase 1.7 = Resend integration). |
| **`minPasswordLen` consolidation** | Architecture | The `12` constant exists in three places: `minPasswordLen` (license server), `minUserPasswordLen` (report server), `minProvisionPasswordLen` (provisioning handler). If they're meant to be one global policy, hoist into `internal/auth` (or `internal/policy`). | When a third call site lands | Trivial when needed; speculative until then. |
| **L4 (1.5)** | Code review | `CountUsersByOrg` is defined in the `UserStore` interface but not consumed in production code (the last-admin guard uses `ListUsers`). | Observation only | Test/future-use scaffolding; no action required. |

### Tier 1 + Tier 2 fixed in-phase (2026-04-08)

All findings from the second-pass architecture and API/test reviews that warranted in-phase fixes are committed under fix(licenseserver) and fix(license)/fix(licensestore) commits. See git log for exact commit messages.

Phase 1.5 review fixes are committed as a separate batch under `fix(server)` and `fix(store)` commits. See `git log feat/multi-tenant -- pkg/server/ pkg/store/` for the exact set.

| Sev | ID | Status | Commit |
|---|---|---|---|
| Med | A1 (audit event naming) | ✅ | Tier 1 batch |
| Med | A2 (DELETE response shape) | ✅ | Tier 1 batch |
| Low | A5 (nil-guard list handlers) | ✅ | Tier 1 batch |
| Med | T1 (password leak coverage) | ✅ | Tier 1 batch |
| Med | T2 (validation error message assertions) | ✅ | Tier 1 batch |
| Low | Arch-1.2 (CHECK migration TODO marker) | ✅ | Tier 1 batch |
| Low | Arch-6.2 (JWT typ check) | ✅ | Tier 1 batch |
| Med | Arch-4.1 (UserUpdate DTO) | ✅ | Separate commit |
| Med | Arch-5.1 (loadPlatformAdmin helpers) | ✅ | Separate commit |
| Med | Arch-7.1 (cacheTTL on validate response) | ✅ | Separate commit |
| Recommendation | Mock-store helper for M6/M7 tests | ✅ | Separate commit |

---

## Phase 1: License Server -- Users & Auth

### Task 1.1: Database Migration -- users and sessions tables

**Files:**
- Modify: `pkg/licensestore/migrations.go` (append migration v4)
- Modify: `pkg/licensestore/store.go` (add User/Session types + interface methods)
- Test: `pkg/licensestore/postgres_test.go`

**Step 1: Add data types to store.go**

Add after `DashboardStats` struct (~line 113):

```go
// User represents a platform or organization user.
type User struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgID,omitempty"` // empty = platform admin
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"` // platform_admin, org_admin, org_user
	Password  string    `json:"-"`    // bcrypt hash, never serialized
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	OrgName   string    `json:"orgName,omitempty"` // populated by joins
}

// Session represents an active user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userID"`
	TokenHash string    `json:"-"`    // SHA-256 of session token, never serialized
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// UserFilter controls user listing.
type UserFilter struct {
	OrgID string
	Role  string
}
```

**Step 2: Add Store interface methods**

Add to the `Store` interface in `store.go` (~line 38):

```go
	// Users
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, filter UserFilter) ([]User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error

	// Sessions
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error
```

**Step 3: Add migration v4 to migrations.go**

Append to the `migrations` slice:

```go
	// Version 4: Users and sessions for multi-tenant auth.
	`CREATE TABLE users (
		id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
		email      TEXT NOT NULL UNIQUE,
		name       TEXT NOT NULL,
		role       TEXT NOT NULL CHECK (role IN ('platform_admin', 'org_admin', 'org_user')),
		password   TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX idx_users_org_id ON users(org_id);
	CREATE INDEX idx_users_email ON users(email);

	CREATE TABLE sessions (
		id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
	CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);`,
```

**Step 4: Write failing tests**

Add to `postgres_test.go`:

```go
func TestCreateUser(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    org.ID,
		Email:    "alice@example.com",
		Name:     "Alice",
		Role:     "org_admin",
		Password: "$2a$10$fakehash",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	got, err := s.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, got.Email)
	assert.Equal(t, user.Role, got.Role)
	assert.Equal(t, org.ID, got.OrgID)
}

func TestGetUserByEmail(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "bob@example.com", Name: "Bob",
		Role: "org_user", Password: "$2a$10$fakehash",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	got, err := s.GetUserByEmail(context.Background(), "bob@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	u1 := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "dup@example.com", Name: "A", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(context.Background(), u1))
	u2 := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "dup@example.com", Name: "B", Role: "org_user", Password: "y",
	}
	err := s.CreateUser(context.Background(), u2)
	require.Error(t, err)
	var conflict *licensestore.ErrConflict
	assert.ErrorAs(t, err, &conflict)
}

func TestPlatformAdminNoOrg(t *testing.T) {
	s := newTestStore(t)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(),
		Email: "admin@platform.com", Name: "Admin",
		Role: "platform_admin", Password: "$2a$10$fakehash",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	got, err := s.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Empty(t, got.OrgID)
}

func TestListUsersFilterByOrg(t *testing.T) {
	s := newTestStore(t)
	org1 := makeOrg(t, s)
	org2 := makeOrg(t, s)
	for i, orgID := range []string{org1.ID, org1.ID, org2.ID} {
		u := &licensestore.User{
			ID: uuid.Must(uuid.NewV7()).String(), OrgID: orgID,
			Email: fmt.Sprintf("user%d@test.com", i), Name: fmt.Sprintf("U%d", i),
			Role: "org_user", Password: "x",
		}
		require.NoError(t, s.CreateUser(context.Background(), u))
	}
	users, err := s.ListUsers(context.Background(), licensestore.UserFilter{OrgID: org1.ID})
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

func TestUpdateUser(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "update@test.com", Name: "Before", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	user.Name = "After"
	user.Role = "org_admin"
	require.NoError(t, s.UpdateUser(context.Background(), user))
	got, err := s.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, "After", got.Name)
	assert.Equal(t, "org_admin", got.Role)
}

func TestDeleteUser(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "delete@test.com", Name: "Del", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	require.NoError(t, s.DeleteUser(context.Background(), user.ID))
	_, err := s.GetUser(context.Background(), user.ID)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestCreateAndGetSession(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "sess@test.com", Name: "S", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "abc123hash",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, s.CreateSession(context.Background(), sess))
	got, err := s.GetSessionByHash(context.Background(), "abc123hash")
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.UserID)
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := newTestStore(t)
	org := makeOrg(t, s)
	user := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: "expired@test.com", Name: "E", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(context.Background(), user))
	expired := &licensestore.Session{
		ID: uuid.Must(uuid.NewV7()).String(), UserID: user.ID,
		TokenHash: "expired_hash", ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	active := &licensestore.Session{
		ID: uuid.Must(uuid.NewV7()).String(), UserID: user.ID,
		TokenHash: "active_hash", ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(context.Background(), expired))
	require.NoError(t, s.CreateSession(context.Background(), active))
	require.NoError(t, s.DeleteExpiredSessions(context.Background()))
	_, err := s.GetSessionByHash(context.Background(), "expired_hash")
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
	got, err := s.GetSessionByHash(context.Background(), "active_hash")
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.UserID)
}
```

**Step 5: Run tests to verify they fail**

Run: `go test -v -run "TestCreateUser|TestGetUserByEmail|TestCreateUserDuplicate|TestPlatformAdmin|TestListUsersFilter|TestUpdateUser|TestDeleteUser|TestCreateAndGetSession|TestDeleteExpiredSessions" ./pkg/licensestore/...`
Expected: FAIL (methods not implemented)

**Step 6: Implement PostgreSQL methods in postgres.go**

Add user and session CRUD methods. Follow existing patterns (parameterized queries, ErrNotFound on pgx.ErrNoRows, ErrConflict on unique violations).

**Step 7: Run tests to verify they pass**

Run: `go test -v -run "TestCreateUser|TestGetUserByEmail|TestCreateUserDuplicate|TestPlatformAdmin|TestListUsersFilter|TestUpdateUser|TestDeleteUser|TestCreateAndGetSession|TestDeleteExpiredSessions" ./pkg/licensestore/...`
Expected: PASS

**Step 8: Commit**

```bash
git add pkg/licensestore/
git commit -m "feat(licensestore): add users and sessions tables with CRUD

Migration v4 adds users (RBAC: platform_admin/org_admin/org_user)
and sessions (SHA-256 token hash) tables. Platform admins have
NULL org_id. Sessions cascade-delete with users."
```

---

### Task 1.2: JWT Encoding/Decoding

**Files:**
- Create: `internal/license/jwt.go`
- Create: `internal/license/jwt_test.go`

**Step 1: Write failing tests**

```go
// jwt_test.go
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{
		Sub:  "user-123",
		Org:  "org-456",
		Role: "org_admin",
		Name: "Alice",
	}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)
	got, err := VerifyJWT(token, pub)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.Sub)
	assert.Equal(t, "org-456", got.Org)
	assert.Equal(t, "org_admin", got.Role)
	assert.Equal(t, "Alice", got.Name)
}

func TestJWTExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Org: "o1", Role: "org_user", Name: "Bob"}
	token, err := SignJWT(claims, priv, -1*time.Hour)
	require.NoError(t, err)
	_, err = VerifyJWT(token, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestJWTWrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Org: "o1", Role: "org_user", Name: "X"}
	token, _ := SignJWT(claims, priv1, 1*time.Hour)
	_, err := VerifyJWT(token, pub2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestJWTPlatformAdminEmptyOrg(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "admin-1", Org: "", Role: "platform_admin", Name: "Root"}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)
	got, err := VerifyJWT(token, pub)
	require.NoError(t, err)
	assert.Empty(t, got.Org)
	assert.Equal(t, "platform_admin", got.Role)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestJWT" ./internal/license/...`
Expected: FAIL (types/functions not defined)

**Step 3: Implement jwt.go**

```go
// jwt.go
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UserClaims represents JWT claims for human users.
type UserClaims struct {
	Sub  string `json:"sub"`            // user UUID
	Org  string `json:"org,omitempty"`  // org UUID (empty for platform admin)
	Role string `json:"role"`           // platform_admin, org_admin, org_user
	Name string `json:"name"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// SignJWT creates an Ed25519-signed JWT from user claims.
func SignJWT(claims *UserClaims, privKey ed25519.PrivateKey, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.Iat = now.Unix()
	claims.Exp = now.Add(ttl).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(privKey, payload)
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)
	return b64Payload + "." + b64Sig, nil
}

// VerifyJWT parses and verifies an Ed25519-signed JWT.
func VerifyJWT(token string, pubKey ed25519.PublicKey) (*UserClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if !ed25519.Verify(pubKey, payload, sig) {
		return nil, errors.New("invalid signature")
	}
	var claims UserClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshalling claims: %w", err)
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestJWT" ./internal/license/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/license/jwt.go internal/license/jwt_test.go
git commit -m "feat(license): add Ed25519-signed JWT for user auth

Same token format as license tokens (base64url claims.signature).
UserClaims carries sub, org, role, name with TTL-based expiry."
```

---

### Task 1.3: Auth Handlers -- login, refresh, logout

**Files:**
- Create: `pkg/licenseserver/handlers_auth.go`
- Create: `pkg/licenseserver/handlers_auth_test.go`
- Modify: `pkg/licenseserver/server.go` (register routes)

**Step 1: Write failing tests**

```go
// handlers_auth_test.go
package licenseserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func setupAuthTestServer(t *testing.T) (*Server, licensestore.Store, ed25519.PublicKey) {
	t.Helper()
	store := newTestStore(t)  // existing helper from server_test.go
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &Config{
		ListenAddr: ":0",
		AdminKeys:  []string{"test-admin-key"},
		SigningKey:  priv,
		PublicKey:   pub,
	}
	srv := New(cfg, store)
	return srv, store, pub
}

func TestLoginSuccess(t *testing.T) {
	srv, store, pub := setupAuthTestServer(t)
	ctx := context.Background()
	org := &licensestore.Organization{ID: newUUID(), Name: "TestOrg"}
	require.NoError(t, store.CreateOrg(ctx, org))
	hashed, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	user := &licensestore.User{
		ID: newUUID(), OrgID: org.ID, Email: "alice@test.com",
		Name: "Alice", Role: "org_admin", Password: string(hashed),
	}
	require.NoError(t, store.CreateUser(ctx, user))

	body, _ := json.Marshal(map[string]string{"email": "alice@test.com", "password": "secret123"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["expiresAt"])

	// Verify the JWT is valid
	claims, err := license.VerifyJWT(resp["token"].(string), pub)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.Sub)
	assert.Equal(t, org.ID, claims.Org)
	assert.Equal(t, "org_admin", claims.Role)
}

func TestLoginWrongPassword(t *testing.T) {
	srv, store, _ := setupAuthTestServer(t)
	ctx := context.Background()
	org := &licensestore.Organization{ID: newUUID(), Name: "WrongPwOrg"}
	require.NoError(t, store.CreateOrg(ctx, org))
	hashed, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.DefaultCost)
	user := &licensestore.User{
		ID: newUUID(), OrgID: org.ID, Email: "wrong@test.com",
		Name: "Wrong", Role: "org_user", Password: string(hashed),
	}
	require.NoError(t, store.CreateUser(ctx, user))

	body, _ := json.Marshal(map[string]string{"email": "wrong@test.com", "password": "incorrect"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLoginUnknownEmail(t *testing.T) {
	srv, _, _ := setupAuthTestServer(t)
	body, _ := json.Marshal(map[string]string{"email": "nobody@test.com", "password": "x"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout(t *testing.T) {
	srv, store, pub := setupAuthTestServer(t)
	ctx := context.Background()
	org := &licensestore.Organization{ID: newUUID(), Name: "LogoutOrg"}
	require.NoError(t, store.CreateOrg(ctx, org))
	hashed, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.DefaultCost)
	user := &licensestore.User{
		ID: newUUID(), OrgID: org.ID, Email: "logout@test.com",
		Name: "L", Role: "org_user", Password: string(hashed),
	}
	require.NoError(t, store.CreateUser(ctx, user))

	// Login first
	body, _ := json.Marshal(map[string]string{"email": "logout@test.com", "password": "pw"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var loginResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	token := loginResp["token"].(string)

	// Verify token works
	_, err := license.VerifyJWT(token, pub)
	require.NoError(t, err)

	// Logout
	req = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestLogin|TestLogout" ./pkg/licenseserver/...`
Expected: FAIL

**Step 3: Implement handlers_auth.go**

Key implementation details:
- `handleLogin`: decode email+password, call `store.GetUserByEmail()`, `bcrypt.CompareHashAndPassword()`, `license.SignJWT()` with 24h TTL, create session with SHA-256(token) hash, return `{token, expiresAt}`
- `handleLogout`: extract Bearer token, compute SHA-256 hash, call `store.DeleteSession()` (by looking up session, then deleting)
- `handleRefresh`: extract Bearer token, verify JWT (allow 5-min grace for just-expired), issue new JWT + session, delete old session

**Step 4: Register routes in server.go**

Add public auth routes (no admin key required) at ~line 68:

```go
// Auth routes (public, no admin key)
r.Route("/api/v1/auth", func(r chi.Router) {
	r.Post("/login", srv.handleLogin)
	r.Post("/logout", srv.handleLogout)
	r.Post("/refresh", srv.handleRefresh)
})
```

**Step 5: Run tests to verify they pass**

Run: `go test -v -run "TestLogin|TestLogout" ./pkg/licenseserver/...`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/licenseserver/handlers_auth.go pkg/licenseserver/handlers_auth_test.go pkg/licenseserver/server.go
git commit -m "feat(licenseserver): add auth endpoints -- login, logout, refresh

POST /api/v1/auth/login: email+password -> Ed25519-signed JWT (24h)
POST /api/v1/auth/logout: invalidate session
POST /api/v1/auth/refresh: rotate JWT token
Sessions stored as SHA-256 hashes. bcrypt password verification."
```

---

### Task 1.4: Superadmin CRUD Handlers

**Amended 2026-04-07:** Originally specified user CRUD for all three roles (`platform_admin`, `org_admin`, `org_user`). Under the split-identity model, the license server only holds **superadmins** (`platform_admin`). Org users live in the report server (Task 1.5d). This task is now scoped to superadmin CRUD only — single role, no `?org=` filter, simpler validation.

**Goal:** Expose admin-gated REST endpoints for managing the license server's superadmin population. Only platform_admin role is supported. The store layer (`CreateUser`, `GetUser`, `ListUsers`, `UpdateUser`, `DeleteUser`) was built in Task 1.1 and is reused as-is.

**Files:**
- Create: `pkg/licenseserver/handlers_superadmin.go`
- Create: `pkg/licenseserver/handlers_superadmin_test.go`
- Modify: `pkg/licenseserver/server.go` (register `/admin/superadmins` route group)

**API surface (all behind `X-Triton-Admin-Key`):**

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/admin/superadmins` | Create a new superadmin (email + name + password) |
| GET | `/api/v1/admin/superadmins` | List all superadmins (no filter — superadmin pool is small) |
| GET | `/api/v1/admin/superadmins/{id}` | Fetch one by UUID |
| PUT | `/api/v1/admin/superadmins/{id}` | Update name and/or password |
| DELETE | `/api/v1/admin/superadmins/{id}` | Delete (sessions cascade via FK) |

**Validation rules:**
- Email: required, must contain `@`, max 255 chars, lowercased before storage
- Name: required, max 255 chars
- Password: required on create, optional on update (omit to keep current); minimum 12 characters when supplied; bcrypt hashed before storage with `bcrypt.DefaultCost`
- Role: forced to `platform_admin` server-side — never accepted from request body. Even if the client sends `role: "org_user"`, it is ignored.
- OrgID: forced to empty string server-side. Superadmins are not org-scoped.
- Duplicate email returns HTTP 409 (store layer returns `ErrConflict`, which the handler maps).

**Response shape:**
- Successful create/get returns the `User` struct (password field excluded via `json:"-"`).
- List returns a JSON array (empty array `[]`, never null).
- Delete returns HTTP 204 No Content.
- Errors follow the existing `{error: "..."}` envelope from `writeError`.

**Audit trail:**
Each mutating handler (create, update, delete) calls `s.audit(r, "<event>", actorID, targetID, targetType, details)` to write to the audit log. Event names:
- `superadmin_create`
- `superadmin_update`
- `superadmin_delete`

(The actor is currently the admin key's identity — represented as `"admin-key"` until JWT-based actor tracking lands in a later task.)

---

**Step 1: Write failing tests**

Create `pkg/licenseserver/handlers_superadmin_test.go` with the following 14 tests. Use the existing test setup from `server_test.go` (`newTestServer`, `adminReq` helpers — adapt or extend if needed). Tests use `httptest.NewRecorder` and call `srv.Router().ServeHTTP(...)` directly.

```go
// Smoke / happy paths
TestCreateSuperadmin            // POST → 201, returns user with empty password field
TestListSuperadmins             // POST 3, GET → 200, len=3
TestGetSuperadmin               // POST then GET by ID → 200
TestUpdateSuperadminName        // PUT with name only → 200, password unchanged
TestUpdateSuperadminPassword    // PUT with new password → can log in with new pwd, not old
TestDeleteSuperadmin            // POST then DELETE → 204, GET → 404

// Validation edge cases
TestCreateSuperadminMissingEmail        // POST {name,password} → 400
TestCreateSuperadminMissingPassword     // POST {email,name} → 400
TestCreateSuperadminWeakPassword        // POST with 8-char password → 400
TestCreateSuperadminInvalidEmail        // POST with "notanemail" → 400
TestCreateSuperadminDuplicateEmail      // POST same email twice → 409
TestCreateSuperadminIgnoresRole         // POST with role="org_user" → 201, persisted role is platform_admin
TestGetSuperadminNotFound               // GET random UUID → 404

// Auth
TestSuperadminRoutesRequireAdminKey     // POST without X-Triton-Admin-Key → 401

// Security
TestPasswordNeverInResponse             // POST then GET → response JSON has no "password" field
```

**Test helpers needed (add to `server_test.go` if not present):**

```go
// adminReq builds a request with the admin key header set.
func adminReq(t *testing.T, method, path string, body any) *http.Request {
    t.Helper()
    var bodyReader io.Reader
    if body != nil {
        b, err := json.Marshal(body)
        if err != nil {
            t.Fatalf("marshal: %v", err)
        }
        bodyReader = bytes.NewReader(b)
    }
    req := httptest.NewRequest(method, path, bodyReader)
    req.Header.Set("X-Triton-Admin-Key", testAdminKey)
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    return req
}
```

**Step 2: Run tests, verify they fail (RED)**

```bash
go test -v -run "TestCreateSuperadmin|TestListSuperadmins|TestGetSuperadmin|TestUpdateSuperadmin|TestDeleteSuperadmin|TestSuperadminRoutes|TestPasswordNeverInResponse" ./pkg/licenseserver/...
```

Expected: all 14 tests FAIL (handlers don't exist yet).

**Step 3: Implement `handlers_superadmin.go` (GREEN)**

Skeleton (match the existing style of `handlers_org.go`):

```go
package licenseserver

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

    "github.com/amiryahaya/triton/pkg/licensestore"
)

const (
    minPasswordLen = 12
    maxEmailLen    = 255
)

type createSuperadminRequest struct {
    Email    string `json:"email"`
    Name     string `json:"name"`
    Password string `json:"password"`
}

type updateSuperadminRequest struct {
    Name     string `json:"name"`
    Password string `json:"password,omitempty"` // omit to keep current
}

// POST /api/v1/admin/superadmins
func (s *Server) handleCreateSuperadmin(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
    var req createSuperadminRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    email := strings.ToLower(strings.TrimSpace(req.Email))
    if email == "" || !strings.Contains(email, "@") {
        writeError(w, http.StatusBadRequest, "valid email is required")
        return
    }
    if tooLong(email, maxEmailLen) {
        writeError(w, http.StatusBadRequest, "email exceeds maximum length")
        return
    }
    if req.Name == "" {
        writeError(w, http.StatusBadRequest, "name is required")
        return
    }
    if tooLong(req.Name, maxNameLen) {
        writeError(w, http.StatusBadRequest, "name exceeds maximum length")
        return
    }
    if len(req.Password) < minPasswordLen {
        writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
        return
    }

    hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("bcrypt error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    now := time.Now().UTC()
    user := &licensestore.User{
        ID:        uuid.Must(uuid.NewV7()).String(),
        Email:     email,
        Name:      req.Name,
        Role:      "platform_admin", // forced — request body role ignored
        Password:  string(hashed),
        CreatedAt: now,
        UpdatedAt: now,
    }

    if err := s.store.CreateUser(r.Context(), user); err != nil {
        var conflict *licensestore.ErrConflict
        if errors.As(err, &conflict) {
            writeError(w, http.StatusConflict, conflict.Message)
            return
        }
        log.Printf("create superadmin error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    s.audit(r, "superadmin_create", "", user.ID, "user", nil)
    writeJSON(w, http.StatusCreated, user)
}

// GET /api/v1/admin/superadmins
func (s *Server) handleListSuperadmins(w http.ResponseWriter, r *http.Request) {
    users, err := s.store.ListUsers(r.Context(), licensestore.UserFilter{Role: "platform_admin"})
    if err != nil {
        log.Printf("list superadmins error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if users == nil {
        users = []licensestore.User{} // never return null
    }
    writeJSON(w, http.StatusOK, users)
}

// GET /api/v1/admin/superadmins/{id}
func (s *Server) handleGetSuperadmin(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    user, err := s.store.GetUser(r.Context(), id)
    if err != nil {
        var nf *licensestore.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "superadmin not found")
            return
        }
        log.Printf("get superadmin error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if user.Role != "platform_admin" {
        // Defensive: this endpoint only exposes superadmins. If somehow the
        // table contains a non-platform_admin row, hide it.
        writeError(w, http.StatusNotFound, "superadmin not found")
        return
    }
    writeJSON(w, http.StatusOK, user)
}

// PUT /api/v1/admin/superadmins/{id}
func (s *Server) handleUpdateSuperadmin(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
    var req updateSuperadminRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    existing, err := s.store.GetUser(r.Context(), id)
    if err != nil {
        var nf *licensestore.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "superadmin not found")
            return
        }
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if existing.Role != "platform_admin" {
        writeError(w, http.StatusNotFound, "superadmin not found")
        return
    }

    if req.Name != "" {
        if tooLong(req.Name, maxNameLen) {
            writeError(w, http.StatusBadRequest, "name exceeds maximum length")
            return
        }
        existing.Name = req.Name
    }
    if req.Password != "" {
        if len(req.Password) < minPasswordLen {
            writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
            return
        }
        hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
        if err != nil {
            writeError(w, http.StatusInternalServerError, "internal server error")
            return
        }
        existing.Password = string(hashed)
    }
    // Role is never updated.

    if err := s.store.UpdateUser(r.Context(), existing); err != nil {
        log.Printf("update superadmin error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    s.audit(r, "superadmin_update", "", id, "user", nil)
    writeJSON(w, http.StatusOK, existing)
}

// DELETE /api/v1/admin/superadmins/{id}
func (s *Server) handleDeleteSuperadmin(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")

    // Verify the target is a superadmin before deleting (defensive against
    // accidental deletion of org users that may exist in the table during
    // the migration window).
    existing, err := s.store.GetUser(r.Context(), id)
    if err != nil {
        var nf *licensestore.ErrNotFound
        if errors.As(err, &nf) {
            writeError(w, http.StatusNotFound, "superadmin not found")
            return
        }
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if existing.Role != "platform_admin" {
        writeError(w, http.StatusNotFound, "superadmin not found")
        return
    }

    if err := s.store.DeleteUser(r.Context(), id); err != nil {
        log.Printf("delete superadmin error: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    s.audit(r, "superadmin_delete", "", id, "user", nil)
    w.WriteHeader(http.StatusNoContent)
}
```

**Step 4: Register routes in `server.go`**

Add inside the existing `r.Route("/api/v1/admin", ...)` block (around line 110, after the Audit/Stats routes):

```go
// Superadmins (platform admins for the license server itself)
r.Route("/superadmins", func(r chi.Router) {
    r.Post("/", srv.handleCreateSuperadmin)
    r.Get("/", srv.handleListSuperadmins)
    r.Get("/{id}", srv.handleGetSuperadmin)
    r.Put("/{id}", srv.handleUpdateSuperadmin)
    r.Delete("/{id}", srv.handleDeleteSuperadmin)
})
```

**Step 5: Run tests, verify pass (GREEN)**

```bash
go test -v -run "TestCreateSuperadmin|TestListSuperadmins|TestGetSuperadmin|TestUpdateSuperadmin|TestDeleteSuperadmin|TestSuperadminRoutes|TestPasswordNeverInResponse" ./pkg/licenseserver/...
```

Expected: all 14 tests PASS.

**Step 6: Refactor**

Look for:
- Repeated `existing.Role != "platform_admin"` check across get/update/delete → consider extracting `s.getSuperadminByID(ctx, id)` helper that returns `(*User, error)` and folds the role check.
- Validation of email/name/password is duplicated between create and update (partially) → consider a `validateSuperadminFields(email, name, password string, isCreate bool) error` helper.
- The `users == nil` guard in `handleListSuperadmins` is a pattern that should also exist in any other list handler — leave alone for now if other handlers don't do it; raise it as a separate cleanup.

Run tests again after each refactor. Refactor only if it improves clarity — don't speculate.

**Step 7: Run full unit suite to confirm nothing broke**

```bash
go test ./pkg/licenseserver/...
```

**Step 8: Commit**

```bash
git add pkg/licenseserver/handlers_superadmin.go \
        pkg/licenseserver/handlers_superadmin_test.go \
        pkg/licenseserver/server.go
git commit -m "feat(licenseserver): add superadmin CRUD endpoints under admin API

Adds /api/v1/admin/superadmins (POST/GET/GET-id/PUT/DELETE) for managing
platform admins of the license server. Single role enforced server-side
(platform_admin); request-body role is ignored. Min 12-char passwords,
bcrypt hashed. Reuses existing User store methods from Task 1.1.

Superadmins are the only user population in the license server under
the 2026-04-07 split-identity amendment. Org users live in the report
server (Task 1.5d).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

**Out of scope for this task (deferred):**
- Login flow for superadmins (Task 1.3 already provides `/api/v1/auth/login`; that handler must be updated to enforce `role = 'platform_admin'` if it doesn't already, but that's a Task 1.3 amendment, not a 1.4 deliverable).
- The DB CHECK constraint tightening (`role = 'platform_admin' AND org_id IS NULL`) is a Task 1.1 follow-up migration, not part of 1.4. The handler enforces it at the application layer for now.
- Audit actor identity beyond `"admin-key"` placeholder — improved when JWT-based actor tracking lands.

---

### Task 1.5: Seed Initial Platform Admin

**Files:**
- Modify: `cmd/licenseserver/main.go` (add seeding logic)
- Modify: `pkg/licensestore/store.go` (add `CountUsers` method)
- Modify: `pkg/licensestore/postgres.go` (implement `CountUsers`)

**Step 1: Add CountUsers to store interface and implement**

```go
// store.go - add to Store interface
CountUsers(ctx context.Context) (int, error)

// postgres.go
func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
```

**Step 2: Add seeding in main.go**

After store creation, before server start:

```go
// Seed initial platform admin if no users exist.
count, err := store.CountUsers(ctx)
if err != nil {
	return fmt.Errorf("counting users: %w", err)
}
if count == 0 {
	adminEmail := envOr("TRITON_LICENSE_SERVER_ADMIN_EMAIL", "admin@localhost")
	adminPassword := envOr("TRITON_LICENSE_SERVER_ADMIN_PASSWORD", "")
	if adminPassword == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_ADMIN_PASSWORD is required on first run (no users exist)")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}
	admin := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    adminEmail,
		Name:     "Platform Admin",
		Role:     "platform_admin",
		Password: string(hashed),
	}
	if err := store.CreateUser(ctx, admin); err != nil {
		return fmt.Errorf("seeding admin user: %w", err)
	}
	log.Printf("Seeded initial platform admin: %s", adminEmail)
}
```

**Step 3: Commit**

```bash
git add cmd/licenseserver/main.go pkg/licensestore/store.go pkg/licensestore/postgres.go
git commit -m "feat(licenseserver): seed platform admin on first startup

If no users exist, creates platform_admin from TRITON_LICENSE_SERVER_ADMIN_EMAIL
and TRITON_LICENSE_SERVER_ADMIN_PASSWORD env vars."
```

---

### Task 1.6: Enhanced Validate Endpoint -- return org info

**Files:**
- Modify: `pkg/licenseserver/handlers_activation.go` (enhance handleValidate response)
- Modify: `pkg/licenseserver/handlers_activation_test.go`

**Step 1: Write failing test**

```go
func TestValidateReturnsOrgInfo(t *testing.T) {
	// Setup: create org, license, activate, then validate
	// Assert response includes: orgID, orgName, tier fields
	// Current response only has: valid, tier, seats, seatsUsed, expiresAt
	// New response adds: orgID, orgName
}
```

**Step 2: Enhance handleValidate response**

Add `OrgID` and `OrgName` fields to the validate response struct (~line 195):

```go
type validateResponse struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason,omitempty"`
	Tier      string `json:"tier,omitempty"`
	OrgID     string `json:"orgID,omitempty"`     // NEW
	OrgName   string `json:"orgName,omitempty"`   // NEW
	Seats     int    `json:"seats,omitempty"`
	SeatsUsed int    `json:"seatsUsed,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}
```

Populate from the license record (already fetched in handleValidate).

**Step 3: Run tests, verify pass**

**Step 4: Commit**

```bash
git add pkg/licenseserver/handlers_activation.go pkg/licenseserver/handlers_activation_test.go
git commit -m "feat(licenseserver): return orgID and orgName in validate response

Triton server needs org context from validation to scope scan data."
```

---

## Phase 2: Triton Server -- New Auth Middleware

### Task 2.1: Validation Cache

**Files:**
- Create: `pkg/server/valcache.go`
- Create: `pkg/server/valcache_test.go`

**Step 1: Write failing tests**

```go
func TestValCacheGetMiss(t *testing.T) {
	c := NewValidationCache(5*time.Minute, 30*time.Minute)
	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
}

func TestValCacheSetAndGet(t *testing.T) {
	c := NewValidationCache(5*time.Minute, 30*time.Minute)
	entry := &ValCacheEntry{OrgID: "org1", Tier: "pro", Valid: true}
	c.Set("tok1", entry)
	got, ok := c.Get("tok1")
	assert.True(t, ok)
	assert.Equal(t, "org1", got.OrgID)
}

func TestValCacheExpired(t *testing.T) {
	c := NewValidationCache(1*time.Millisecond, 1*time.Millisecond)
	c.Set("tok1", &ValCacheEntry{OrgID: "org1", Valid: true})
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("tok1")
	assert.False(t, ok)
}

func TestValCacheStale(t *testing.T) {
	c := NewValidationCache(1*time.Millisecond, 1*time.Hour)
	c.Set("tok1", &ValCacheEntry{OrgID: "org1", Valid: true})
	time.Sleep(5 * time.Millisecond)
	got, ok := c.Get("tok1")
	assert.True(t, ok)   // within grace
	assert.True(t, got.Stale)
}
```

**Step 2: Implement valcache.go**

```go
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type ValCacheEntry struct {
	OrgID   string
	OrgName string
	Tier    string
	Valid   bool
	Stale   bool
	CachedAt time.Time
}

type ValidationCache struct {
	mu      sync.RWMutex
	entries map[string]*ValCacheEntry
	ttl     time.Duration
	grace   time.Duration
}

func NewValidationCache(ttl, grace time.Duration) *ValidationCache {
	return &ValidationCache{
		entries: make(map[string]*ValCacheEntry),
		ttl:     ttl,
		grace:   grace,
	}
}

func (c *ValidationCache) key(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (c *ValidationCache) Get(token string) (*ValCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[c.key(token)]
	if !ok {
		return nil, false
	}
	age := time.Since(e.CachedAt)
	if age > c.grace {
		return nil, false // fully expired
	}
	result := *e // copy
	result.Stale = age > c.ttl
	return &result, true
}

func (c *ValidationCache) Set(token string, entry *ValCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.CachedAt = time.Now()
	c.entries[c.key(token)] = entry
}
```

**Step 3: Run tests, verify pass**

**Step 4: Commit**

```bash
git add pkg/server/valcache.go pkg/server/valcache_test.go
git commit -m "feat(server): add in-memory validation cache with TTL and grace period

Cache key is SHA-256 of token. Entries are fresh (<TTL), stale (TTL-grace),
or expired (>grace). Stale entries returned with Stale=true for async refresh."
```

---

### Task 2.2: License Server Client for Triton Server

**Files:**
- Create: `pkg/server/licenseclient.go`
- Create: `pkg/server/licenseclient_test.go`

**Step 1: Write failing tests**

Test the client that triton server uses to call license server's validate endpoint. Use httptest.Server to mock the license server.

```go
func TestLicenseClientValidate(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/license/validate", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "tier": "enterprise",
			"orgID": "org-123", "orgName": "Acme",
			"seats": 10, "seatsUsed": 3,
		})
	}))
	defer mockServer.Close()

	client := NewLicenseClient(mockServer.URL, "service-key")
	result, err := client.ValidateToken("lic-id", "machine-id", "token-string")
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "org-123", result.OrgID)
	assert.Equal(t, "enterprise", result.Tier)
}

func TestLicenseClientValidateInvalid(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "reason": "revoked"})
	}))
	defer mockServer.Close()

	client := NewLicenseClient(mockServer.URL, "service-key")
	result, err := client.ValidateToken("lic-id", "machine-id", "bad-token")
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, "revoked", result.Reason)
}
```

**Step 2: Implement licenseclient.go**

```go
package server

// LicenseClient calls the license server's validate endpoint.
type LicenseClient struct {
	baseURL    string
	serviceKey string
	httpClient *http.Client
}

type ValidateResult struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason,omitempty"`
	OrgID     string `json:"orgID,omitempty"`
	OrgName   string `json:"orgName,omitempty"`
	Tier      string `json:"tier,omitempty"`
	Seats     int    `json:"seats,omitempty"`
	SeatsUsed int    `json:"seatsUsed,omitempty"`
}

func (c *LicenseClient) ValidateToken(licenseID, machineID, token string) (*ValidateResult, error) {
	// POST to /api/v1/license/validate with JSON body
	// Parse response into ValidateResult
}
```

**Step 3: Run tests, verify pass**

**Step 4: Commit**

```bash
git add pkg/server/licenseclient.go pkg/server/licenseclient_test.go
git commit -m "feat(server): add license client for server-to-license-server validation

Calls POST /api/v1/license/validate. Returns org context (orgID, orgName, tier)
for tenant scoping. 15s timeout, 1MB response limit."
```

---

### Task 2.3: Dual Auth Middleware (JWT + License Token)

**Files:**
- Modify: `pkg/server/tenant.go` (replace TenantScope with DualAuth)
- Create: `pkg/server/authcontext.go` (auth context types)
- Modify: `pkg/server/server.go` (wire new middleware)
- Test: `pkg/server/server_test.go`

**Step 1: Define auth context types**

```go
// authcontext.go
package server

type AuthIdentity struct {
	Type    string // "user" or "agent"
	UserID  string // for JWT auth
	OrgID   string
	OrgName string
	Role    string // platform_admin, org_admin, org_user, agent
	Tier    string // license tier
}

func AuthFromContext(ctx context.Context) *AuthIdentity { ... }
```

**Step 2: Implement DualAuth middleware**

Replace `TenantScope` + `APIKeyAuth` with a single `DualAuth` middleware:

1. Check `Authorization: Bearer <JWT>` header first (human users)
   - Verify JWT with license server's public key
   - Extract sub, org, role
   - Set AuthIdentity{Type: "user", ...}

2. Check `X-Triton-License-Token` header (agents)
   - Parse license token locally (Ed25519 signature check)
   - Extract license_id, machine_id from token
   - Validate against license server (via LicenseClient + ValCache)
   - Set AuthIdentity{Type: "agent", OrgID: result.OrgID, Role: "agent"}

3. No auth → 401

**Step 3: Update handlers to use AuthFromContext**

Replace all `TenantFromContext(r.Context())` with `AuthFromContext(r.Context()).OrgID`.

**Step 4: Commit**

```bash
git commit -m "feat(server): replace API key auth with dual JWT + license token auth

DualAuth middleware: JWT (human users) or license token (agents).
JWT verified locally with Ed25519 public key.
License tokens validated against license server with 5-min cache."
```

---

### Task 2.4: Role-Based Access Control Middleware

**Files:**
- Create: `pkg/server/rbac.go`
- Create: `pkg/server/rbac_test.go`
- Modify: `pkg/server/server.go` (apply RBAC to routes)

**Step 1: Implement RBAC middleware**

```go
// rbac.go
package server

// RequireRole returns middleware that checks the auth identity role.
func RequireRole(allowed ...string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowed))
	for _, r := range allowed {
		set[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := AuthFromContext(r.Context())
			if auth == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			// Platform admin can do everything
			if auth.Role == "platform_admin" {
				next.ServeHTTP(w, r)
				return
			}
			if !set[auth.Role] {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

**Step 2: Apply RBAC to routes in server.go**

Based on the permissions matrix:

```go
r.Route("/api/v1", func(r chi.Router) {
	r.Use(DualAuth(cfg, valCache, licClient))

	// Public
	r.Get("/health", srv.handleHealth)

	// Agent-only
	r.With(RequireRole("agent")).Post("/scans", srv.handleSubmitScan)

	// Authenticated users (any role) + platform admin
	r.Group(func(r chi.Router) {
		r.Use(RequireRole("org_admin", "org_user"))
		r.Get("/scans", srv.handleListScans)
		r.Get("/scans/{id}", srv.handleGetScan)
		r.Get("/scans/{id}/findings", srv.handleGetFindings)
		r.Get("/diff", srv.handleDiff)
		r.Get("/trend", srv.handleTrend)
		r.Get("/machines", srv.handleListMachines)
		r.Get("/machines/{hostname}", srv.handleMachineHistory)
		r.Post("/policy/evaluate", srv.handlePolicyEvaluate)
		r.Get("/reports/{id}/{format}", srv.handleGenerateReport)
		r.Get("/aggregate", srv.handleAggregate)
	})

	// Admin-only (org_admin deletes own org scans, platform_admin any)
	r.With(RequireRole("org_admin")).Delete("/scans/{id}", srv.handleDeleteScan)

	// Auth proxy
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", srv.handleAuthLogin)    // proxy to license server
		r.Post("/logout", srv.handleAuthLogout)
		r.Post("/refresh", srv.handleAuthRefresh)
		r.Get("/me", srv.handleAuthMe)
	})
})
```

**Step 3: Write tests for RBAC enforcement**

Test each role against allowed/denied routes.

**Step 4: Commit**

```bash
git commit -m "feat(server): add RBAC middleware enforcing permissions matrix

Routes gated by role: agent (submit only), org_user (read),
org_admin (read+delete), platform_admin (everything).
Platform admin bypasses all role checks."
```

---

### Task 2.5: Auth Proxy Handlers

**Files:**
- Create: `pkg/server/handlers_auth.go`
- Modify: `pkg/server/server.go` (Config changes)
- Modify: `cmd/server.go` (add --license-server flag)

**Step 1: Add license server URL to Config**

```go
// server.go Config struct
type Config struct {
	ListenAddr       string
	DBUrl            string
	APIKeys          []string          // DEPRECATED
	TLSCert          string
	TLSKey           string
	Guard            *license.Guard
	TenantPubKey     []byte
	LicenseServerURL string            // NEW: required
	LicenseServerKey string            // NEW: service-to-service auth
}
```

**Step 2: Add --license-server flag to cmd/server.go**

```go
serverCmd.Flags().StringVar(&licenseServerURL, "license-server", "", "License server URL (required)")
serverCmd.Flags().StringVar(&licenseServerKey, "license-server-key", "", "License server service key")
```

**Step 3: Implement auth proxy handlers**

```go
// handlers_auth.go
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	// Proxy POST to license server /api/v1/auth/login
	// Return JWT token to caller
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	// Proxy POST to license server /api/v1/auth/logout
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	// Proxy POST to license server /api/v1/auth/refresh
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	// Extract claims from JWT in context, return user info
	auth := AuthFromContext(r.Context())
	writeJSON(w, http.StatusOK, auth)
}
```

**Step 4: Deprecate --api-key with warning**

In `cmd/server.go`:

```go
if len(serverAPIKeys) > 0 {
	log.Println("WARNING: --api-key is deprecated and will be removed. Use license tokens instead.")
}
```

**Step 5: Commit**

```bash
git commit -m "feat(server): add auth proxy and --license-server flag

Login/logout/refresh proxied to license server. --api-key deprecated
with warning. --license-server required for production use."
```

---

### Task 2.6: Update Server Tests

**Files:**
- Modify: `pkg/server/server_test.go` (update all tests to use new auth)
- Modify: `test/integration/server_workflow_test.go`

**Step 1: Update test helpers**

Create helper that generates a test JWT for use in test requests:

```go
func testJWT(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, orgID, role string) string {
	t.Helper()
	claims := &license.UserClaims{Sub: "test-user", Org: orgID, Role: role, Name: "Test"}
	token, err := license.SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)
	return token
}
```

**Step 2: Update all test requests to include auth headers**

Replace `req.Header.Set("X-Triton-API-Key", ...)` with `req.Header.Set("Authorization", "Bearer "+jwt)`.

**Step 3: Run full test suite**

Run: `go test -v ./pkg/server/...`
Expected: PASS

**Step 4: Commit**

```bash
git commit -m "test(server): update all tests to use JWT auth

Replace API key auth in tests with JWT Bearer tokens.
Add testJWT helper for generating test tokens."
```

---

## Phase 3: Web UI Update

### Task 3.1: Triton Server Login Page

**Files:**
- Modify: `pkg/server/ui/dist/index.html` (add login form)
- Modify: `pkg/server/ui/dist/app.js` (add auth logic)

**Step 1: Add login screen**

- Email + password form
- Submit to `/api/v1/auth/login`
- Store JWT in `sessionStorage`
- Include JWT in all subsequent API calls as `Authorization: Bearer`
- Show/hide UI based on auth state
- Logout button calls `/api/v1/auth/logout`

**Step 2: Add org-scoped views**

- Dashboard shows only authenticated org's data
- Platform admin sees org selector dropdown
- All API calls automatically scoped by JWT's org claim

**Step 3: Commit**

```bash
git commit -m "feat(ui): add login page and org-scoped dashboard

Email/password login, JWT stored in sessionStorage.
Org-scoped views for org users. Platform admin sees all orgs."
```

---

### Task 3.2: License Server Admin UI -- User Management

**Files:**
- Modify: `pkg/licenseserver/ui/dist/index.html` (add users page)
- Modify: `pkg/licenseserver/ui/dist/admin.js` (add user CRUD)

**Step 1: Add users page to admin UI**

- Users table (name, email, org, role)
- Create user modal (name, email, password, org selector, role selector)
- Edit user (change name, role, reset password)
- Delete user (with confirmation)
- Filter by org

**Step 2: Commit**

```bash
git commit -m "feat(license-ui): add user management page

CRUD users: create, list, edit, delete. Filter by org.
Role selector: platform_admin, org_admin, org_user."
```

---

## Phase 4: Deprecation Cleanup

### Task 4.1: Remove API Key Auth

**Files:**
- Delete: `pkg/server/auth.go` (old APIKeyAuth middleware)
- Modify: `pkg/server/server.go` (remove APIKeys from Config, remove middleware)
- Modify: `cmd/server.go` (remove --api-key flag)
- Modify: `pkg/server/server_test.go` (remove API key tests)

**Step 1: Remove all API key references**

**Step 2: Run full test suite**

Run: `go test ./...`
Expected: PASS

**Step 3: Commit**

```bash
git commit -m "chore: remove deprecated API key auth

License tokens and JWT replace API key authentication.
Remove --api-key flag, APIKeyAuth middleware, and related tests."
```

---

### Task 4.2: Update Documentation

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `docs/SYSTEM_ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Step 1: Update deployment guide**

- Add license server as required dependency
- Document user creation flow
- Document JWT auth for API access
- Remove API key references
- Add compose.yaml examples for full stack

**Step 2: Update architecture doc**

- Add user model diagram
- Update auth flow diagrams
- Document permissions matrix

**Step 3: Commit**

```bash
git commit -m "docs: update for multi-tenant architecture

Add user management, JWT auth, license server dependency.
Remove API key references. Update permissions matrix."
```

---

### Task 4.3: Update E2E Tests

**Files:**
- Modify: `test/e2e/cmd/testserver/main.go` (add mock license server)
- Modify: `test/e2e/global-setup.js` (login flow)
- Modify: `test/e2e/*.spec.js` (use JWT auth)
- Modify: `test/e2e/license-admin.spec.js` (add user management tests)

**Step 1: Update test server to include auth**

The test server needs to either:
- Embed a minimal license server, or
- Mock the license server endpoints

**Step 2: Update all E2E tests to login first**

```js
test.beforeEach(async ({ page }) => {
  // Login via API
  const resp = await page.evaluate(async () => {
    const r = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@test.com', password: 'test123' }),
    });
    return r.json();
  });
  await page.evaluate((token) => {
    sessionStorage.setItem('triton_jwt', token);
  }, resp.token);
});
```

**Step 3: Add user management E2E tests**

- Create user via modal
- List users
- Edit user role
- Delete user

**Step 4: Commit**

```bash
git commit -m "test(e2e): update for JWT auth and user management

Login flow in beforeEach. All API calls use JWT.
New user management E2E tests for license admin UI."
```

---

### Task 4.4: Update Integration Tests

**Files:**
- Modify: `test/integration/server_workflow_test.go`
- Modify: `test/integration/license_server_test.go`
- Create: `test/integration/multi_tenant_test.go`

**Step 1: Add multi-tenant integration tests**

- Create 2 orgs with separate licenses
- Submit scans as different orgs
- Verify scan isolation (org A can't see org B's scans)
- Verify platform admin can see all scans
- Verify role enforcement (org_user can't delete)

**Step 2: Update existing integration tests**

Replace API key auth with JWT auth in existing server workflow tests.

**Step 3: Commit**

```bash
git commit -m "test(integration): add multi-tenant isolation tests

Verify: cross-org isolation, platform admin access, role enforcement,
scan submission with license token validation."
```

---

## Commit Summary

| Phase | Tasks | Commits |
|-------|-------|---------|
| 1: License Server Users & Auth | 1.1-1.6 | 6 commits |
| 2: Triton Server Auth | 2.1-2.6 | 6 commits |
| 3: Web UI | 3.1-3.2 | 2 commits |
| 4: Cleanup | 4.1-4.4 | 4 commits |
| **Total** | **18 tasks** | **18 commits** |
