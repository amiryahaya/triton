package store

// migrations is an ordered list of SQL schema migrations.
// Each entry is applied once, in order. The index+1 is the schema version.
var migrations = []string{
	// Version 1: Initial schema
	`CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		timestamp TIMESTAMPTZ NOT NULL,
		profile TEXT NOT NULL,
		total_findings INTEGER NOT NULL DEFAULT 0,
		safe INTEGER NOT NULL DEFAULT 0,
		transitional INTEGER NOT NULL DEFAULT 0,
		deprecated INTEGER NOT NULL DEFAULT 0,
		unsafe INTEGER NOT NULL DEFAULT 0,
		result_json JSONB NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
	CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);

	CREATE TABLE IF NOT EXISTS file_hashes (
		path TEXT PRIMARY KEY,
		hash TEXT NOT NULL,
		scanned_at TIMESTAMPTZ NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_file_hashes_scanned_at ON file_hashes(scanned_at);`,

	// Version 2: Migrate scan ID from TEXT to native UUID (UUIDv7)
	`TRUNCATE TABLE scans;
	ALTER TABLE scans ALTER COLUMN id TYPE UUID USING id::uuid;`,

	// Version 3: Add org_id for multi-tenant isolation
	`ALTER TABLE scans ADD COLUMN org_id UUID;
	CREATE INDEX IF NOT EXISTS idx_scans_org_id ON scans(org_id);`,

	// Version 4: Report server identity layer (Phase 1.5a).
	//
	// Adds organizations, users, and sessions tables. The organizations
	// table mirrors the license server's authoritative table — provisioning
	// is push-based via Phase 1.5b's POST /api/v1/admin/orgs endpoint.
	//
	// users.role is restricted to ('org_admin', 'org_user'). platform_admin
	// users live in the license server (split-identity model, 2026-04-07
	// amendment). org_id is NOT NULL — every report-server user belongs
	// to exactly one org.
	//
	// must_change_password is set to TRUE on invite (Phase 1.5e) and
	// cleared after the user changes their password on first login.
	`CREATE TABLE IF NOT EXISTS organizations (
		id         UUID PRIMARY KEY,
		name       TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);

	CREATE TABLE IF NOT EXISTS users (
		id                   UUID PRIMARY KEY,
		org_id               UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
		email                TEXT NOT NULL UNIQUE,
		name                 TEXT NOT NULL,
		role                 TEXT NOT NULL CHECK (role IN ('org_admin', 'org_user')),
		password             TEXT NOT NULL,
		must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
		created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

	CREATE TABLE IF NOT EXISTS sessions (
		id         UUID PRIMARY KEY,
		user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,

	// Version 5: Invite expiry (Phase 5.2).
	//
	// Adds invited_at to users, timestamped on org creation or explicit
	// resend-invite. handleLogin rejects invited users whose
	// must_change_password=true AND invited_at + the configured window
	// has elapsed; the response is collapsed to 401 (not 403) so an
	// attacker holding a stolen temp password cannot distinguish
	// "expired invite" from "wrong password" — see the Phase 5.1/5.2
	// review finding D4. Legitimate users who have already changed
	// their password are unaffected: mcp=false short-circuits the
	// expiry check entirely.
	//
	// Backfill: the ALTER stamps every existing row with invited_at =
	// now() (the ALTER wall-clock time), which is always AFTER that
	// row's created_at. We then overwrite those stamps with the row's
	// own created_at so the anchor reflects when the user was actually
	// created, not when the migration ran. The UPDATE is unconditional
	// (no WHERE predicate on the timestamp comparison) so that future
	// re-applications of the migration remain idempotent and a human
	// reading the SQL sees the intent plainly.
	`ALTER TABLE users ADD COLUMN invited_at TIMESTAMPTZ NOT NULL DEFAULT now();
	UPDATE users SET invited_at = created_at;`,

	// Version 6: Report server audit log (Phase 5 Sprint 3 B2).
	//
	// Mirrors the license server's audit_log schema. Every sensitive
	// action on the report server — user CRUD, scan deletion,
	// resend-invite, admin provisioning receiver calls — writes a
	// row here so operators and compliance auditors can reconstruct
	// who did what and when. Reads are exposed via a future admin
	// endpoint; writes happen inline from handlers.
	//
	// Columns:
	//   timestamp   — when the event occurred (server clock)
	//   event_type  — short tag e.g. "user.create", "scan.delete"
	//   org_id      — tenant the event belongs to, nullable for
	//                 service-key admin calls that cross tenants
	//   actor_id    — user ID of the human who triggered the event,
	//                 empty for system / service-key actions
	//   target_id   — the primary object the event acted on (user
	//                 ID, scan ID, etc.), free-form string
	//   details     — JSONB bag for event-specific context
	//   ip_address  — remote IP from chi RealIP middleware
	`CREATE TABLE IF NOT EXISTS audit_events (
		id         BIGSERIAL PRIMARY KEY,
		timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		event_type TEXT NOT NULL,
		org_id     UUID,
		actor_id   TEXT NOT NULL DEFAULT '',
		target_id  TEXT NOT NULL DEFAULT '',
		details    JSONB NOT NULL DEFAULT '{}',
		ip_address TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_audit_events_org_id ON audit_events(org_id);
	CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id);`,

	// Version 7: Denormalized findings read-model (Analytics Phase 1).
	//
	// Extracts per-finding crypto data from scans.result_json into a
	// queryable table. scans remains the source of truth; findings is a
	// rebuildable read-model populated on scan submit (inline via
	// SaveScanWithFindings) and for existing rows via the first-boot
	// backfill (pkg/store/backfill.go).
	//
	// Only findings with a non-nil CryptoAsset are extracted — non-crypto
	// findings stay in the blob and are irrelevant to the analytics views.
	//
	// At-rest encryption scope (/pensive:full-review item B3, 2026-04-09):
	// When REPORT_SERVER_DATA_ENCRYPTION_KEY is set, the AES-256-GCM
	// envelope covers ONLY scans.result_json — NOT this findings table.
	// Columns like subject, issuer, file_path, and hostname are stored
	// as plaintext so they can be used in SQL predicates for the three
	// analytics queries. Operators who require end-to-end encryption of
	// certificate subjects or file paths must either (a) disable the
	// findings table by reverting migration v7, (b) wrap the projection
	// with pgcrypto / storage-layer TDE, or (c) accept the reduced scope.
	// See docs/DEPLOYMENT_GUIDE.md §at-rest-encryption for the full
	// operator-facing explanation.
	`CREATE TABLE IF NOT EXISTS findings (
		id                  UUID PRIMARY KEY,
		scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		org_id              UUID NOT NULL,
		hostname            TEXT NOT NULL,
		finding_index       INTEGER NOT NULL,
		module              TEXT NOT NULL,
		file_path           TEXT NOT NULL DEFAULT '',
		algorithm           TEXT NOT NULL,
		key_size            INTEGER NOT NULL DEFAULT 0,
		pqc_status          TEXT NOT NULL DEFAULT '',
		migration_priority  INTEGER NOT NULL DEFAULT 0,
		not_after           TIMESTAMPTZ,
		subject             TEXT NOT NULL DEFAULT '',
		issuer              TEXT NOT NULL DEFAULT '',
		reachability        TEXT NOT NULL DEFAULT '',
		created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
		UNIQUE (scan_id, finding_index)
	);

	CREATE INDEX IF NOT EXISTS idx_findings_org_algorithm
		ON findings (org_id, algorithm, key_size);

	CREATE INDEX IF NOT EXISTS idx_findings_org_not_after
		ON findings (org_id, not_after)
		WHERE not_after IS NOT NULL;

	CREATE INDEX IF NOT EXISTS idx_findings_org_priority
		ON findings (org_id, migration_priority DESC);

	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);

	ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_extracted_at TIMESTAMPTZ;`,

	// Version 8: Partial index on scans.findings_extracted_at for the
	// backfill goroutine's batch query. Without this, every batch after
	// the first re-scans the processed portion of the scans table to
	// find the next 100 unprocessed rows, giving O(processed_rows)
	// per-batch cost on large catalogs with intermittent backfill runs.
	//
	// The partial index covers ONLY rows awaiting backfill; once a row
	// is marked via UPDATE ... SET findings_extracted_at = NOW(), it
	// drops out of the index automatically. Index size stays bounded
	// to the unprocessed-scan count even as the scans table grows.
	//
	// Planner behavior: `SELECT id FROM scans WHERE
	// findings_extracted_at IS NULL ORDER BY id LIMIT $1` walks the
	// partial index in id order and stops after $1 rows — O(batch_size)
	// regardless of total scan count. /pensive:full-review Arch-4.
	`CREATE INDEX IF NOT EXISTS idx_scans_unbackfilled
		ON scans (id)
		WHERE findings_extracted_at IS NULL;`,

	// Version 9: Executive summary display preferences per org (Analytics Phase 2).
	//
	// Two columns on the existing organizations table carry each
	// org's compliance target percentage and deadline year. Defaults
	// are chosen for Triton's primary audience (Malaysian government /
	// NACSA-2030); orgs with different needs override per-org via
	// direct SQL:
	//
	//   UPDATE organizations
	//   SET executive_target_percent = 95,
	//       executive_deadline_year  = 2035
	//   WHERE name = 'US Defense Contractor';
	//
	// Phase 2.5 will add an admin form for org_admin to change these
	// without SQL. See docs/plans/2026-04-10-analytics-phase-2-design.md §6.
	`ALTER TABLE organizations
		ADD COLUMN IF NOT EXISTS executive_target_percent NUMERIC(5,2) NOT NULL DEFAULT 80.0;
	ALTER TABLE organizations
		ADD COLUMN IF NOT EXISTS executive_deadline_year INTEGER NOT NULL DEFAULT 2030;`,

	// Version 10: key_size can exceed int4 max (e.g. 2^31 for large DH parameters).
	`ALTER TABLE findings ALTER COLUMN key_size TYPE BIGINT;`,

	// Version 11: Container image annotation on the findings read-model.
	// Populated by the OCIImageModule delegation wrapper when findings
	// originate from a pulled OCI image scan. Host filesystem scans
	// leave both columns NULL. No backfill required.
	`ALTER TABLE findings
		ADD COLUMN IF NOT EXISTS image_ref TEXT;
	ALTER TABLE findings
		ADD COLUMN IF NOT EXISTS image_digest TEXT;`,

	// Version 12: Analytics Stage 2+3 summary tables (Phase 4A ETL pipeline).
	// host_summary: per-(org, hostname) aggregates, refreshed by pipeline T2.
	// org_snapshot: per-org rollup, refreshed by pipeline T3.
	// Both are derived read-models — rebuildable from the findings table.
	`CREATE TABLE IF NOT EXISTS host_summary (
		org_id                UUID NOT NULL,
		hostname              TEXT NOT NULL,
		scan_id               UUID NOT NULL,
		scanned_at            TIMESTAMPTZ NOT NULL,
		total_findings        INT NOT NULL DEFAULT 0,
		safe_findings         INT NOT NULL DEFAULT 0,
		transitional_findings INT NOT NULL DEFAULT 0,
		deprecated_findings   INT NOT NULL DEFAULT 0,
		unsafe_findings       INT NOT NULL DEFAULT 0,
		readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
		certs_expiring_30d    INT NOT NULL DEFAULT 0,
		certs_expiring_90d    INT NOT NULL DEFAULT 0,
		certs_expired         INT NOT NULL DEFAULT 0,
		max_priority          INT NOT NULL DEFAULT 0,
		trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
		trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
		sparkline             JSONB NOT NULL DEFAULT '[]',
		refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (org_id, hostname)
	);

	CREATE INDEX IF NOT EXISTS idx_host_summary_readiness
		ON host_summary(org_id, readiness_pct ASC);
	CREATE INDEX IF NOT EXISTS idx_host_summary_unsafe
		ON host_summary(org_id, unsafe_findings DESC);

	CREATE TABLE IF NOT EXISTS org_snapshot (
		org_id                UUID PRIMARY KEY,
		readiness_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
		total_findings        INT NOT NULL DEFAULT 0,
		safe_findings         INT NOT NULL DEFAULT 0,
		machines_total        INT NOT NULL DEFAULT 0,
		machines_red          INT NOT NULL DEFAULT 0,
		machines_yellow       INT NOT NULL DEFAULT 0,
		machines_green        INT NOT NULL DEFAULT 0,
		trend_direction       TEXT NOT NULL DEFAULT 'insufficient',
		trend_delta_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
		monthly_trend         JSONB NOT NULL DEFAULT '[]',
		projection_status     TEXT NOT NULL DEFAULT 'insufficient-history',
		projected_year        INT,
		target_pct            NUMERIC(5,2) NOT NULL DEFAULT 80.0,
		deadline_year         INT NOT NULL DEFAULT 2030,
		policy_verdicts       JSONB NOT NULL DEFAULT '[]',
		top_blockers          JSONB NOT NULL DEFAULT '[]',
		certs_expiring_30d    INT NOT NULL DEFAULT 0,
		certs_expiring_90d    INT NOT NULL DEFAULT 0,
		certs_expired         INT NOT NULL DEFAULT 0,
		refreshed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`,

	// Version 13: Remediation tracking — append-only finding_status table.
	// Analytics Phase 4B.
	`CREATE TABLE IF NOT EXISTS finding_status (
		id          BIGSERIAL PRIMARY KEY,
		finding_key TEXT NOT NULL,
		org_id      UUID NOT NULL,
		status      TEXT NOT NULL CHECK (status IN ('open','in_progress','resolved','accepted')),
		reason      TEXT NOT NULL DEFAULT '',
		changed_by  TEXT NOT NULL,
		changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at  TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_finding_status_key ON finding_status(finding_key, changed_at DESC);
	CREATE INDEX IF NOT EXISTS idx_finding_status_org ON finding_status(org_id);`,

	// Version 14: Add resolved/accepted counts to host_summary and org_snapshot.
	// Analytics Phase 4B.
	`ALTER TABLE host_summary ADD COLUMN IF NOT EXISTS resolved_count INT NOT NULL DEFAULT 0;
	ALTER TABLE host_summary ADD COLUMN IF NOT EXISTS accepted_count INT NOT NULL DEFAULT 0;
	ALTER TABLE org_snapshot ADD COLUMN IF NOT EXISTS resolved_count INT NOT NULL DEFAULT 0;
	ALTER TABLE org_snapshot ADD COLUMN IF NOT EXISTS accepted_count INT NOT NULL DEFAULT 0;`,

	// Version 15: Add org_officer role for onboarding RBAC.
	// Per Onboarding design spec §5: Officer is view-only + can trigger
	// scans on pre-defined groups. Engineer equals existing org_user;
	// Owner equals existing org_admin. The original CHECK constraint
	// from Version 4 is inlined on the column (no named constraint),
	// so we drop the implicit one by name pattern ("users_role_check"
	// is the PG default for a column CHECK) if present, then add the
	// expanded constraint explicitly so future migrations can name-drop it.
	`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
	ALTER TABLE users ADD CONSTRAINT users_role_check
		CHECK (role IN ('org_admin', 'org_user', 'org_officer'));`,

	// Version 16: Inventory schema — groups, hosts, tags.
	// Onboarding Phase 1, design spec §6. Top-level public-schema
	// tables (matches existing organizations/users/sessions convention;
	// we intentionally do NOT introduce a separate identity/inventory
	// schema).
	//
	// inventory_groups: org-scoped named buckets (unique name per org).
	// inventory_hosts : per-host row, group_id REQUIRED (RESTRICT on
	//   group delete so we never orphan a host). mode is agentless by
	//   default; engine_id + last_scan_id + last_seen are populated
	//   later by the scan pipeline. (hostname, address) unique per
	//   org on hostname only — address is informational/optional.
	// inventory_tags  : free-form key/value labels, one row per (host, key).
	`CREATE TABLE IF NOT EXISTS inventory_groups (
		id          UUID PRIMARY KEY,
		org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
		name        TEXT NOT NULL,
		description TEXT,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_by  UUID REFERENCES users(id),
		UNIQUE (org_id, name)
	);

	CREATE INDEX IF NOT EXISTS idx_inventory_groups_org ON inventory_groups(org_id);

	CREATE TABLE IF NOT EXISTS inventory_hosts (
		id           UUID PRIMARY KEY,
		org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
		group_id     UUID NOT NULL REFERENCES inventory_groups(id) ON DELETE RESTRICT,
		hostname     TEXT,
		address      INET,
		os           TEXT CHECK (os IS NULL OR os IN ('linux', 'windows', 'macos', 'cisco-iosxe', 'juniper-junos', 'unknown')),
		mode         TEXT NOT NULL DEFAULT 'agentless' CHECK (mode IN ('agentless', 'agent')),
		engine_id    UUID,
		last_scan_id UUID,
		last_seen    TIMESTAMPTZ,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (org_id, hostname)
	);

	CREATE INDEX IF NOT EXISTS idx_inventory_hosts_group ON inventory_hosts(group_id);
	CREATE INDEX IF NOT EXISTS idx_inventory_hosts_org   ON inventory_hosts(org_id);

	CREATE TABLE IF NOT EXISTS inventory_tags (
		host_id UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
		key     TEXT NOT NULL,
		value   TEXT NOT NULL,
		PRIMARY KEY (host_id, key)
	);

	CREATE INDEX IF NOT EXISTS idx_inventory_tags_kv ON inventory_tags(key, value);`,

	// Version 17: Replace the (org_id, hostname) unique constraint with
	// partial unique indexes so both named hosts AND address-only hosts
	// are deduped per org. The original Version 16 constraint
	// `UNIQUE (org_id, hostname)` allowed unlimited NULL hostnames,
	// meaning two address-only hosts with identical IPs in the same
	// org were stored as separate rows. Migrations are append-only,
	// so this fixes it forward rather than editing v16.
	//
	// The implicit constraint name PostgreSQL assigns to an inline
	// `UNIQUE (col1, col2)` on CREATE TABLE is `<table>_<cols>_key` —
	// verified via \d inventory_hosts to be inventory_hosts_org_id_hostname_key.
	`ALTER TABLE inventory_hosts DROP CONSTRAINT IF EXISTS inventory_hosts_org_id_hostname_key;

	CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_hosts_org_hostname
		ON inventory_hosts(org_id, hostname)
		WHERE hostname IS NOT NULL;

	CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_hosts_org_address
		ON inventory_hosts(org_id, address)
		WHERE hostname IS NULL AND address IS NOT NULL;`,

	// Version 18: Engine enrollment schema — per-org CA + engines table.
	// Onboarding Phase 2, Tasks 1-4. Introduces:
	//   engine_cas : one row per org, stores PEM-encoded CA cert plus
	//                ChaCha20-Poly1305 (XChaCha20) encrypted CA private
	//                key (24-byte nonce). Wrapping key is held in-process,
	//                never persisted to disk.
	//   engines    : one row per enrolled engine. cert_fingerprint is the
	//                SHA-256 hash of the engine's leaf certificate in hex;
	//                UNIQUE globally to support the mTLS middleware lookup
	//                by client-cert fingerprint (Task 6) without needing
	//                an org scope at the TLS layer.
	//                status transitions: enrolled -> online (first poll) ->
	//                offline (stale heartbeat) / revoked (admin action).
	//                first_seen_at NULL means the engine has never called
	//                home; single-use claim is enforced at the store layer
	//                via `UPDATE ... WHERE first_seen_at IS NULL`.
	//
	// Also finally installs the FK from inventory_hosts.engine_id →
	// engines.id (column added in v16, FK deferred until the engines
	// table existed). ON DELETE SET NULL so revoking an engine detaches
	// its hosts without cascading destruction of the inventory rows.
	`CREATE TABLE engine_cas (
		org_id           UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
		ca_cert_pem      TEXT NOT NULL,
		ca_key_encrypted BYTEA NOT NULL,
		ca_key_nonce     BYTEA NOT NULL,
		created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE engines (
		id                UUID PRIMARY KEY,
		org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
		label             TEXT NOT NULL,
		public_ip         INET,
		cert_fingerprint  TEXT NOT NULL,
		bundle_issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		first_seen_at     TIMESTAMPTZ,
		last_poll_at      TIMESTAMPTZ,
		status            TEXT NOT NULL DEFAULT 'enrolled'
		                  CHECK (status IN ('enrolled', 'online', 'offline', 'revoked')),
		revoked_at        TIMESTAMPTZ,
		UNIQUE (org_id, label),
		UNIQUE (cert_fingerprint)
	);

	CREATE INDEX idx_engines_org ON engines(org_id);
	CREATE INDEX idx_engines_status ON engines(status);

	ALTER TABLE inventory_hosts
		ADD CONSTRAINT fk_inventory_hosts_engine
		FOREIGN KEY (engine_id) REFERENCES engines(id) ON DELETE SET NULL;`,

	// Version 19: Discovery jobs + candidates (Onboarding Phase 3, Tasks 1-3).
	// Engines poll for queued discovery jobs, scan the requested CIDRs/ports,
	// and stream candidate hosts back for operator review + promotion into
	// inventory_hosts. Status transitions:
	//   queued -> claimed (engine picked up) -> running -> completed/failed
	//   queued -> cancelled (operator aborted before claim)
	// Single-claim under concurrent engine polls is enforced with
	// FOR UPDATE SKIP LOCKED on the idx_discovery_jobs_engine_queue partial
	// index.
	// discovery_candidates.promoted flips TRUE when a human (or batch
	// promote-all) adopts the candidate into inventory_hosts so subsequent
	// reviews skip already-imported rows. UNIQUE (job_id, address) makes
	// engine retries idempotent.
	`
CREATE TABLE discovery_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    cidrs           TEXT[] NOT NULL,
    ports           INTEGER[] NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    candidate_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_discovery_jobs_org        ON discovery_jobs(org_id);
CREATE INDEX idx_discovery_jobs_engine     ON discovery_jobs(engine_id);
CREATE INDEX idx_discovery_jobs_status     ON discovery_jobs(status);
CREATE INDEX idx_discovery_jobs_engine_queue
    ON discovery_jobs(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE discovery_candidates (
    id          UUID PRIMARY KEY,
    job_id      UUID NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    address     INET NOT NULL,
    hostname    TEXT,
    open_ports  INTEGER[] NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    promoted    BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (job_id, address)
);

CREATE INDEX idx_discovery_candidates_job ON discovery_candidates(job_id);
`,

	// Version 20: Credentials schema (Onboarding Phase 4, Tasks 1-3).
	// Adds per-engine encryption_pubkey (X25519) so the browser can seal
	// secrets to the engine's static key, plus four new tables:
	//   credentials_profiles   — operator-defined named credential bundles
	//                            (auth_type + matcher + opaque secret_ref)
	//   credential_deliveries  — per-engine queue of push/delete payloads;
	//                            profile_id is intentionally nullable +
	//                            FK-less so delete rows survive profile
	//                            removal
	//   credential_tests       — operator-triggered connectivity probes
	//   credential_test_results — per-host outcome rows for a test job
	`
ALTER TABLE engines ADD COLUMN encryption_pubkey BYTEA;

CREATE TABLE credentials_profiles (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id     UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    auth_type     TEXT NOT NULL CHECK (auth_type IN ('ssh-password', 'ssh-key', 'winrm-password', 'bootstrap-admin')),
    matcher       JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_ref    UUID NOT NULL UNIQUE,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_tested_at TIMESTAMPTZ,
    UNIQUE (org_id, name)
);

CREATE INDEX idx_credentials_profiles_org    ON credentials_profiles(org_id);
CREATE INDEX idx_credentials_profiles_engine ON credentials_profiles(engine_id);

CREATE TABLE credential_deliveries (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    profile_id      UUID,
    secret_ref      UUID NOT NULL,
    auth_type       TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('push', 'delete')),
    ciphertext      BYTEA,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'acked', 'failed')),
    error           TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    acked_at        TIMESTAMPTZ
);

CREATE INDEX idx_credential_deliveries_engine_queue
    ON credential_deliveries(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE credential_tests (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id      UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    profile_id     UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE CASCADE,
    host_ids       UUID[] NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error          TEXT,
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

CREATE INDEX idx_credential_tests_engine_queue
    ON credential_tests(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE credential_test_results (
    test_id      UUID NOT NULL REFERENCES credential_tests(id) ON DELETE CASCADE,
    host_id      UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    success      BOOLEAN NOT NULL,
    latency_ms   INTEGER,
    error        TEXT,
    probed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (test_id, host_id)
);
`,

	// Version 21: Scan jobs queue (Onboarding Phase 5).
	// Fourth engine job-queue (after discovery / credential-delivery /
	// credential-test). One job targets a single engine and one or more
	// hosts in that engine's reach. host_ids is a UUID[] rather than a
	// join table because (a) we never query individual host membership
	// outside the job's own claim/progress flow and (b) the engine-side
	// worker fans out per-host scans atomically against this single row.
	// credential_profile_id is RESTRICT on delete so an in-flight scan
	// can never lose its credential mid-claim. progress_total/done/failed
	// are advisory counters maintained by the engine via
	// /api/v1/engine/scans/{id}/progress; the source of truth for which
	// host produced which finding lives in scans.scan_job_id below.
	//
	// scans gains engine_id + scan_job_id so the dashboard can attribute
	// a scan back to the job that produced it. Both columns are
	// nullable + ON DELETE SET NULL so legacy CLI scans (no engine, no
	// job) and post-revocation rows survive.
	`
CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    group_id        UUID REFERENCES inventory_groups(id) ON DELETE SET NULL,
    host_ids        UUID[] NOT NULL,
    scan_profile    TEXT NOT NULL DEFAULT 'standard'
                    CHECK (scan_profile IN ('quick', 'standard', 'comprehensive')),
    credential_profile_id UUID REFERENCES credentials_profiles(id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    progress_total  INTEGER NOT NULL DEFAULT 0,
    progress_done   INTEGER NOT NULL DEFAULT 0,
    progress_failed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_scan_jobs_org ON scan_jobs(org_id);
CREATE INDEX idx_scan_jobs_engine_queue
    ON scan_jobs(engine_id, requested_at)
    WHERE status = 'queued';
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);

ALTER TABLE scans ADD COLUMN engine_id    UUID REFERENCES engines(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN scan_job_id  UUID REFERENCES scan_jobs(id) ON DELETE SET NULL;
CREATE INDEX idx_scans_scan_job ON scans(scan_job_id) WHERE scan_job_id IS NOT NULL;
`,

	// Version 22: Onboarding metrics view (Phase 7 Task 9).
	// Derives per-org milestone timestamps from audit_events plus the
	// engines table (engine enrollment has no audit event). The view
	// powers a "time to first scan" card on the management dashboard.
	`
CREATE OR REPLACE VIEW onboarding_metrics AS
WITH milestones AS (
    SELECT
        org_id,
        MIN(CASE WHEN event_type = 'user.create' THEN timestamp END)                        AS t_signup,
        MIN(CASE WHEN event_type LIKE 'inventory.host%' THEN timestamp END)                  AS t_hosts,
        MIN(CASE WHEN event_type = 'credentials.profile.create' THEN timestamp END)          AS t_creds,
        MIN(CASE WHEN event_type = 'scanjobs.job.create' THEN timestamp END)                 AS t_scan,
        MIN(CASE WHEN event_type = 'discovery.job.create' THEN timestamp END)                AS t_discovery
    FROM audit_events
    WHERE org_id IS NOT NULL
    GROUP BY org_id
),
engine_first AS (
    SELECT org_id, MIN(bundle_issued_at) AS t_engine
    FROM engines
    GROUP BY org_id
),
scan_first AS (
    SELECT org_id, MIN(completed_at) AS t_results
    FROM scan_jobs
    WHERE status = 'completed'
    GROUP BY org_id
)
SELECT
    COALESCE(m.org_id, e.org_id) AS org_id,
    m.t_signup,
    e.t_engine,
    m.t_hosts,
    m.t_creds,
    m.t_scan,
    m.t_discovery,
    s.t_results,
    CASE WHEN m.t_signup IS NOT NULL AND s.t_results IS NOT NULL
         THEN EXTRACT(EPOCH FROM (s.t_results - m.t_signup)) / 60.0
    END AS minutes_to_first_scan
FROM milestones m
FULL OUTER JOIN engine_first e ON e.org_id = m.org_id
LEFT JOIN scan_first s ON s.org_id = COALESCE(m.org_id, e.org_id);
`,

	// Version 23: Agent-push jobs + fleet agents (Onboarding Phase 6).
	// agent_push_jobs is the fifth engine job-queue (after discovery,
	// credential-delivery, credential-test, scan-jobs). One job pushes
	// the triton-agent binary + per-host TLS cert to a set of hosts via
	// SSH using a bootstrap-admin credential profile.
	// fleet_agents tracks installed agent instances — one row per host.
	// cert_fingerprint is SHA-256 hex of the agent's leaf cert DER;
	// UNIQUE globally for mTLS lookup. host_id is also UNIQUE (one agent
	// per host). Status transitions:
	//   installing -> healthy (first heartbeat) -> unhealthy (stale) / uninstalled
	`
CREATE TABLE agent_push_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    group_id        UUID REFERENCES inventory_groups(id) ON DELETE SET NULL,
    host_ids        UUID[] NOT NULL,
    credential_profile_id UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    progress_total  INTEGER NOT NULL DEFAULT 0,
    progress_done   INTEGER NOT NULL DEFAULT 0,
    progress_failed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_agent_push_jobs_engine_queue
    ON agent_push_jobs(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE fleet_agents (
    id               UUID PRIMARY KEY,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id          UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    engine_id        UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    cert_fingerprint TEXT NOT NULL UNIQUE,
    installed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat   TIMESTAMPTZ,
    version          TEXT,
    status           TEXT NOT NULL DEFAULT 'installing'
                     CHECK (status IN ('installing', 'healthy', 'unhealthy', 'uninstalled')),
    UNIQUE (host_id)
);

CREATE INDEX idx_fleet_agents_engine ON fleet_agents(engine_id);
CREATE INDEX idx_fleet_agents_status ON fleet_agents(status);
`,
}
