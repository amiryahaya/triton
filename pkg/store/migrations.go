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
}
