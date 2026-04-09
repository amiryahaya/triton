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
}
