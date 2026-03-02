package licensestore

// migrations is an ordered list of SQL schema migrations for the license server.
// Each entry is applied once, in order. The index+1 is the schema version.
var migrations = []string{
	// Version 1: Initial license server schema
	`CREATE TABLE IF NOT EXISTS organizations (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL UNIQUE,
		contact    TEXT NOT NULL DEFAULT '',
		notes      TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS licenses (
		id         TEXT PRIMARY KEY,
		org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
		tier       TEXT NOT NULL CHECK (tier IN ('free','pro','enterprise')),
		seats      INTEGER NOT NULL CHECK (seats > 0),
		issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		revoked    BOOLEAN NOT NULL DEFAULT FALSE,
		revoked_at TIMESTAMPTZ,
		revoked_by TEXT,
		notes      TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_licenses_org_id ON licenses(org_id);

	CREATE TABLE IF NOT EXISTS activations (
		id             TEXT PRIMARY KEY,
		license_id     TEXT NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
		machine_id     TEXT NOT NULL,
		hostname       TEXT NOT NULL DEFAULT '',
		os             TEXT NOT NULL DEFAULT '',
		arch           TEXT NOT NULL DEFAULT '',
		token          TEXT NOT NULL,
		activated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		deactivated_at TIMESTAMPTZ,
		active         BOOLEAN NOT NULL DEFAULT TRUE,
		UNIQUE (license_id, machine_id)
	);

	CREATE INDEX IF NOT EXISTS idx_activations_license_id ON activations(license_id);
	CREATE INDEX IF NOT EXISTS idx_activations_machine_id ON activations(machine_id);

	CREATE TABLE IF NOT EXISTS audit_log (
		id         BIGSERIAL PRIMARY KEY,
		timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		event_type TEXT NOT NULL,
		license_id TEXT,
		org_id     TEXT,
		machine_id TEXT,
		actor      TEXT NOT NULL DEFAULT '',
		details    JSONB NOT NULL DEFAULT '{}',
		ip_address TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);`,

	// Version 2: Add audit_log indexes for license_id and org_id
	`CREATE INDEX IF NOT EXISTS idx_audit_log_license_id ON audit_log(license_id);
	 CREATE INDEX IF NOT EXISTS idx_audit_log_org_id ON audit_log(org_id);`,
}
