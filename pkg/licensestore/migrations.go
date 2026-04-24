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

	// Version 3: Migrate ID columns from TEXT to native UUID (UUIDv7)
	// Drop FK constraints first, alter all columns, then re-add FKs.
	// Use COALESCE to handle empty strings in org_id (convert to NULL before casting to UUID).
	`TRUNCATE TABLE organizations CASCADE;

	ALTER TABLE activations DROP CONSTRAINT IF EXISTS activations_license_id_fkey;
	ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_org_id_fkey;

	ALTER TABLE organizations ALTER COLUMN id TYPE UUID USING id::uuid;

	ALTER TABLE licenses ALTER COLUMN id TYPE UUID USING id::uuid;
	ALTER TABLE licenses ALTER COLUMN org_id TYPE UUID USING NULLIF(org_id, '')::uuid;

	ALTER TABLE activations ALTER COLUMN id TYPE UUID USING id::uuid;
	ALTER TABLE activations ALTER COLUMN license_id TYPE UUID USING license_id::uuid;

	ALTER TABLE audit_log ALTER COLUMN license_id TYPE UUID USING license_id::uuid;
	ALTER TABLE audit_log ALTER COLUMN org_id TYPE UUID USING NULLIF(org_id, '')::uuid;

	ALTER TABLE licenses ADD CONSTRAINT licenses_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
	ALTER TABLE activations ADD CONSTRAINT activations_license_id_fkey FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE RESTRICT;`,

	// Version 4: Users and sessions for multi-tenant auth.
	`CREATE TABLE IF NOT EXISTS users (
		id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
		email      TEXT NOT NULL UNIQUE,
		name       TEXT NOT NULL,
		role       TEXT NOT NULL CHECK (role IN ('platform_admin', 'org_admin', 'org_user')),
		password   TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

	CREATE TABLE IF NOT EXISTS sessions (
		id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,

	// Version 5: License Server v2 — feature flags + per-metric limits + usage tracking.
	// CHECK constraints are named explicitly so future inspection/migration can
	// reference them by stable identifier rather than a PG-generated name.
	`ALTER TABLE licenses
		ADD COLUMN IF NOT EXISTS features          JSONB    NOT NULL DEFAULT '{}',
		ADD COLUMN IF NOT EXISTS limits            JSONB    NOT NULL DEFAULT '[]',
		ADD COLUMN IF NOT EXISTS soft_buffer_pct   SMALLINT NOT NULL DEFAULT 10,
		ADD COLUMN IF NOT EXISTS product_scope     TEXT     NOT NULL DEFAULT 'legacy';

	DO $$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'licenses_soft_buffer_pct_check') THEN
			ALTER TABLE licenses ADD CONSTRAINT licenses_soft_buffer_pct_check
				CHECK (soft_buffer_pct BETWEEN 0 AND 25);
		END IF;
		IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'licenses_product_scope_check') THEN
			ALTER TABLE licenses ADD CONSTRAINT licenses_product_scope_check
				CHECK (product_scope IN ('legacy','report','manage','bundle'));
		END IF;
	END $$;

	CREATE TABLE IF NOT EXISTS license_usage (
		license_id   UUID        NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
		instance_id  UUID        NOT NULL,
		metric       TEXT        NOT NULL,
		"window"     TEXT        NOT NULL,
		value        BIGINT      NOT NULL,
		reported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (license_id, instance_id, metric, "window")
	);

	CREATE INDEX IF NOT EXISTS idx_license_usage_reported_at ON license_usage(reported_at);
	CREATE INDEX IF NOT EXISTS idx_license_usage_license_metric ON license_usage(license_id, metric, "window");`,

	// Version 6: portal-pushed schedule columns on licenses
	`ALTER TABLE licenses
		ADD COLUMN IF NOT EXISTS schedule        TEXT,
		ADD COLUMN IF NOT EXISTS schedule_jitter INTEGER;

	DO $$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'licenses_schedule_jitter_check') THEN
			ALTER TABLE licenses ADD CONSTRAINT licenses_schedule_jitter_check
				CHECK (schedule_jitter IS NULL OR schedule_jitter >= 0);
		END IF;
	END$$;`,

	// Version 7: Relax seats check from > 0 to >= 0.
	// seats = 0 now means "unlimited" — enforced at the application layer.
	`DO $$
	BEGIN
		IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'licenses_seats_check') THEN
			ALTER TABLE licenses DROP CONSTRAINT licenses_seats_check;
		END IF;
		ALTER TABLE licenses ADD CONSTRAINT licenses_seats_check CHECK (seats >= 0);
	END$$;`,

	// Version 8: Add suspended column to organizations.
	// suspended=true blocks new activations and validation for all machines
	// on any licence belonging to this org (hard suspend).
	`ALTER TABLE organizations ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT FALSE;`,
}
