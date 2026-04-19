package managestore

// migrations is an ordered list of SQL schema migrations for the Manage Server.
// Each entry is applied once, in order. The index+1 is the schema version.
var migrations = []string{
	// Version 1: Initial schema — manage users, sessions, setup singleton.
	`CREATE TABLE IF NOT EXISTS manage_users (
		id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
		email           TEXT         NOT NULL UNIQUE,
		name            TEXT         NOT NULL,
		role            TEXT         NOT NULL CHECK (role IN ('admin', 'network_engineer')),
		password        TEXT         NOT NULL,
		must_change_pw  BOOLEAN      NOT NULL DEFAULT FALSE,
		created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
		updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manage_users_email ON manage_users(email);

	CREATE TABLE IF NOT EXISTS manage_sessions (
		id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id     UUID         NOT NULL REFERENCES manage_users(id) ON DELETE CASCADE,
		token_hash  TEXT         NOT NULL UNIQUE,
		expires_at  TIMESTAMPTZ  NOT NULL,
		created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manage_sessions_token_hash ON manage_sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_manage_sessions_expires_at ON manage_sessions(expires_at);

	CREATE TABLE IF NOT EXISTS manage_setup (
		id                   SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
		admin_created        BOOLEAN     NOT NULL DEFAULT FALSE,
		license_activated    BOOLEAN     NOT NULL DEFAULT FALSE,
		license_server_url   TEXT        NOT NULL DEFAULT '',
		license_key          TEXT        NOT NULL DEFAULT '',
		signed_token         TEXT        NOT NULL DEFAULT '',
		instance_id          UUID,
		updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	INSERT INTO manage_setup (id) VALUES (1) ON CONFLICT DO NOTHING;`,
}
