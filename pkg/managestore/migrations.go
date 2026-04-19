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

	// Version 2: Zones + Hosts + membership table (Manage B2.2).
	`CREATE TABLE IF NOT EXISTS manage_zones (
		id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		name        TEXT        NOT NULL UNIQUE,
		description TEXT        NOT NULL DEFAULT '',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS manage_hosts (
		id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		hostname    TEXT        NOT NULL,
		ip          INET,
		zone_id     UUID REFERENCES manage_zones(id) ON DELETE SET NULL,
		os          TEXT        NOT NULL DEFAULT '',
		last_seen_at TIMESTAMPTZ,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (hostname)
	);
	CREATE INDEX IF NOT EXISTS idx_manage_hosts_zone ON manage_hosts(zone_id);
	CREATE TABLE IF NOT EXISTS manage_zone_memberships (
		zone_id UUID NOT NULL REFERENCES manage_zones(id) ON DELETE CASCADE,
		host_id UUID NOT NULL REFERENCES manage_hosts(id) ON DELETE CASCADE,
		PRIMARY KEY (zone_id, host_id)
	);`,

	// Version 3: Scan jobs (Manage in-process orchestrator).
	`CREATE TABLE IF NOT EXISTS manage_scan_jobs (
		id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id            UUID        NOT NULL,
		zone_id              UUID        NOT NULL REFERENCES manage_zones(id),
		host_id              UUID        NOT NULL REFERENCES manage_hosts(id),
		profile              TEXT        NOT NULL CHECK (profile IN ('quick','standard','comprehensive')),
		credentials_ref      UUID,
		status               TEXT        NOT NULL DEFAULT 'queued'
			CHECK (status IN ('queued','running','completed','failed','cancelled')),
		cancel_requested     BOOLEAN     NOT NULL DEFAULT FALSE,
		worker_id            TEXT,
		enqueued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		started_at           TIMESTAMPTZ,
		finished_at          TIMESTAMPTZ,
		running_heartbeat_at TIMESTAMPTZ,
		progress_text        TEXT        NOT NULL DEFAULT '',
		error_message        TEXT        NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_manage_scan_jobs_pull ON manage_scan_jobs (status, enqueued_at);
	CREATE INDEX IF NOT EXISTS idx_manage_scan_jobs_stale ON manage_scan_jobs (running_heartbeat_at) WHERE status='running';`,

	// Version 4: Result queue + push creds + license state.
	`CREATE TABLE IF NOT EXISTS manage_scan_results_queue (
		id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		scan_job_id     UUID        NOT NULL REFERENCES manage_scan_jobs(id) ON DELETE CASCADE,
		source_type     TEXT        NOT NULL CHECK (source_type IN ('manage','agent')),
		source_id       UUID        NOT NULL,
		payload_json    JSONB       NOT NULL,
		enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		attempt_count   INT         NOT NULL DEFAULT 0,
		last_error      TEXT        NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_manage_queue_due ON manage_scan_results_queue (next_attempt_at) WHERE attempt_count < 10;

	CREATE TABLE IF NOT EXISTS manage_scan_results_dead_letter (
		id                  UUID        PRIMARY KEY,
		scan_job_id         UUID        NOT NULL,
		source_type         TEXT        NOT NULL,
		source_id           UUID        NOT NULL,
		payload_json        JSONB       NOT NULL,
		enqueued_at         TIMESTAMPTZ NOT NULL,
		attempt_count       INT         NOT NULL,
		last_error          TEXT        NOT NULL,
		dead_lettered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		dead_letter_reason  TEXT        NOT NULL
	);

	CREATE TABLE IF NOT EXISTS manage_push_creds (
		id              SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id=1),
		client_cert_pem TEXT        NOT NULL,
		client_key_pem  TEXT        NOT NULL,
		ca_cert_pem     TEXT        NOT NULL,
		report_url      TEXT        NOT NULL,
		tenant_id       TEXT        NOT NULL DEFAULT '',
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS manage_license_state (
		id                   SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id=1),
		last_pushed_at       TIMESTAMPTZ,
		last_pushed_metrics  JSONB,
		last_push_error      TEXT        NOT NULL DEFAULT '',
		consecutive_failures INT         NOT NULL DEFAULT 0,
		updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	INSERT INTO manage_license_state (id) VALUES (1) ON CONFLICT DO NOTHING;`,

	// Version 5: Manage CA + agent cert revocations.
	`CREATE TABLE IF NOT EXISTS manage_ca (
		id          SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id=1),
		ca_cert_pem TEXT        NOT NULL,
		ca_key_pem  TEXT        NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS manage_agents (
		id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		name           TEXT        NOT NULL,
		zone_id        UUID REFERENCES manage_zones(id) ON DELETE SET NULL,
		cert_serial    TEXT        NOT NULL UNIQUE,
		cert_expires_at TIMESTAMPTZ NOT NULL,
		status         TEXT        NOT NULL DEFAULT 'pending'
			CHECK (status IN ('pending','active','revoked')),
		last_seen_at   TIMESTAMPTZ,
		created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manage_agents_cert_serial ON manage_agents (cert_serial);
	CREATE TABLE IF NOT EXISTS manage_agent_cert_revocations (
		cert_serial   TEXT        PRIMARY KEY,
		agent_id      UUID        NOT NULL REFERENCES manage_agents(id) ON DELETE CASCADE,
		revoked_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		revoke_reason TEXT        NOT NULL DEFAULT ''
	);`,
}
