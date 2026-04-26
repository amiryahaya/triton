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
	//
	// NOTE: zone_id + host_id started life as NOT NULL REFERENCES without an
	// ON DELETE clause (which defaults to RESTRICT). Migration v6 loosens
	// this to ON DELETE SET NULL + DROP NOT NULL so deleting a zone/host
	// preserves historical scan jobs for audit. See v6 for details.
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
		-- intentionally no FK to manage_scan_jobs: dead-letter rows must
		-- outlive the source job, preserving the undeliverable payload
		-- for operator triage even after the originating job row has been
		-- pruned.
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

	// Version 6: Loosen scan-job FK cascade to SET NULL so deleting a
	// zone/host preserves historical scan jobs for audit. Triton Manage is
	// a compliance tool; retaining scan history across zone/host churn is a
	// feature, not a bug. Handlers querying `WHERE zone_id = $1` simply
	// won't see orphaned rows; admin UIs can surface them via `zone_id IS
	// NULL` as "orphaned scan jobs".
	//
	// Constraint names follow PostgreSQL's default pattern
	// `<table>_<column>_fkey`, which is what the v3 CREATE TABLE statement
	// produces when REFERENCES is used without an explicit CONSTRAINT
	// clause.
	`ALTER TABLE manage_scan_jobs ALTER COLUMN zone_id DROP NOT NULL;
	ALTER TABLE manage_scan_jobs ALTER COLUMN host_id DROP NOT NULL;
	ALTER TABLE manage_scan_jobs DROP CONSTRAINT manage_scan_jobs_zone_id_fkey;
	ALTER TABLE manage_scan_jobs ADD CONSTRAINT manage_scan_jobs_zone_id_fkey
		FOREIGN KEY (zone_id) REFERENCES manage_zones(id) ON DELETE SET NULL;
	ALTER TABLE manage_scan_jobs DROP CONSTRAINT manage_scan_jobs_host_id_fkey;
	ALTER TABLE manage_scan_jobs ADD CONSTRAINT manage_scan_jobs_host_id_fkey
		FOREIGN KEY (host_id) REFERENCES manage_hosts(id) ON DELETE SET NULL;`,

	// Version 7: Allow agent-submitted scan results on the queue by
	// making scan_job_id nullable. Agent scans arrive via the :8443
	// gateway without an originating scan_job row (the agent owns the
	// scan lifecycle; Manage is a pass-through).
	//
	// Queue table: relax NOT NULL + promote the FK cascade to SET NULL
	// so deleting a scan_job doesn't cascade-delete queued rows on the
	// way to Report.
	//
	// Dead-letter table: only relax NOT NULL. v4 intentionally omitted
	// the FK to manage_scan_jobs so dead-letter rows outlive the source
	// job, preserving operator-triage evidence after scan_job pruning
	// (see v4 comment). v7 preserves that intent — DO NOT add an FK
	// here. DeadLetter's INSERT...SELECT from queue now carries a
	// potentially-nullable scan_job_id, which the NOT NULL drop makes
	// legal. TestMigrate_V7_QueueFKIsSetNull_DeadLetterHasNoFK pins
	// both halves so a future "tidy-up" FK addition trips the test.
	`ALTER TABLE manage_scan_results_queue ALTER COLUMN scan_job_id DROP NOT NULL;
	ALTER TABLE manage_scan_results_queue DROP CONSTRAINT manage_scan_results_queue_scan_job_id_fkey;
	ALTER TABLE manage_scan_results_queue ADD CONSTRAINT manage_scan_results_queue_scan_job_id_fkey
		FOREIGN KEY (scan_job_id) REFERENCES manage_scan_jobs(id) ON DELETE SET NULL;
	ALTER TABLE manage_scan_results_dead_letter ALTER COLUMN scan_job_id DROP NOT NULL;`,

	// Version 8: pending_deactivation flag on the setup singleton row.
	// Set when the operator has requested licence deactivation but the
	// deactivation handshake with the licence server has not yet completed
	// (e.g. server unreachable). Cleared on successful deactivation.
	`ALTER TABLE manage_setup
		ADD COLUMN IF NOT EXISTS pending_deactivation BOOLEAN NOT NULL DEFAULT FALSE;`,

	// Version 9: Replace single-zone host grouping with a flexible multi-tag
	// system. Creates manage_tags + manage_host_tags, migrates existing zone
	// data, then drops the now-redundant zone_id columns and manage_zones table.
	// Also cleans up zone_id from manage_agents (added in v5) which would
	// otherwise block the DROP TABLE manage_zones.
	`CREATE TABLE IF NOT EXISTS manage_tags (
		id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		name       TEXT        NOT NULL UNIQUE,
		color      TEXT        NOT NULL DEFAULT '#6366F1',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS manage_host_tags (
		host_id UUID NOT NULL REFERENCES manage_hosts(id) ON DELETE CASCADE,
		tag_id  UUID NOT NULL REFERENCES manage_tags(id)  ON DELETE CASCADE,
		PRIMARY KEY (host_id, tag_id)
	);

	INSERT INTO manage_tags (name, color)
	SELECT name, '#6366F1' FROM manage_zones
	ON CONFLICT (name) DO NOTHING;

	INSERT INTO manage_host_tags (host_id, tag_id)
	SELECT h.id, t.id
	FROM manage_hosts h
	JOIN manage_zones z ON z.id = h.zone_id
	JOIN manage_tags  t ON t.name = z.name
	WHERE h.zone_id IS NOT NULL
	ON CONFLICT (host_id, tag_id) DO NOTHING;

	ALTER TABLE manage_scan_jobs DROP CONSTRAINT IF EXISTS manage_scan_jobs_zone_id_fkey;
	ALTER TABLE manage_scan_jobs DROP COLUMN IF EXISTS zone_id;

	ALTER TABLE manage_agents DROP CONSTRAINT IF EXISTS manage_agents_zone_id_fkey;
	ALTER TABLE manage_agents DROP COLUMN IF EXISTS zone_id;

	DROP INDEX IF EXISTS idx_manage_hosts_zone;
	ALTER TABLE manage_hosts DROP COLUMN IF EXISTS zone_id;

	DROP TABLE IF EXISTS manage_zone_memberships;
	DROP TABLE IF EXISTS manage_zones;`,

	// Version 10: Network discovery — singleton job + discovered candidates.
	`CREATE TABLE IF NOT EXISTS manage_discovery_jobs (
		id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id        UUID        NOT NULL,
		cidr             TEXT        NOT NULL,
		ports            INT[]       NOT NULL,
		status           TEXT        NOT NULL DEFAULT 'queued'
		                             CHECK (status IN ('queued','running','completed','failed','cancelled')),
		total_ips        INT         NOT NULL DEFAULT 0,
		scanned_ips      INT         NOT NULL DEFAULT 0,
		cancel_requested BOOLEAN     NOT NULL DEFAULT FALSE,
		started_at       TIMESTAMPTZ,
		finished_at      TIMESTAMPTZ,
		error_message    TEXT        NOT NULL DEFAULT '',
		created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS manage_discovery_candidates (
		id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		job_id           UUID        NOT NULL REFERENCES manage_discovery_jobs(id) ON DELETE CASCADE,
		ip               TEXT        NOT NULL,
		hostname         TEXT,
		open_ports       INT[]       NOT NULL DEFAULT '{}',
		existing_host_id UUID        REFERENCES manage_hosts(id) ON DELETE SET NULL,
		created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_discovery_candidates_job ON manage_discovery_candidates(job_id);`,

	// Version 11: Make ip required and hostname/os optional on manage_hosts.
	// hostname: drop NOT NULL so existing rows keep their value but new rows
	//           can omit it; ip becomes the unique identity key.
	// UNIQUE constraint moves from hostname to ip.
	// os already had DEFAULT '' so it is already optional in practice; no change needed.
	`ALTER TABLE manage_hosts ALTER COLUMN hostname DROP NOT NULL;
	ALTER TABLE manage_hosts ALTER COLUMN hostname SET DEFAULT NULL;

	-- Handle existing rows that may have a null ip before we make it required.
	-- Use a placeholder so the NOT NULL constraint is satisfiable; operators
	-- should clean up placeholder values post-migration.
	UPDATE manage_hosts SET ip = '0.0.0.0'::inet WHERE ip IS NULL;
	ALTER TABLE manage_hosts ALTER COLUMN ip SET NOT NULL;

	-- Swap UNIQUE constraint: hostname → ip.
	ALTER TABLE manage_hosts DROP CONSTRAINT IF EXISTS manage_hosts_hostname_key;
	ALTER TABLE manage_hosts ADD CONSTRAINT manage_hosts_ip_key UNIQUE (ip);`,

	// Version 12: Add os column to manage_discovery_candidates for OS detection results.
	`ALTER TABLE manage_discovery_candidates
 ADD COLUMN IF NOT EXISTS os TEXT NOT NULL DEFAULT '';`,

	// Version 13: Add MAC address and mDNS name to discovery candidates.
	`ALTER TABLE manage_discovery_candidates
 ADD COLUMN IF NOT EXISTS mac_address TEXT NOT NULL DEFAULT '';
ALTER TABLE manage_discovery_candidates
 ADD COLUMN IF NOT EXISTS mdns_name TEXT NOT NULL DEFAULT '';`,

	// Version 14: Port survey job type + deferred scheduling.
	// job_type discriminates filesystem scans (default, backward-compat)
	// from port_survey scans. scheduled_at, when set, defers claiming
	// until that timestamp is reached.
	`ALTER TABLE manage_scan_jobs
	 ADD COLUMN IF NOT EXISTS job_type TEXT NOT NULL DEFAULT 'filesystem'
	 CHECK (job_type IN ('filesystem','port_survey'));
ALTER TABLE manage_scan_jobs
	 ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;`,
}
