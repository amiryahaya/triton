package managestore

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// validSchemaName validates a schema name is safe for SQL use.
var validSchemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// PostgresStore implements Store using PostgreSQL via pgx v5.
type PostgresStore struct {
	pool   *pgxpool.Pool
	schema string // non-empty when using an isolated test schema
}

// NewPostgresStore connects to PostgreSQL and runs any pending schema migrations.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgresql: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgresql: %w", err)
	}
	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

// NewPostgresStoreFromPool wraps an externally-owned pgxpool.Pool as a
// PostgresStore without touching connection or migration lifecycle.
//
// **Pool ownership.** The caller owns the pool's lifecycle. Do NOT call
// Close() on the returned store when the pool is shared with other
// packages — PostgresStore.Close() unconditionally closes the underlying
// pool and would pull it out from under the other consumers. Close the
// pool yourself when the last user is done. This contrasts with
// NewPostgresStore, which is the sole owner of its pool and whose
// Close() method IS the correct teardown path.
//
// The caller MUST have run Migrate(ctx, pool) (or gone through
// NewPostgresStore which does this) before using the returned store, or
// reads/writes will fail against a schema that doesn't exist.
//
// Mirrors pkg/store.NewPostgresStoreFromPool from B2.1. Intended for
// cmd/manageserver/main.go, which runs BOTH managestore.Migrate and
// store.Migrate against a single shared pool at boot.
func NewPostgresStoreFromPool(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// NewPostgresStoreInSchema is for integration tests — isolates tables
// in a named schema so parallel test runs don't collide.
func NewPostgresStoreInSchema(ctx context.Context, connStr, schema string) (*PostgresStore, error) {
	if !validSchemaName.MatchString(schema) {
		return nil, fmt.Errorf("invalid schema name: %q", schema)
	}
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	// Schema name validated above against strict alphanumeric pattern.
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("drop stale schema: %w", err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	pool.Close()

	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing conn string: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting with schema: %w", err)
	}
	s := &PostgresStore{pool: pool, schema: schema}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrating schema %s: %w", schema, err)
	}
	return s, nil
}

// DropSchema drops the isolated test schema. Only meaningful when
// created via NewPostgresStoreInSchema.
func (s *PostgresStore) DropSchema(ctx context.Context) error {
	if s.schema == "" {
		return nil
	}
	if !validSchemaName.MatchString(s.schema) {
		return fmt.Errorf("invalid schema: %q", s.schema)
	}
	// Schema name validated above against strict alphanumeric pattern.
	_, err := s.pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+s.schema+" CASCADE")
	return err
}

// Close releases pgx pool resources.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// Pool returns the underlying pgx connection pool. Exposed so other Manage
// packages (zones, hosts, scanjobs) can share the single pool their store
// already opened, instead of dialling a second time. The caller must NOT
// Close() the returned pool — that remains the store's responsibility when
// constructed via NewPostgresStore or NewPostgresStoreInSchema. When the
// store was built via NewPostgresStoreFromPool, the original caller still
// owns the pool's lifecycle.
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// Migrate applies any unapplied Manage Server schema migrations against the
// given pool. Safe to call from any caller that owns a pgxpool.Pool against
// the target database. Uses an advisory lock (id 7355693422) to serialise
// concurrent migrators on the same database; the lock is released before
// return. Idempotent — running twice against the same DB is a no-op for
// already-applied migrations.
//
// Uses manage_schema_version (not schema_version) for version tracking, so
// the Manage schema can cohabit a database with the Report Server's store
// (pkg/store), which owns schema_version. This lets cmd/manageserver/main.go
// call BOTH managestore.Migrate and store.Migrate on the same pool at boot.
//
// The advisory-lock id (7355693422) is deliberately one greater than
// pkg/store.Migrate's id (7355693421) so the two migrations cannot deadlock
// when run in sequence against the same pool.
//
// Mirrors pkg/store.Migrate from B2.1.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS manage_schema_version (
		version    INTEGER     NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating manage_schema_version: %w", err)
	}

	// Acquire a dedicated connection for advisory lock to prevent concurrent migrations.
	// Advisory locks are session-level — we must hold the same connection for lock + migrations.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migration: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(7355693422)"); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(7355693422)")
	}()

	var current int
	err = conn.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM manage_schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}
	for i := current; i < len(migrations); i++ {
		version := i + 1
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for migration %d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, migrations[i]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO manage_schema_version (version, applied_at) VALUES ($1, NOW())", version,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording migration %d: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}

// migrate applies any unapplied schema migrations using the store's pool.
// Thin wrapper over Migrate so the exported function is the single source
// of truth.
func (s *PostgresStore) migrate(ctx context.Context) error {
	return Migrate(ctx, s.pool)
}

// --- Users -----------------------------------------------------------------

func (s *PostgresStore) CreateUser(ctx context.Context, u *ManageUser) error {
	if u.Role != "admin" && u.Role != "network_engineer" {
		return fmt.Errorf("invalid role: %q", u.Role)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO manage_users (email, name, role, password, must_change_pw)
		VALUES ($1, $2, $3, $4, $5)`,
		u.Email, u.Name, u.Role, u.PasswordHash, u.MustChangePW,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: fmt.Sprintf("email %q already exists", u.Email)}
		}
		return fmt.Errorf("create user: %w", err)
	}
	// Populate generated ID + timestamps back to the caller.
	return s.pool.QueryRow(ctx,
		`SELECT id, created_at, updated_at FROM manage_users WHERE email = $1`, u.Email,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*ManageUser, error) {
	var u ManageUser
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, name, role, password, must_change_pw, created_at, updated_at
		FROM manage_users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.PasswordHash, &u.MustChangePW, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "user", ID: email}
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*ManageUser, error) {
	var u ManageUser
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, name, role, password, must_change_pw, created_at, updated_at
		FROM manage_users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.PasswordHash, &u.MustChangePW, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "user", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]ManageUser, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, name, role, password, must_change_pw, created_at, updated_at
		FROM manage_users ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	out := make([]ManageUser, 0)
	for rows.Next() {
		var u ManageUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.PasswordHash, &u.MustChangePW, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id, newHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_users SET password = $2, must_change_pw = FALSE, updated_at = NOW() WHERE id = $1`,
		id, newHash,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "user", ID: id}
	}
	return nil
}

func (s *PostgresStore) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_users`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func (s *PostgresStore) CountAdmins(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_users WHERE role = 'admin'`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return n, nil
}

// DeleteUser removes a user row. Sessions are cleaned up automatically
// by the ON DELETE CASCADE on manage_sessions.user_id.
//
// Atomicity: the DELETE is guarded by a subquery so an admin row is
// only removed when doing so leaves at least one other admin. This
// closes a TOCTOU race the handler's CountAdmins → DeleteUser sequence
// would otherwise have against two concurrent admin deletions.
// Returns ErrLastAdmin when the guard blocks the delete; callers can
// use errors.Is to distinguish.
func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM manage_users
		WHERE id = $1
		  AND NOT (
		      role = 'admin'
		      AND (SELECT COUNT(*) FROM manage_users WHERE role = 'admin') <= 1
		  )`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the row never existed or the last-admin guard fired.
		// Distinguish via a follow-up lookup — cheap, and only runs in
		// the failure path.
		var role string
		err := s.pool.QueryRow(ctx,
			`SELECT role FROM manage_users WHERE id = $1`, id,
		).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			// Row didn't exist — noop semantics preserved (handler
			// owns 404 via GetUserByID upstream).
			return nil
		}
		if err != nil {
			return fmt.Errorf("delete user guard lookup: %w", err)
		}
		if role == "admin" {
			return ErrLastAdmin
		}
		// Shouldn't happen — row exists but wasn't an admin, so the
		// guard wouldn't have fired. Treat as transient.
		return fmt.Errorf("delete user: row present but guard blocked")
	}
	return nil
}

// --- Sessions --------------------------------------------------------------

func (s *PostgresStore) CreateSession(ctx context.Context, sess *ManageSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO manage_sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`,
		sess.UserID, sess.TokenHash, sess.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return s.pool.QueryRow(ctx,
		`SELECT id, created_at FROM manage_sessions WHERE token_hash = $1`, sess.TokenHash,
	).Scan(&sess.ID, &sess.CreatedAt)
}

func (s *PostgresStore) GetSessionByTokenHash(ctx context.Context, hash string) (*ManageSession, error) {
	var sess ManageSession
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM manage_sessions WHERE token_hash = $1`, hash,
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "session", ID: hash}
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return &sess, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM manage_sessions WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- Setup -----------------------------------------------------------------

func (s *PostgresStore) GetSetup(ctx context.Context) (*SetupState, error) {
	var state SetupState
	var instanceID *string
	err := s.pool.QueryRow(ctx, `
		SELECT admin_created, license_activated, license_server_url, license_key, signed_token, instance_id, pending_deactivation, updated_at
		FROM manage_setup WHERE id = 1`,
	).Scan(&state.AdminCreated, &state.LicenseActivated, &state.LicenseServerURL,
		&state.LicenseKey, &state.SignedToken, &instanceID, &state.PendingDeactivation, &state.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Singleton row guaranteed by migration. Lazily insert and retry once.
		if _, ierr := s.pool.Exec(ctx,
			`INSERT INTO manage_setup (id) VALUES (1) ON CONFLICT DO NOTHING`,
		); ierr != nil {
			return nil, fmt.Errorf("lazy-insert setup row: %w", ierr)
		}
		return s.GetSetup(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("get setup: %w", err)
	}
	if instanceID != nil {
		state.InstanceID = *instanceID
	}
	return &state, nil
}

func (s *PostgresStore) MarkAdminCreated(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_setup SET admin_created = TRUE, updated_at = NOW() WHERE id = 1`,
	)
	return err
}

func (s *PostgresStore) SaveLicenseActivation(ctx context.Context, serverURL, key, signedToken, instanceID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE manage_setup
		SET license_activated = TRUE,
			license_server_url = $1,
			license_key = $2,
			signed_token = $3,
			instance_id = $4,
			updated_at = NOW()
		WHERE id = 1`,
		serverURL, key, signedToken, instanceID,
	)
	return err
}

func (s *PostgresStore) UpdateLicenseToken(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE manage_setup SET signed_token = $1, updated_at = NOW() WHERE id = 1`,
		token,
	)
	return err
}

func (s *PostgresStore) UpdateLicenseKey(ctx context.Context, key, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE manage_setup SET license_key = $1, signed_token = $2, updated_at = NOW()
		WHERE id = 1`,
		key, token,
	)
	return err
}

func (s *PostgresStore) SetPendingDeactivation(ctx context.Context, pending bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE manage_setup SET pending_deactivation = $1, updated_at = NOW() WHERE id = 1`,
		pending,
	)
	return err
}

func (s *PostgresStore) ClearLicenseActivation(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE manage_setup
		SET license_activated    = FALSE,
		    license_server_url   = '',
		    license_key          = '',
		    signed_token         = '',
		    instance_id          = NULL,
		    pending_deactivation = FALSE,
		    updated_at           = NOW()
		WHERE id = 1`,
	)
	return err
}

// --- Test helpers ----------------------------------------------------------

// ExecForTest exposes the pool's Exec for schema-inspection tests.
func (s *PostgresStore) ExecForTest(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, sql, args...)
}

// QueryRowForTest exposes the pool's QueryRow for schema-inspection tests.
func (s *PostgresStore) QueryRowForTest(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.pool.QueryRow(ctx, sql, args...)
}
