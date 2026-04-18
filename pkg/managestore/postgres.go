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

// migrate applies any unapplied schema migrations.
func (s *PostgresStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS manage_schema_version (
		version    INTEGER     NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating manage_schema_version: %w", err)
	}
	var current int
	err = s.pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM manage_schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}
	for i := current; i < len(migrations); i++ {
		version := i + 1
		tx, err := s.pool.Begin(ctx)
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
		FROM manage_users ORDER BY created_at`)
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
	return n, err
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
		SELECT admin_created, license_activated, license_server_url, license_key, signed_token, instance_id, updated_at
		FROM manage_setup WHERE id = 1`,
	).Scan(&state.AdminCreated, &state.LicenseActivated, &state.LicenseServerURL,
		&state.LicenseKey, &state.SignedToken, &instanceID, &state.UpdatedAt)
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

// --- Test helpers ----------------------------------------------------------

// ExecForTest exposes the pool's Exec for schema-inspection tests.
func (s *PostgresStore) ExecForTest(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, sql, args...)
}

// QueryRowForTest exposes the pool's QueryRow for schema-inspection tests.
func (s *PostgresStore) QueryRowForTest(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.pool.QueryRow(ctx, sql, args...)
}
