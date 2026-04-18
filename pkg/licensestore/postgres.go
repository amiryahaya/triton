package licensestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// validSchemaName validates that a schema name is safe for SQL use.
var validSchemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// PostgresStore implements Store using PostgreSQL via pgx v5.
type PostgresStore struct {
	pool   *pgxpool.Pool
	schema string // non-empty when using an isolated test schema

	// staleThreshold is the duration after which an activation with no
	// heartbeat is eligible for automatic reaping during Activate. When
	// zero, no reaping occurs (backward compatible with all existing
	// call sites). Set via SetStaleThreshold before the server starts.
	staleThreshold time.Duration
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

// NewPostgresStoreInSchema connects to PostgreSQL and creates an isolated schema
// for test isolation. Each caller gets its own set of tables so parallel test
// packages do not interfere with each other. Call DropSchema to clean up.
func NewPostgresStoreInSchema(ctx context.Context, connStr, schema string) (*PostgresStore, error) {
	if !validSchemaName.MatchString(schema) {
		return nil, fmt.Errorf("invalid schema name: %q", schema)
	}

	// Connect with default search_path to create the schema.
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgresql: %w", err)
	}
	// Schema name is validated above against a strict alphanumeric pattern.
	// Drop first to ensure clean state (stale schemas from crashed test runs).
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("dropping stale schema %s: %w", schema, err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("creating schema %s: %w", schema, err)
	}
	pool.Close()

	// Reconnect with search_path set to the new schema.
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting with schema %s: %w", schema, err)
	}

	s := &PostgresStore{pool: pool, schema: schema}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations in schema %s: %w", schema, err)
	}
	return s, nil
}

// DropSchema drops the isolated test schema and all its tables.
// Only works when the store was created with NewPostgresStoreInSchema.
func (s *PostgresStore) DropSchema(ctx context.Context) error {
	if s.schema == "" {
		return nil
	}
	if !validSchemaName.MatchString(s.schema) {
		return fmt.Errorf("invalid schema name: %q", s.schema)
	}
	// Schema name is validated above against a strict alphanumeric pattern.
	_, err := s.pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+s.schema+" CASCADE")
	return err
}

// migrate applies any unapplied schema migrations.
func (s *PostgresStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS license_schema_version (
		version INTEGER NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating license_schema_version table: %w", err)
	}

	var current int
	err = s.pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM license_schema_version").Scan(&current)
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
			"INSERT INTO license_schema_version (version, applied_at) VALUES ($1, NOW())", version,
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

// --- Organizations ---

func (s *PostgresStore) CreateOrg(ctx context.Context, org *Organization) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO organizations (id, name, contact, notes, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		org.ID, org.Name, org.Contact, org.Notes, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: fmt.Sprintf("organization name %q already exists", org.Name)}
		}
		return fmt.Errorf("creating organization: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
	var org Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, contact, notes, created_at, updated_at
		 FROM organizations WHERE id = $1`, id,
	).Scan(&org.ID, &org.Name, &org.Contact, &org.Notes, &org.CreatedAt, &org.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "organization", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("getting organization: %w", err)
	}
	return &org, nil
}

func (s *PostgresStore) ListOrgs(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, contact, notes, created_at, updated_at
		 FROM organizations ORDER BY name LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	defer rows.Close()

	orgs := make([]Organization, 0)
	for rows.Next() {
		var org Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.Contact, &org.Notes, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

func (s *PostgresStore) UpdateOrg(ctx context.Context, org *Organization) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE organizations SET name = $2, contact = $3, notes = $4, updated_at = $5
		 WHERE id = $1`,
		org.ID, org.Name, org.Contact, org.Notes, org.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: fmt.Sprintf("organization name %q already exists", org.Name)}
		}
		return fmt.Errorf("updating organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "organization", ID: org.ID}
	}
	return nil
}

func (s *PostgresStore) DeleteOrg(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	if err != nil {
		// FK constraint: licenses.org_id REFERENCES organizations(id) ON DELETE RESTRICT
		// SQLSTATE 23503 (foreign key violation) or 23001 (restrict violation)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23001") {
			return &ErrConflict{Message: "cannot delete organization with existing licenses"}
		}
		return fmt.Errorf("deleting organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "organization", ID: id}
	}
	return nil
}

// --- Licenses ---

func (s *PostgresStore) CreateLicense(ctx context.Context, lic *LicenseRecord) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO licenses (id, org_id, tier, seats, issued_at, expires_at, notes, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		lic.ID, lic.OrgID, lic.Tier, lic.Seats,
		lic.IssuedAt, lic.ExpiresAt, lic.Notes, lic.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("creating license: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetLicense(ctx context.Context, id string) (*LicenseRecord, error) {
	var lic LicenseRecord
	err := s.pool.QueryRow(ctx,
		`SELECT l.id, l.org_id, l.tier, l.seats, l.issued_at, l.expires_at,
		        l.revoked, l.revoked_at, l.revoked_by, l.notes, l.created_at,
		        o.name,
		        (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id AND a.active = TRUE)
		 FROM licenses l
		 JOIN organizations o ON o.id = l.org_id
		 WHERE l.id = $1`, id,
	).Scan(&lic.ID, &lic.OrgID, &lic.Tier, &lic.Seats,
		&lic.IssuedAt, &lic.ExpiresAt,
		&lic.Revoked, &lic.RevokedAt, &lic.RevokedBy, &lic.Notes, &lic.CreatedAt,
		&lic.OrgName, &lic.SeatsUsed,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "license", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("getting license: %w", err)
	}
	lic.IsExpired = time.Now().After(lic.ExpiresAt)
	return &lic, nil
}

func (s *PostgresStore) ListLicenses(ctx context.Context, filter LicenseFilter) ([]LicenseRecord, error) {
	query := `SELECT l.id, l.org_id, l.tier, l.seats, l.issued_at, l.expires_at,
	                 l.revoked, l.revoked_at, l.revoked_by, l.notes, l.created_at,
	                 o.name,
	                 (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id AND a.active = TRUE)
	          FROM licenses l
	          JOIN organizations o ON o.id = l.org_id
	          WHERE 1=1`
	var args []any
	paramIdx := 0

	if filter.OrgID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND l.org_id = $%d", paramIdx)
		args = append(args, filter.OrgID)
	}
	if filter.Tier != "" {
		paramIdx++
		query += fmt.Sprintf(" AND l.tier = $%d", paramIdx)
		args = append(args, filter.Tier)
	}
	switch filter.Status {
	case "revoked":
		query += " AND l.revoked = TRUE"
	case "expired":
		query += " AND l.expires_at < NOW() AND l.revoked = FALSE"
	case "active":
		query += " AND l.revoked = FALSE AND l.expires_at >= NOW()"
	}

	query += " ORDER BY l.created_at DESC LIMIT 1000"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing licenses: %w", err)
	}
	defer rows.Close()

	lics := make([]LicenseRecord, 0)
	for rows.Next() {
		var lic LicenseRecord
		if err := rows.Scan(&lic.ID, &lic.OrgID, &lic.Tier, &lic.Seats,
			&lic.IssuedAt, &lic.ExpiresAt,
			&lic.Revoked, &lic.RevokedAt, &lic.RevokedBy, &lic.Notes, &lic.CreatedAt,
			&lic.OrgName, &lic.SeatsUsed,
		); err != nil {
			return nil, fmt.Errorf("scanning license: %w", err)
		}
		lic.IsExpired = time.Now().After(lic.ExpiresAt)
		lics = append(lics, lic)
	}
	return lics, rows.Err()
}

func (s *PostgresStore) RevokeLicense(ctx context.Context, id, revokedBy string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin revoke tx: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`UPDATE licenses SET revoked = TRUE, revoked_at = NOW(), revoked_by = $2
		 WHERE id = $1 AND revoked = FALSE`, id, revokedBy,
	)
	if err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("revoking license: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish not-found from already-revoked
		var exists bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM licenses WHERE id = $1)`, id).Scan(&exists)
		_ = tx.Rollback(ctx)
		if exists {
			return &ErrConflict{Message: "license already revoked"}
		}
		return &ErrNotFound{Resource: "license", ID: id}
	}

	// Deactivate all active activations
	if _, err := tx.Exec(ctx,
		`UPDATE activations SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1 AND active = TRUE`, id,
	); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("deactivating activations: %w", err)
	}

	return tx.Commit(ctx)
}

// --- Activations ---

func (s *PostgresStore) Activate(ctx context.Context, act *Activation) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin activate tx: %w", err)
	}

	// Check existing activation for this machine
	var existingID string
	var existingActive bool
	err = tx.QueryRow(ctx,
		`SELECT id, active FROM activations
		 WHERE license_id = $1 AND machine_id = $2`,
		act.LicenseID, act.MachineID,
	).Scan(&existingID, &existingActive)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("checking existing activation: %w", err)
	}
	existingFound := err == nil

	// Always verify license status and seat limit within the transaction
	var lic LicenseRecord
	err = tx.QueryRow(ctx,
		`SELECT seats, revoked, expires_at FROM licenses WHERE id = $1`,
		act.LicenseID,
	).Scan(&lic.Seats, &lic.Revoked, &lic.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		return &ErrNotFound{Resource: "license", ID: act.LicenseID}
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("getting license: %w", err)
	}
	if lic.Revoked {
		_ = tx.Rollback(ctx)
		return &ErrLicenseRevoked{LicenseID: act.LicenseID}
	}
	if time.Now().After(lic.ExpiresAt) {
		_ = tx.Rollback(ctx)
		return &ErrLicenseExpired{LicenseID: act.LicenseID}
	}

	if existingFound {
		// Existing row found — re-activate if needed
		if existingActive {
			// Already active — just update last_seen and return existing info
			if _, err := tx.Exec(ctx,
				`UPDATE activations SET last_seen_at = NOW(), hostname = $2, os = $3, arch = $4, token = $5
				 WHERE id = $1`,
				existingID, act.Hostname, act.OS, act.Arch, act.Token,
			); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("updating activation: %w", err)
			}
			act.ID = existingID
			return tx.Commit(ctx)
		}
		// Re-activate — must check seat limit
		var activeCount int
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM activations WHERE license_id = $1 AND active = TRUE`,
			act.LicenseID,
		).Scan(&activeCount); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("counting seats: %w", err)
		}
		if activeCount >= lic.Seats {
			activeCount, err = s.reapAndRecount(ctx, tx, act.LicenseID, activeCount)
			if err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("reap during re-activate: %w", err)
			}
			if activeCount >= lic.Seats {
				_ = tx.Rollback(ctx)
				return &ErrSeatsFull{LicenseID: act.LicenseID, Seats: lic.Seats, Used: activeCount}
			}
		}
		if _, err := tx.Exec(ctx,
			`UPDATE activations SET active = TRUE, deactivated_at = NULL,
			 last_seen_at = NOW(), hostname = $2, os = $3, arch = $4, token = $5
			 WHERE id = $1`,
			existingID, act.Hostname, act.OS, act.Arch, act.Token,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("re-activating: %w", err)
		}
		act.ID = existingID
		return tx.Commit(ctx)
	}

	// No existing row — check seat limit
	var activeCount int
	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM activations WHERE license_id = $1 AND active = TRUE`,
		act.LicenseID,
	).Scan(&activeCount)
	if err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("counting seats: %w", err)
	}

	if activeCount >= lic.Seats {
		activeCount, err = s.reapAndRecount(ctx, tx, act.LicenseID, activeCount)
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("reap during new activate: %w", err)
		}
		if activeCount >= lic.Seats {
			_ = tx.Rollback(ctx)
			return &ErrSeatsFull{LicenseID: act.LicenseID, Seats: lic.Seats, Used: activeCount}
		}
	}

	// Insert new activation
	_, err = tx.Exec(ctx,
		`INSERT INTO activations (id, license_id, machine_id, hostname, os, arch, token, activated_at, last_seen_at, active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)`,
		act.ID, act.LicenseID, act.MachineID, act.Hostname, act.OS, act.Arch, act.Token,
		act.ActivatedAt, act.LastSeenAt,
	)
	if err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("inserting activation: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) Deactivate(ctx context.Context, licenseID, machineID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE activations SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1 AND machine_id = $2 AND active = TRUE`,
		licenseID, machineID,
	)
	if err != nil {
		return fmt.Errorf("deactivating: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "activation", ID: licenseID + "/" + machineID}
	}
	return nil
}

func (s *PostgresStore) GetActivation(ctx context.Context, id string) (*Activation, error) {
	var act Activation
	err := s.pool.QueryRow(ctx,
		`SELECT id, license_id, machine_id, hostname, os, arch, token,
		        activated_at, last_seen_at, deactivated_at, active
		 FROM activations WHERE id = $1`, id,
	).Scan(&act.ID, &act.LicenseID, &act.MachineID, &act.Hostname, &act.OS, &act.Arch, &act.Token,
		&act.ActivatedAt, &act.LastSeenAt, &act.DeactivatedAt, &act.Active,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "activation", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("getting activation: %w", err)
	}
	return &act, nil
}

func (s *PostgresStore) GetActivationByMachine(ctx context.Context, licenseID, machineID string) (*Activation, error) {
	var act Activation
	err := s.pool.QueryRow(ctx,
		`SELECT id, license_id, machine_id, hostname, os, arch, token,
		        activated_at, last_seen_at, deactivated_at, active
		 FROM activations WHERE license_id = $1 AND machine_id = $2`, licenseID, machineID,
	).Scan(&act.ID, &act.LicenseID, &act.MachineID, &act.Hostname, &act.OS, &act.Arch, &act.Token,
		&act.ActivatedAt, &act.LastSeenAt, &act.DeactivatedAt, &act.Active,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "activation", ID: licenseID + "/" + machineID}
	}
	if err != nil {
		return nil, fmt.Errorf("getting activation by machine: %w", err)
	}
	return &act, nil
}

func (s *PostgresStore) ListActivations(ctx context.Context, filter ActivationFilter) ([]Activation, error) {
	query := `SELECT id, license_id, machine_id, hostname, os, arch, token,
	                 activated_at, last_seen_at, deactivated_at, active
	          FROM activations WHERE 1=1`
	var args []any
	paramIdx := 0

	if filter.LicenseID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND license_id = $%d", paramIdx)
		args = append(args, filter.LicenseID)
	}
	if filter.MachineID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND machine_id = $%d", paramIdx)
		args = append(args, filter.MachineID)
	}
	if filter.Active != nil {
		paramIdx++
		query += fmt.Sprintf(" AND active = $%d", paramIdx)
		args = append(args, *filter.Active)
	}

	query += " ORDER BY activated_at DESC LIMIT 1000"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing activations: %w", err)
	}
	defer rows.Close()

	acts := make([]Activation, 0)
	for rows.Next() {
		var act Activation
		if err := rows.Scan(&act.ID, &act.LicenseID, &act.MachineID, &act.Hostname, &act.OS, &act.Arch, &act.Token,
			&act.ActivatedAt, &act.LastSeenAt, &act.DeactivatedAt, &act.Active,
		); err != nil {
			return nil, fmt.Errorf("scanning activation: %w", err)
		}
		acts = append(acts, act)
	}
	return acts, rows.Err()
}

func (s *PostgresStore) CountActiveSeats(ctx context.Context, licenseID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM activations WHERE license_id = $1 AND active = TRUE`,
		licenseID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting active seats: %w", err)
	}
	return count, nil
}

func (s *PostgresStore) UpdateLastSeen(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE activations SET last_seen_at = NOW() WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("updating last seen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "activation", ID: id}
	}
	return nil
}

func (s *PostgresStore) ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE activations
		 SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1
		   AND active = TRUE
		   AND last_seen_at < NOW() - ($2 * interval '1 second')`,
		licenseID, int64(threshold.Seconds()),
	)
	if err != nil {
		return 0, fmt.Errorf("reaping stale activations: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SetStaleThreshold configures the stale activation reaping threshold.
func (s *PostgresStore) SetStaleThreshold(d time.Duration) {
	s.staleThreshold = d
}

// reapAndRecount attempts to reap stale activations for the given
// license within the provided transaction, then re-counts active
// seats. Returns the new active count. If StaleThreshold is zero,
// returns the original count unchanged (no reaping).
func (s *PostgresStore) reapAndRecount(ctx context.Context, tx pgx.Tx, licenseID string, currentCount int) (int, error) {
	if s.staleThreshold <= 0 {
		return currentCount, nil
	}

	tag, err := tx.Exec(ctx,
		`UPDATE activations
		 SET active = FALSE, deactivated_at = NOW()
		 WHERE license_id = $1
		   AND active = TRUE
		   AND last_seen_at < NOW() - ($2 * interval '1 second')`,
		licenseID, int64(s.staleThreshold.Seconds()),
	)
	if err != nil {
		return currentCount, fmt.Errorf("reaping stale activations: %w", err)
	}
	reaped := int(tag.RowsAffected())
	if reaped == 0 {
		return currentCount, nil
	}

	// Audit: log the reap event inside the transaction. Non-fatal —
	// the reap itself already succeeded; a failed audit write should
	// not roll back the seat reclamation.
	details, _ := json.Marshal(map[string]any{"reaped": reaped, "threshold": s.staleThreshold.String()})
	if _, auditErr := tx.Exec(ctx,
		`INSERT INTO audit_log (timestamp, event_type, license_id, actor, details)
		 VALUES (NOW(), 'auto_reap', $1, 'system', $2)`,
		licenseID, details,
	); auditErr != nil {
		log.Printf("warning: auto_reap audit write failed: %v", auditErr)
	}

	var newCount int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM activations WHERE license_id = $1 AND active = TRUE`,
		licenseID,
	).Scan(&newCount); err != nil {
		return currentCount, fmt.Errorf("re-counting seats after reap: %w", err)
	}
	return newCount, nil
}

// ExecForTest exposes pool.Exec for integration tests that need to
// manipulate rows directly (e.g., backdating last_seen_at for reap
// tests). Not part of the Store interface — only available on the
// concrete PostgresStore.
func (s *PostgresStore) ExecForTest(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, sql, args...)
}

// QueryRowForTest exposes pool.QueryRow for integration tests that need
// to inspect schema state (e.g., verifying migration side-effects).
// Not part of the Store interface — only available on the concrete
// PostgresStore.
func (s *PostgresStore) QueryRowForTest(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.pool.QueryRow(ctx, sql, args...)
}

// --- Audit ---

func (s *PostgresStore) WriteAudit(ctx context.Context, entry *AuditEntry) error {
	details := entry.Details
	if details == nil {
		details = json.RawMessage("{}")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (timestamp, event_type, license_id, org_id, machine_id, actor, details, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		entry.Timestamp, entry.EventType, nilIfEmpty(entry.LicenseID), nilIfEmpty(entry.OrgID),
		nilIfEmpty(entry.MachineID), entry.Actor, details, entry.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, event_type,
	                 COALESCE(license_id::text, ''), COALESCE(org_id::text, ''), COALESCE(machine_id, ''),
	                 actor, details, ip_address
	          FROM audit_log WHERE 1=1`
	var args []any
	paramIdx := 0

	if filter.EventType != "" {
		paramIdx++
		query += fmt.Sprintf(" AND event_type = $%d", paramIdx)
		args = append(args, filter.EventType)
	}
	if filter.LicenseID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND license_id = $%d", paramIdx)
		args = append(args, filter.LicenseID)
	}
	if filter.OrgID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND org_id = $%d", paramIdx)
		args = append(args, filter.OrgID)
	}
	if filter.After != nil {
		paramIdx++
		query += fmt.Sprintf(" AND timestamp >= $%d", paramIdx)
		args = append(args, filter.After.UTC())
	}
	if filter.Before != nil {
		paramIdx++
		query += fmt.Sprintf(" AND timestamp <= $%d", paramIdx)
		args = append(args, filter.Before.UTC())
	}

	query += " ORDER BY timestamp DESC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 100 // default limit to prevent unbounded queries
	}
	if limit > 10000 {
		limit = 10000
	}
	paramIdx++
	query += fmt.Sprintf(" LIMIT $%d", paramIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit entries: %w", err)
	}
	defer rows.Close()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.EventType,
			&entry.LicenseID, &entry.OrgID, &entry.MachineID,
			&entry.Actor, &entry.Details, &entry.IPAddress,
		); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// --- Stats ---

func (s *PostgresStore) DashboardStats(ctx context.Context) (*DashboardStats, error) {
	var stats DashboardStats
	err := s.pool.QueryRow(ctx,
		`SELECT
			(SELECT COUNT(*) FROM organizations),
			(SELECT COUNT(*) FROM licenses),
			(SELECT COUNT(*) FROM licenses WHERE revoked = FALSE AND expires_at >= NOW()),
			(SELECT COUNT(*) FROM licenses WHERE revoked = TRUE),
			(SELECT COUNT(*) FROM licenses WHERE expires_at < NOW() AND revoked = FALSE),
			(SELECT COUNT(*) FROM activations),
			(SELECT COUNT(*) FROM activations WHERE active = TRUE)`,
	).Scan(&stats.TotalOrgs, &stats.TotalLicenses, &stats.ActiveLicenses,
		&stats.RevokedLicenses, &stats.ExpiredLicenses,
		&stats.TotalActivations, &stats.ActiveSeats,
	)
	if err != nil {
		return nil, fmt.Errorf("getting dashboard stats: %w", err)
	}
	return &stats, nil
}

// --- Users ---

func (s *PostgresStore) CreateUser(ctx context.Context, user *User) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, role, password, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, nilIfEmpty(user.OrgID), user.Email, user.Name, user.Role, user.Password,
		time.Now(), time.Now(),
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: "user with this email already exists"}
		}
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (*User, error) {
	var user User
	var orgID *string
	err := s.pool.QueryRow(ctx,
		`SELECT u.id, u.org_id, u.email, u.name, u.role, u.password, u.created_at, u.updated_at,
		        COALESCE(o.name, '') AS org_name
		 FROM users u LEFT JOIN organizations o ON u.org_id = o.id
		 WHERE u.id = $1`, id,
	).Scan(&user.ID, &orgID, &user.Email, &user.Name, &user.Role, &user.Password,
		&user.CreatedAt, &user.UpdatedAt, &user.OrgName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "user", ID: id}
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if orgID != nil {
		user.OrgID = *orgID
	}
	return &user, nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	var orgID *string
	err := s.pool.QueryRow(ctx,
		`SELECT u.id, u.org_id, u.email, u.name, u.role, u.password, u.created_at, u.updated_at,
		        COALESCE(o.name, '') AS org_name
		 FROM users u LEFT JOIN organizations o ON u.org_id = o.id
		 WHERE u.email = $1`, email,
	).Scan(&user.ID, &orgID, &user.Email, &user.Name, &user.Role, &user.Password,
		&user.CreatedAt, &user.UpdatedAt, &user.OrgName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "user", ID: email}
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	if orgID != nil {
		user.OrgID = *orgID
	}
	return &user, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context, filter UserFilter) ([]User, error) {
	query := `SELECT u.id, u.org_id, u.email, u.name, u.role, u.created_at, u.updated_at,
	                 COALESCE(o.name, '') AS org_name
	          FROM users u LEFT JOIN organizations o ON u.org_id = o.id WHERE 1=1`
	args := []any{}
	paramIdx := 0

	if filter.OrgID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND u.org_id = $%d", paramIdx)
		args = append(args, filter.OrgID)
	}
	if filter.Role != "" {
		paramIdx++
		query += fmt.Sprintf(" AND u.role = $%d", paramIdx)
		args = append(args, filter.Role)
	}
	query += " ORDER BY u.name LIMIT 1000"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var orgID *string
		if err := rows.Scan(&u.ID, &orgID, &u.Email, &u.Name, &u.Role,
			&u.CreatedAt, &u.UpdatedAt, &u.OrgName); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		if orgID != nil {
			u.OrgID = *orgID
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser updates the mutable fields of a user. The UserUpdate type has
// no Role or OrgID field — the split-identity model enforces role and org
// immutability at the type level so callers can't accidentally mutate them.
//
// If update.Password is empty, the password is left unchanged (a partial
// update). Otherwise it is replaced verbatim — callers are expected to have
// already bcrypt-hashed the value.
func (s *PostgresStore) UpdateUser(ctx context.Context, update UserUpdate) error {
	var (
		tag pgconn.CommandTag
		err error
	)
	if update.Password == "" {
		tag, err = s.pool.Exec(ctx,
			`UPDATE users SET name = $2, updated_at = $3 WHERE id = $1`,
			update.ID, update.Name, time.Now(),
		)
	} else {
		tag, err = s.pool.Exec(ctx,
			`UPDATE users SET name = $2, password = $3, updated_at = $4 WHERE id = $1`,
			update.ID, update.Name, update.Password, time.Now(),
		)
	}
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "user", ID: update.ID}
	}
	return nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "user", ID: id}
	}
	return nil
}

func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// --- Sessions ---

func (s *PostgresStore) CreateSession(ctx context.Context, session *Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		session.ID, session.UserID, session.TokenHash, session.ExpiresAt, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error) {
	var sess Session
	// Filter expired rows here so callers can rely on a successful fetch
	// meaning "the session is still valid right now". DeleteExpiredSessions
	// is a separate cleanup pass for old rows.
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, created_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash,
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "session", ID: tokenHash}
		}
		return nil, fmt.Errorf("getting session: %w", err)
	}
	return &sess, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", id)
	return err
}

func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM sessions WHERE expires_at < now()")
	return err
}

// --- Lifecycle ---

func (s *PostgresStore) TruncateAll(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "TRUNCATE organizations, licenses, activations, audit_log, users, sessions, license_usage CASCADE")
	return err
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// nilIfEmpty returns nil for empty strings, for nullable DB columns.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
