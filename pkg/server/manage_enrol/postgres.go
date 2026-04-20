package manage_enrol

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool. The pool's
// lifecycle is owned by the caller.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Create inserts a new manage_instances row. Returns wrapped errors; callers
// needing conflict detection should check error contents explicitly.
func (s *PostgresStore) Create(ctx context.Context, mi ManageInstance) error {
	if mi.Status == "" {
		mi.Status = StatusActive
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_instances
		    (id, license_key_hash, cert_serial, tenant_attribution, status)
		 VALUES ($1, $2, $3, $4, $5)`,
		mi.ID, mi.LicenseKeyHash, mi.CertSerial, mi.TenantAttribution, mi.Status,
	)
	if err != nil {
		return fmt.Errorf("insert manage_instance: %w", err)
	}
	return nil
}

// GetByCertSerial fetches a row by cert_serial. Returns ErrNotFound when no
// row matches.
func (s *PostgresStore) GetByCertSerial(ctx context.Context, serial string) (ManageInstance, error) {
	var mi ManageInstance
	err := s.pool.QueryRow(ctx,
		`SELECT id, license_key_hash, cert_serial, tenant_attribution, enrolled_at, status
		 FROM manage_instances WHERE cert_serial = $1`,
		serial,
	).Scan(&mi.ID, &mi.LicenseKeyHash, &mi.CertSerial, &mi.TenantAttribution, &mi.EnrolledAt, &mi.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ManageInstance{}, ErrNotFound
		}
		return ManageInstance{}, fmt.Errorf("get manage_instance by cert_serial: %w", err)
	}
	return mi, nil
}

// Revoke flips status to 'revoked'. Idempotent; missing rows are a no-op to
// keep the admin flow simple (no concurrent-deactivate races to handle).
func (s *PostgresStore) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_instances SET status = 'revoked' WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke manage_instance: %w", err)
	}
	return nil
}

// List returns every manage_instances row ordered by enrolment time.
func (s *PostgresStore) List(ctx context.Context) ([]ManageInstance, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, license_key_hash, cert_serial, tenant_attribution, enrolled_at, status
		 FROM manage_instances ORDER BY enrolled_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list manage_instances: %w", err)
	}
	defer rows.Close()

	out := []ManageInstance{}
	for rows.Next() {
		var mi ManageInstance
		if err := rows.Scan(
			&mi.ID, &mi.LicenseKeyHash, &mi.CertSerial,
			&mi.TenantAttribution, &mi.EnrolledAt, &mi.Status,
		); err != nil {
			return nil, fmt.Errorf("scan manage_instance row: %w", err)
		}
		out = append(out, mi)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate manage_instance rows: %w", err)
	}
	return out, nil
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)
