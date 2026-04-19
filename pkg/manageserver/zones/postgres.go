package zones

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool. The
// pool's lifetime is owned by the caller — typically shared with the
// rest of the Manage Server via pool injection.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps an externally-owned pgxpool.Pool. The caller
// must have already run managestore.Migrate against this pool so the
// manage_zones table exists.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// Create inserts a new zone. The DB generates id + timestamps.
func (s *PostgresStore) Create(ctx context.Context, z Zone) (Zone, error) {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name, description)
		 VALUES ($1, $2)
		 RETURNING id, created_at, updated_at`,
		z.Name, z.Description,
	).Scan(&z.ID, &z.CreatedAt, &z.UpdatedAt)
	if err != nil {
		return Zone{}, fmt.Errorf("create zone: %w", err)
	}
	return z, nil
}

// Get fetches a zone by id.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Zone, error) {
	var z Zone
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, description, created_at, updated_at
		 FROM manage_zones WHERE id = $1`,
		id,
	).Scan(&z.ID, &z.Name, &z.Description, &z.CreatedAt, &z.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Zone{}, ErrNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("get zone: %w", err)
	}
	return z, nil
}

// List returns every zone ordered by name.
func (s *PostgresStore) List(ctx context.Context) ([]Zone, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, created_at, updated_at
		 FROM manage_zones ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	defer rows.Close()

	out := []Zone{}
	for rows.Next() {
		var z Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Description, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan zone: %w", err)
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// Update changes name + description on an existing zone.
func (s *PostgresStore) Update(ctx context.Context, z Zone) (Zone, error) {
	err := s.pool.QueryRow(ctx,
		`UPDATE manage_zones SET name = $1, description = $2, updated_at = NOW()
		 WHERE id = $3
		 RETURNING id, name, description, created_at, updated_at`,
		z.Name, z.Description, z.ID,
	).Scan(&z.ID, &z.Name, &z.Description, &z.CreatedAt, &z.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Zone{}, ErrNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("update zone: %w", err)
	}
	return z, nil
}

// Delete removes the zone and returns ErrNotFound if no row matched.
func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_zones WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Count returns the total number of zones.
func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_zones`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count zones: %w", err)
	}
	return n, nil
}
