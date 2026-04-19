package hosts

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool. The
// pool's lifetime is owned by the caller.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps an externally-owned pgxpool.Pool. The caller
// must have already run managestore.Migrate so manage_hosts exists.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// hostSelectCols matches the column order expected by scanHost.
const hostSelectCols = `id, hostname, host(ip)::text, zone_id, os, last_seen_at, created_at, updated_at`

// scanHost decodes a single row into a Host. Nullable columns (ip,
// zone_id, last_seen_at) are scanned via pointers and translated to
// the Host struct's zero values / pointer types.
func scanHost(scanner pgx.Row) (Host, error) {
	var h Host
	var ip *string
	var zoneID *uuid.UUID
	if err := scanner.Scan(
		&h.ID, &h.Hostname, &ip, &zoneID, &h.OS, &h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt,
	); err != nil {
		return Host{}, err
	}
	if ip != nil {
		h.IP = *ip
	}
	h.ZoneID = zoneID
	return h, nil
}

// ipArg translates our empty-string-means-NULL convention into a
// driver-safe value. Passing a non-nil `any("")` value to pgx would
// produce the text "" and then fail INET parsing, so we return an
// untyped nil when empty.
func ipArg(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

// zoneArg converts a *uuid.UUID to a driver-safe value. nil pointer
// becomes untyped nil so the INSERT picks up NULL.
func zoneArg(z *uuid.UUID) any {
	if z == nil {
		return nil
	}
	return *z
}

// isUniqueViolation reports whether err wraps a Postgres unique_violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Create inserts a new host. Empty IP and nil ZoneID insert NULL.
// Returns ErrConflict if the hostname collides.
func (s *PostgresStore) Create(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO manage_hosts (hostname, ip, zone_id, os, last_seen_at)
		 VALUES ($1, $2::inet, $3, $4, $5)
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), zoneArg(h.ZoneID), h.OS, h.LastSeenAt,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		return Host{}, fmt.Errorf("create host: %w", err)
	}
	return h, nil
}

// Get fetches a host by id.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE id = $1`,
		id,
	)
	h, err := scanHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("get host: %w", err)
	}
	return h, nil
}

// List returns every host ordered by hostname.
func (s *PostgresStore) List(ctx context.Context) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts ORDER BY hostname`,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Update changes hostname/ip/zone/os/last_seen on an existing host.
// Returns ErrConflict if the new hostname collides with another row.
func (s *PostgresStore) Update(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_hosts
		 SET hostname = $1, ip = $2::inet, zone_id = $3, os = $4, last_seen_at = $5, updated_at = NOW()
		 WHERE id = $6
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), zoneArg(h.ZoneID), h.OS, h.LastSeenAt, h.ID,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		return Host{}, fmt.Errorf("update host: %w", err)
	}
	return h, nil
}

// Delete removes the host and returns ErrNotFound if no row matched.
func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_hosts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Count returns the total number of hosts.
func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_hosts`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count hosts: %w", err)
	}
	return n, nil
}

// ListByZone returns hosts whose zone_id matches, ordered by hostname.
func (s *PostgresStore) ListByZone(ctx context.Context, zoneID uuid.UUID) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE zone_id = $1 ORDER BY hostname`,
		zoneID,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts by zone: %w", err)
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CountByZone returns the number of hosts in the given zone.
func (s *PostgresStore) CountByZone(ctx context.Context, zoneID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_hosts WHERE zone_id = $1`,
		zoneID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count hosts by zone: %w", err)
	}
	return n, nil
}

// ListByHostnames returns hosts whose hostname is in names. An empty
// or nil slice returns an empty result without querying.
func (s *PostgresStore) ListByHostnames(ctx context.Context, names []string) ([]Host, error) {
	if len(names) == 0 {
		return []Host{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE hostname = ANY($1) ORDER BY hostname`,
		names,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts by names: %w", err)
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// BulkCreate inserts a batch of hosts in a single transaction. Any
// error — including a hostname conflict — rolls back the entire batch.
// The returned slice mirrors the input order with DB-populated fields
// filled in.
func (s *PostgresStore) BulkCreate(ctx context.Context, hosts []Host) ([]Host, error) {
	if len(hosts) == 0 {
		return []Host{}, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin bulk-create tx: %w", err)
	}
	// Rollback is a no-op after Commit; safe to defer unconditionally.
	defer func() { _ = tx.Rollback(ctx) }()

	out := make([]Host, len(hosts))
	for i, h := range hosts {
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_hosts (hostname, ip, zone_id, os, last_seen_at)
			 VALUES ($1, $2::inet, $3, $4, $5)
			 RETURNING id, created_at, updated_at`,
			h.Hostname, ipArg(h.IP), zoneArg(h.ZoneID), h.OS, h.LastSeenAt,
		)
		if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
			if isUniqueViolation(err) {
				return nil, fmt.Errorf("%w: hostname %q (index %d)", ErrConflict, h.Hostname, i)
			}
			return nil, fmt.Errorf("bulk create host %q (index %d): %w", h.Hostname, i, err)
		}
		out[i] = h
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit bulk-create tx: %w", err)
	}
	return out, nil
}
