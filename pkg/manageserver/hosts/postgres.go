package hosts

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

// hostSelectCols selects host columns only (no tags). Tags are loaded
// separately via loadTagsForHosts and attached by the caller.
const hostSelectCols = `id, hostname, host(ip)::text, os, last_seen_at, created_at, updated_at`

func scanHost(row pgx.Row) (Host, error) {
	var h Host
	var ip *string
	if err := row.Scan(&h.ID, &h.Hostname, &ip, &h.OS, &h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return Host{}, err
	}
	if ip != nil {
		h.IP = *ip
	}
	h.Tags = []tags.Tag{}
	return h, nil
}

func ipArg(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

func isInvalidTextRepresentation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "22P02"
}

// loadTagsForHosts fetches all tags for the given host IDs in one query
// and returns a map from host ID → tag slice.
func (s *PostgresStore) loadTagsForHosts(ctx context.Context, hostIDs []uuid.UUID) (map[uuid.UUID][]tags.Tag, error) {
	if len(hostIDs) == 0 {
		return map[uuid.UUID][]tags.Tag{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT ht.host_id, t.id, t.name, t.color, t.created_at
		 FROM manage_host_tags ht
		 JOIN manage_tags t ON t.id = ht.tag_id
		 WHERE ht.host_id = ANY($1)
		 ORDER BY t.name`,
		hostIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load tags for hosts: %w", err)
	}
	defer rows.Close()

	result := map[uuid.UUID][]tags.Tag{}
	for rows.Next() {
		var hostID uuid.UUID
		var tag tags.Tag
		if err := rows.Scan(&hostID, &tag.ID, &tag.Name, &tag.Color, &tag.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan host tag: %w", err)
		}
		result[hostID] = append(result[hostID], tag)
	}
	return result, rows.Err()
}

func (s *PostgresStore) Create(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO manage_hosts (hostname, ip, os, last_seen_at)
		 VALUES ($1, $2::inet, $3, $4)
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), h.OS, h.LastSeenAt,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		if isInvalidTextRepresentation(err) {
			return Host{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		return Host{}, fmt.Errorf("create host: %w", err)
	}
	h.Tags = []tags.Tag{}
	return h, nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Host, error) {
	h, err := scanHost(s.pool.QueryRow(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE id = $1`, id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("get host: %w", err)
	}
	tagMap, err := s.loadTagsForHosts(ctx, []uuid.UUID{h.ID})
	if err != nil {
		return Host{}, err
	}
	if t, ok := tagMap[h.ID]; ok {
		h.Tags = t
	}
	return h, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts ORDER BY hostname`,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) Update(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_hosts
		 SET hostname = $1, ip = $2::inet, os = $3, last_seen_at = $4, updated_at = NOW()
		 WHERE id = $5
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), h.OS, h.LastSeenAt, h.ID,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		if isInvalidTextRepresentation(err) {
			return Host{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		return Host{}, fmt.Errorf("update host: %w", err)
	}
	tagMap, err := s.loadTagsForHosts(ctx, []uuid.UUID{h.ID})
	if err != nil {
		return Host{}, err
	}
	if t, ok := tagMap[h.ID]; ok {
		h.Tags = t
	} else {
		h.Tags = []tags.Tag{}
	}
	return h, nil
}

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

func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_hosts`).Scan(&n)
	return n, err
}

func (s *PostgresStore) SetTags(ctx context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set-tags tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM manage_host_tags WHERE host_id = $1`, hostID); err != nil {
		return fmt.Errorf("clear host tags: %w", err)
	}
	for _, tid := range tagIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO manage_host_tags (host_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			hostID, tid,
		); err != nil {
			return fmt.Errorf("insert host tag: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ResolveTagNames(ctx context.Context, names []string, defaultColor string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		var id uuid.UUID
		err := s.pool.QueryRow(ctx,
			`INSERT INTO manage_tags (name, color) VALUES ($1, $2)
			 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			 RETURNING id`,
			name, defaultColor,
		).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("resolve tag %q: %w", name, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *PostgresStore) ListByTag(ctx context.Context, tagID uuid.UUID) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts h
		 JOIN manage_host_tags ht ON ht.host_id = h.id
		 WHERE ht.tag_id = $1
		 ORDER BY h.hostname`,
		tagID,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts by tag: %w", err)
	}
	defer rows.Close()

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) CountByTag(ctx context.Context, tagID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_host_tags WHERE tag_id = $1`, tagID,
	).Scan(&n)
	return n, err
}

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

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) BulkCreate(ctx context.Context, hosts []Host) ([]Host, error) {
	if len(hosts) == 0 {
		return []Host{}, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin bulk-create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := make([]Host, len(hosts))
	for i := range hosts {
		src := &hosts[i]
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_hosts (hostname, ip, os, last_seen_at)
			 VALUES ($1, $2::inet, $3, $4)
			 RETURNING id, created_at, updated_at`,
			src.Hostname, ipArg(src.IP), src.OS, src.LastSeenAt,
		)
		dst := *src
		if err := row.Scan(&dst.ID, &dst.CreatedAt, &dst.UpdatedAt); err != nil {
			if isUniqueViolation(err) {
				return nil, fmt.Errorf("%w: hostname %q (index %d)", ErrConflict, src.Hostname, i)
			}
			if isInvalidTextRepresentation(err) {
				return nil, fmt.Errorf("%w: index %d: %v", ErrInvalidInput, i, err)
			}
			return nil, fmt.Errorf("bulk create host %q (index %d): %w", src.Hostname, i, err)
		}
		dst.Tags = []tags.Tag{}
		out[i] = dst
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit bulk-create tx: %w", err)
	}
	return out, nil
}
