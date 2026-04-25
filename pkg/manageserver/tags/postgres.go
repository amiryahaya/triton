package tags

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

func (s *PostgresStore) Create(ctx context.Context, t Tag) (Tag, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO manage_tags (name, color) VALUES ($1, $2)
		 RETURNING id, created_at`,
		t.Name, t.Color,
	)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return Tag{}, fmt.Errorf("%w: %q", ErrConflict, t.Name)
		}
		return Tag{}, fmt.Errorf("create tag: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Tag, error) {
	var t Tag
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, color, created_at FROM manage_tags WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Color, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	if err != nil {
		return Tag{}, fmt.Errorf("get tag: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Tag, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, t.color, t.created_at,
		        COUNT(ht.host_id)::int AS host_count
		 FROM manage_tags t
		 LEFT JOIN manage_host_tags ht ON ht.tag_id = t.id
		 GROUP BY t.id
		 ORDER BY t.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}
	defer rows.Close()
	out := []Tag{}
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.CreatedAt, &t.HostCount); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Update(ctx context.Context, t Tag) (Tag, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_tags SET name = $1, color = $2 WHERE id = $3
		 RETURNING id, name, color, created_at`,
		t.Name, t.Color, t.ID,
	)
	var out Tag
	if err := row.Scan(&out.ID, &out.Name, &out.Color, &out.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tag{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Tag{}, fmt.Errorf("%w: %q", ErrConflict, t.Name)
		}
		return Tag{}, fmt.Errorf("update tag: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_tags WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete tag: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
