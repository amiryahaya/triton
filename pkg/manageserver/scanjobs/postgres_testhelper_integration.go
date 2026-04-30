//go:build integration

package scanjobs

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// QueryRowForTest exposes pool.QueryRow for integration test helpers.
func (s *PostgresStore) QueryRowForTest(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.pool.QueryRow(ctx, sql, args...)
}
