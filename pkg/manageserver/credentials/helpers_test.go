//go:build integration

package credentials_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_credentials_%d", testSchemaSeq.Add(1))

	ctx := context.Background()
	setupPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		setupPool.Close()
		t.Fatalf("drop stale schema: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		setupPool.Close()
		t.Fatalf("create schema: %v", err)
	}
	setupPool.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		cleanup, cerr := pgxpool.New(context.Background(), dbURL)
		if cerr != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}
