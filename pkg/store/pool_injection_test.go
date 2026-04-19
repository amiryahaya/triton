//go:build integration

package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// testPool returns a pgxpool.Pool against the test DB. Skips if DB unavailable.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL ping failed: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// TestMigrate_IsIdempotent calls Migrate twice against the same pool and
// verifies that schema_version is unchanged between calls.
func TestMigrate_IsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	require.NoError(t, Migrate(ctx, pool))

	var v1 int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v1))

	require.NoError(t, Migrate(ctx, pool))

	var v2 int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v2))

	require.Equal(t, v1, v2, "Migrate should be idempotent — re-running must not advance schema_version")
}

// TestPoolInjection_EquivalentToURLConstructor verifies that a store built
// via NewPostgresStoreFromPool(pool) + Migrate(ctx, pool) behaves identically
// to one built via NewPostgresStore(ctx, connStr). Both should read the same
// schema version and support basic store operations.
//
// Test ordering note: sA (URL path) runs migrations first, so by the time
// sB calls Migrate(pool) it is a no-op for already-applied versions —
// which is exactly what TestMigrate_IsIdempotent already exercises. What
// this test proves is that the pool-constructor path produces a fully
// functional store (non-nil pool, SchemaVersion reads, file_hashes
// round-trip), not that it migrates from scratch. That's sufficient for
// B2.1's "zero behaviour change" gate.
func TestPoolInjection_EquivalentToURLConstructor(t *testing.T) {
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	// Path A: URL constructor (existing behaviour).
	sA, err := NewPostgresStore(ctx, dbUrl)
	require.NoError(t, err)
	defer sA.Close()

	// Path B: pool constructor + Migrate.
	pool, err := pgxpool.New(ctx, dbUrl)
	require.NoError(t, err)
	require.NoError(t, pool.Ping(ctx))
	defer pool.Close() // closes the pool we own; NO defer sB.Close() —
	// sB does not own the pool (see NewPostgresStoreFromPool godoc).
	require.NoError(t, Migrate(ctx, pool))
	sB := NewPostgresStoreFromPool(pool)

	// Both stores should report the same schema version.
	vA, err := sA.SchemaVersion(ctx)
	require.NoError(t, err)
	vB, err := sB.SchemaVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, vA, vB, "both constructors must produce stores on the same schema version")

	// Both stores should have non-nil pools.
	require.NotNil(t, sA.Pool(), "URL-constructed store must expose its pool")
	require.NotNil(t, sB.Pool(), "pool-constructed store must expose its pool")

	// Trivial write/read round-trip via pool-constructed store proves it is
	// fully functional, not just structurally equivalent.
	require.NoError(t, sB.SetFileHash(ctx, "/tmp/b2.1-equivalence-test", "deadbeef"))
	hash, _, err := sB.GetFileHash(ctx, "/tmp/b2.1-equivalence-test")
	require.NoError(t, err)
	require.Equal(t, "deadbeef", hash)

	// Cleanup the test row.
	_, err = pool.Exec(ctx, "DELETE FROM file_hashes WHERE path = $1", "/tmp/b2.1-equivalence-test")
	require.NoError(t, err)
}
