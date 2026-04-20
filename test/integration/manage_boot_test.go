//go:build integration

// This file covers the Manage Server boot path established in B2.2 Batch A6:
// the Manage binary must run BOTH managestore.Migrate and store.Migrate
// against a single shared pool so the Manage DB carries the Manage-native
// tables (users, zones, hosts, scan_jobs, CA, …) AND the Report Server's
// read-model tables (scans, findings, …) that Manage consumes inline.
//
// We can't easily spawn the cmd/manageserver binary here without adding a
// test harness; instead we exercise the same Migrate(pool) calls directly.
// If the two packages ever drift to incompatible schema-version tables,
// this test catches it.
package integration_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/managestore"
	"github.com/amiryahaya/triton/pkg/store"
)

var manageBootSchemaSeq atomic.Int64

// TestManageBoot_SharedSchemaPresent asserts both managestore.Migrate and
// store.Migrate succeed against the same pool, and that the two
// versioning tables (manage_schema_version + schema_version) are both
// populated. Regression guard for the Manage Server boot path.
func TestManageBoot_SharedSchemaPresent(t *testing.T) {
	ctx := context.Background()
	dbURL := testDBURL()

	// Provision an isolated schema so the test doesn't leak tables into
	// the default `public` schema shared with other integration tests.
	schema := fmt.Sprintf("test_mgmt_boot_%d", manageBootSchemaSeq.Add(1))

	bootstrap, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	if _, err := bootstrap.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		bootstrap.Close()
		t.Fatalf("drop stale schema: %v", err)
	}
	if _, err := bootstrap.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		bootstrap.Close()
		t.Fatalf("create schema: %v", err)
	}
	bootstrap.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		// Clean up the schema with a fresh connection since `pool`
		// will be closed by now.
		cleanup, err := pgxpool.New(ctx, dbURL)
		if err == nil {
			_, _ = cleanup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
			cleanup.Close()
		}
	})
	defer pool.Close()

	// Run BOTH migrators in the order the manageserver main() will: the
	// Manage-native schema first, then the Report Server's tables that
	// cohabit the same DB.
	require.NoError(t, managestore.Migrate(ctx, pool), "managestore.Migrate must succeed")
	require.NoError(t, store.Migrate(ctx, pool), "store.Migrate must succeed")

	// Both versioning tables must exist in the isolated schema.
	assertTableInSchema(t, ctx, pool, schema, "manage_schema_version")
	assertTableInSchema(t, ctx, pool, schema, "schema_version")

	// Both must have at least one applied-migration row.
	var mv, sv int
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM manage_schema_version").Scan(&mv))
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM schema_version").Scan(&sv))
	assert.GreaterOrEqual(t, mv, 1, "manage_schema_version must have at least one row")
	assert.GreaterOrEqual(t, sv, 1, "schema_version must have at least one row")

	// A handful of marker tables from each side — sanity check that the
	// two migration sets actually ran end-to-end, not just the version
	// table CREATE.
	for _, tbl := range []string{
		"manage_users",        // managestore v1
		"manage_zones",        // managestore v2
		"manage_scan_jobs",    // managestore v3
		"manage_license_state", // managestore v4
		"manage_agents",       // managestore v5
		"scans",               // pkg/store v1
	} {
		assertTableInSchema(t, ctx, pool, schema, tbl)
	}

	// Re-running both migrators must be a no-op (idempotency).
	require.NoError(t, managestore.Migrate(ctx, pool), "re-running managestore.Migrate must be a no-op")
	require.NoError(t, store.Migrate(ctx, pool), "re-running store.Migrate must be a no-op")
}

func assertTableInSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema, table string) {
	t.Helper()
	var exists bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = $1 AND table_name = $2
		)`, schema, table).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "table %s.%s must exist after migrate", schema, table)
}
