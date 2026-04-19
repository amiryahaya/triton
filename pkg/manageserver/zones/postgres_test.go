//go:build integration

package zones_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/zones"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// testSchemaSeq generates unique per-test schema names so parallel
// integration test runs don't collide.
var testSchemaSeq atomic.Int64

// newTestPool returns a pgxpool.Pool scoped to a fresh isolated schema
// (with managestore migrations applied). Mirrors the isolation pattern
// in pkg/managestore/postgres_test.go::openTestStore.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_zones_%d", testSchemaSeq.Add(1))

	// Create the schema on a short-lived pool.
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

	// Dedicated pool pinned to the isolated schema.
	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		// Teardown on a fresh pool — the scoped pool is already closed.
		cleanup, cerr := pgxpool.New(context.Background(), dbURL)
		if cerr != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

func TestZones_CreateListGetDelete(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := zones.NewPostgresStore(pool)

	z, err := s.Create(ctx, zones.Zone{Name: "dmz", Description: "perimeter"})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, z.ID, "Create must populate ID")
	assert.False(t, z.CreatedAt.IsZero(), "Create must populate CreatedAt")
	assert.False(t, z.UpdatedAt.IsZero(), "Create must populate UpdatedAt")

	got, err := s.Get(ctx, z.ID)
	require.NoError(t, err)
	assert.Equal(t, "dmz", got.Name)
	assert.Equal(t, "perimeter", got.Description)
	assert.Equal(t, z.ID, got.ID)

	all, err := s.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	count, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	require.NoError(t, s.Delete(ctx, z.ID))

	_, err = s.Get(ctx, z.ID)
	assert.ErrorIs(t, err, zones.ErrNotFound)

	// Delete on missing id must also return ErrNotFound.
	err = s.Delete(ctx, z.ID)
	assert.ErrorIs(t, err, zones.ErrNotFound)
}

func TestZones_Update_ChangesNameAndDescription(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := zones.NewPostgresStore(pool)

	z, err := s.Create(ctx, zones.Zone{Name: "prod", Description: "production"})
	require.NoError(t, err)
	originalUpdatedAt := z.UpdatedAt

	z.Name = "production-ap-southeast-1"
	z.Description = "prod AP Southeast"
	updated, err := s.Update(ctx, z)
	require.NoError(t, err)
	assert.Equal(t, "production-ap-southeast-1", updated.Name)
	assert.Equal(t, "prod AP Southeast", updated.Description)
	assert.True(t, updated.UpdatedAt.After(originalUpdatedAt) || updated.UpdatedAt.Equal(originalUpdatedAt),
		"UpdatedAt must advance or stay equal (NOW() precision)")

	// Re-read to confirm persistence.
	got, err := s.Get(ctx, z.ID)
	require.NoError(t, err)
	assert.Equal(t, "production-ap-southeast-1", got.Name)
}

func TestZones_Update_MissingReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := zones.NewPostgresStore(pool)

	_, err := s.Update(ctx, zones.Zone{ID: uuid.Must(uuid.NewV7()), Name: "ghost", Description: ""})
	assert.ErrorIs(t, err, zones.ErrNotFound)
}

func TestZones_List_OrdersByName(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := zones.NewPostgresStore(pool)

	// Insert out of order.
	for _, name := range []string{"zeta", "alpha", "mu"} {
		_, err := s.Create(ctx, zones.Zone{Name: name})
		require.NoError(t, err)
	}

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, "alpha", list[0].Name)
	assert.Equal(t, "mu", list[1].Name)
	assert.Equal(t, "zeta", list[2].Name)
}
