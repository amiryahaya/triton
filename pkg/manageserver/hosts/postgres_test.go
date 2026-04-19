//go:build integration

package hosts_test

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

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/managestore"
)

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
	schema := fmt.Sprintf("test_hosts_%d", testSchemaSeq.Add(1))

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

// insertZone inserts a zone directly via SQL so the hosts tests don't
// have to import the zones package.
func insertZone(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO manage_zones (name) VALUES ($1) RETURNING id`,
		name,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestHosts_CreateListGetDelete(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	h, err := s.Create(ctx, hosts.Host{
		Hostname: "web01.example.com",
		IP:       "10.0.0.5",
		OS:       "linux",
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, h.ID)
	assert.False(t, h.CreatedAt.IsZero())

	got, err := s.Get(ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, "web01.example.com", got.Hostname)
	assert.Equal(t, "10.0.0.5", got.IP)
	assert.Equal(t, "linux", got.OS)

	all, err := s.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	count, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	require.NoError(t, s.Delete(ctx, h.ID))

	_, err = s.Get(ctx, h.ID)
	assert.ErrorIs(t, err, hosts.ErrNotFound)

	err = s.Delete(ctx, h.ID)
	assert.ErrorIs(t, err, hosts.ErrNotFound)
}

func TestHosts_UniqueHostname_Rejected(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	_, err := s.Create(ctx, hosts.Host{Hostname: "dup.example.com"})
	require.NoError(t, err)

	_, err = s.Create(ctx, hosts.Host{Hostname: "dup.example.com"})
	assert.ErrorIs(t, err, hosts.ErrConflict)
}

func TestHosts_ListByZone_FiltersCorrectly(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	zoneID := insertZone(t, pool, "dmz")

	// Two in-zone hosts, one with no zone.
	_, err := s.Create(ctx, hosts.Host{Hostname: "in-zone-1", ZoneID: &zoneID})
	require.NoError(t, err)
	_, err = s.Create(ctx, hosts.Host{Hostname: "in-zone-2", ZoneID: &zoneID})
	require.NoError(t, err)
	_, err = s.Create(ctx, hosts.Host{Hostname: "outside"})
	require.NoError(t, err)

	list, err := s.ListByZone(ctx, zoneID)
	require.NoError(t, err)
	assert.Len(t, list, 2)
	names := []string{list[0].Hostname, list[1].Hostname}
	assert.Contains(t, names, "in-zone-1")
	assert.Contains(t, names, "in-zone-2")

	n, err := s.CountByZone(ctx, zoneID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// Arbitrary zone id — no matches.
	n, err = s.CountByZone(ctx, uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

func TestHosts_NullableIPAndZone_RoundTrips(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	// No IP, no zone.
	created, err := s.Create(ctx, hosts.Host{Hostname: "bare.example"})
	require.NoError(t, err)

	got, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "", got.IP, "empty IP must round-trip as empty (NULL in DB)")
	assert.Nil(t, got.ZoneID, "nil ZoneID must round-trip as nil (NULL in DB)")
	assert.Equal(t, "", got.OS, "default empty OS")
}

func TestHosts_Update_ChangesFields(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	zoneID := insertZone(t, pool, "prod")
	h, err := s.Create(ctx, hosts.Host{Hostname: "app01", OS: "linux"})
	require.NoError(t, err)

	h.IP = "10.1.2.3"
	h.ZoneID = &zoneID
	h.OS = "linux-ubuntu"
	updated, err := s.Update(ctx, h)
	require.NoError(t, err)
	assert.Equal(t, "10.1.2.3", updated.IP)
	require.NotNil(t, updated.ZoneID)
	assert.Equal(t, zoneID, *updated.ZoneID)
	assert.Equal(t, "linux-ubuntu", updated.OS)

	// Re-read to confirm persistence.
	got, err := s.Get(ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, "10.1.2.3", got.IP)
}

func TestHosts_Update_MissingReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	_, err := s.Update(ctx, hosts.Host{ID: uuid.Must(uuid.NewV7()), Hostname: "ghost"})
	assert.ErrorIs(t, err, hosts.ErrNotFound)
}

func TestHosts_ListByHostnames_ReturnsMatchingRows(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := s.Create(ctx, hosts.Host{Hostname: name})
		require.NoError(t, err)
	}

	list, err := s.ListByHostnames(ctx, []string{"alpha", "gamma", "missing"})
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Equal(t, "alpha", list[0].Hostname)
	assert.Equal(t, "gamma", list[1].Hostname)

	// Empty input returns empty without a query error.
	empty, err := s.ListByHostnames(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestHosts_BulkCreate_InsertsAll(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	in := []hosts.Host{
		{Hostname: "bulk-1", IP: "10.0.0.1"},
		{Hostname: "bulk-2", IP: "10.0.0.2"},
		{Hostname: "bulk-3"},
	}
	out, err := s.BulkCreate(ctx, in)
	require.NoError(t, err)
	require.Len(t, out, 3)
	for _, h := range out {
		assert.NotEqual(t, uuid.Nil, h.ID)
	}

	count, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

// TestHosts_InvalidIP_AtStoreLayer confirms the belt-and-braces guard
// in the store: if a caller bypasses the handler validation and hands
// the store a malformed IP literal, we surface ErrInvalidInput rather
// than a raw pg SQLSTATE 22P02.
func TestHosts_InvalidIP_AtStoreLayer(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	// Create: bad literal cast against INET -> ErrInvalidInput.
	_, err := s.Create(ctx, hosts.Host{Hostname: "bad-ip", IP: "not-an-ip"})
	assert.ErrorIs(t, err, hosts.ErrInvalidInput)

	// BulkCreate: same guard should fire mid-batch and roll back.
	_, err = s.BulkCreate(ctx, []hosts.Host{
		{Hostname: "ok-bulk"},
		{Hostname: "bad-ip-bulk", IP: "also-bogus"},
	})
	assert.ErrorIs(t, err, hosts.ErrInvalidInput)

	// And nothing should have been committed.
	count, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "invalid bulk insert must not leave rows behind")
}

func TestHosts_BulkCreate_ConflictRollsBackAll(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := hosts.NewPostgresStore(pool)

	// Pre-existing host that the bulk batch collides with.
	_, err := s.Create(ctx, hosts.Host{Hostname: "collide"})
	require.NoError(t, err)

	in := []hosts.Host{
		{Hostname: "fresh-1"},
		{Hostname: "collide"}, // collides, must roll back
		{Hostname: "fresh-2"},
	}
	_, err = s.BulkCreate(ctx, in)
	assert.ErrorIs(t, err, hosts.ErrConflict)

	// Exactly the pre-existing host should be present; fresh-1 must
	// have been rolled back.
	all, err := s.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Equal(t, "collide", all[0].Hostname)
}
