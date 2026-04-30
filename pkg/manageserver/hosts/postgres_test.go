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

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5432/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_hosts_%d", testSchemaSeq.Add(1))
	ctx := context.Background()
	setup, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	_, _ = setup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	_, err = setup.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	setup.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		c, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

func insertTag(t *testing.T, pool *pgxpool.Pool, name, color string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO manage_tags (name, color) VALUES ($1, $2) RETURNING id`, name, color,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestHosts_CreateListGetDelete(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	h, err := s.Create(ctx, hosts.Host{IP: "10.0.1.1", Hostname: "web-01", OS: "linux"})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, h.ID)
	assert.Empty(t, h.Tags)

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "web-01", list[0].Hostname)

	got, err := s.Get(ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, h.ID, got.ID)

	require.NoError(t, s.Delete(ctx, h.ID))
	_, err = s.Get(ctx, h.ID)
	assert.ErrorIs(t, err, hosts.ErrNotFound)
}

func TestHosts_SetTags_AndListByTags(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	tagID := insertTag(t, pool, "test-tag", "#EF4444")
	h, err := s.Create(ctx, hosts.Host{IP: "10.0.1.2", Hostname: "db-01", OS: "linux"})
	require.NoError(t, err)

	require.NoError(t, s.SetTags(ctx, h.ID, []uuid.UUID{tagID}))

	// List shows tag on host
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list[0].Tags, 1)
	assert.Equal(t, "test-tag", list[0].Tags[0].Name)

	// ListByTags (OR — single tag)
	tagged, err := s.ListByTags(ctx, []uuid.UUID{tagID})
	require.NoError(t, err)
	require.Len(t, tagged, 1)
	assert.Equal(t, h.ID, tagged[0].ID)

	// CountByTag
	n, err := s.CountByTag(ctx, tagID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// Replace tags (SetTags idempotent)
	require.NoError(t, s.SetTags(ctx, h.ID, []uuid.UUID{}))
	list, err = s.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list[0].Tags)
}

func TestHosts_ResolveTagNames_CreatesIfMissing(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	// "linux" doesn't exist yet
	ids, err := s.ResolveTagNames(ctx, []string{"linux", "prod"}, "#6366F1")
	require.NoError(t, err)
	assert.Len(t, ids, 2)

	// Calling again returns same IDs (idempotent)
	ids2, err := s.ResolveTagNames(ctx, []string{"linux"}, "#6366F1")
	require.NoError(t, err)
	assert.Equal(t, ids[0], ids2[0])
}

func TestHosts_UniqueIP(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()
	_, _ = s.Create(ctx, hosts.Host{IP: "10.0.1.10", Hostname: "web-01"})
	_, err := s.Create(ctx, hosts.Host{IP: "10.0.1.10", Hostname: "web-02"})
	assert.ErrorIs(t, err, hosts.ErrConflict)
}

func TestHosts_BulkCreate(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	batch := []hosts.Host{
		{IP: "10.0.1.20", Hostname: "a", OS: "linux"},
		{IP: "10.0.1.21", Hostname: "b", OS: "linux"},
	}
	out, err := s.BulkCreate(ctx, batch)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.NotEqual(t, uuid.Nil, out[0].ID)
}

func TestHosts_BulkCreate_Conflict_RollsBack(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()
	_, _ = s.Create(ctx, hosts.Host{IP: "10.0.1.30", Hostname: "dup"})
	_, err := s.BulkCreate(ctx, []hosts.Host{
		{IP: "10.0.1.31", Hostname: "ok"},
		{IP: "10.0.1.30", Hostname: "dup2"}, // same IP as existing
	})
	assert.ErrorIs(t, err, hosts.ErrConflict)
	// "ok" should not have been created
	list, _ := s.List(ctx)
	for _, h := range list {
		assert.NotEqual(t, "10.0.1.31", h.IP)
	}
}

func TestGetByIDs(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	h1, err := s.Create(ctx, hosts.Host{Hostname: "alpha", IP: "10.0.0.1"})
	require.NoError(t, err)
	h2, err := s.Create(ctx, hosts.Host{Hostname: "beta", IP: "10.0.0.2"})
	require.NoError(t, err)
	_, err = s.Create(ctx, hosts.Host{Hostname: "gamma", IP: "10.0.0.3"})
	require.NoError(t, err)

	got, err := s.GetByIDs(ctx, []uuid.UUID{h1.ID, h2.ID})
	require.NoError(t, err)
	require.Len(t, got, 2)
	gotIDs := []uuid.UUID{got[0].ID, got[1].ID}
	assert.Contains(t, gotIDs, h1.ID)
	assert.Contains(t, gotIDs, h2.ID)

	// empty input returns empty slice without error
	none, err := s.GetByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, none)
}
