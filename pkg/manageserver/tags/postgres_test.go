//go:build integration

package tags_test

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

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5432/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_tags_%d", testSchemaSeq.Add(1))
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

func TestTags_CreateListGetUpdateDelete(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	// Create — use a name not in the 13 built-in tags seeded by migration v19
	tag, err := s.Create(ctx, tags.Tag{Name: "z-test-tag", Color: "#EF4444"})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, tag.ID)
	assert.Equal(t, "z-test-tag", tag.Name)
	assert.Equal(t, "#EF4444", tag.Color)

	// List — includes HostCount; 13 built-in tags + 1 just created
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 14)
	var found *tags.Tag
	for i := range list {
		if list[i].ID == tag.ID {
			found = &list[i]
			break
		}
	}
	require.NotNil(t, found, "created tag must appear in list")
	assert.Equal(t, 0, found.HostCount)

	// Get
	got, err := s.Get(ctx, tag.ID)
	require.NoError(t, err)
	assert.Equal(t, tag.ID, got.ID)

	// Update
	updated, err := s.Update(ctx, tags.Tag{ID: tag.ID, Name: "prod", Color: "#22C55E"})
	require.NoError(t, err)
	assert.Equal(t, "prod", updated.Name)
	assert.Equal(t, "#22C55E", updated.Color)

	// Delete
	require.NoError(t, s.Delete(ctx, tag.ID))
	_, err = s.Get(ctx, tag.ID)
	assert.ErrorIs(t, err, tags.ErrNotFound)
	// 13 built-in tags remain after deleting the test tag
	listAfter, err := s.List(ctx)
	require.NoError(t, err)
	assert.Len(t, listAfter, 13)
}

func TestTags_DuplicateName_Conflict(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	_, err := s.Create(ctx, tags.Tag{Name: "alpha", Color: "#3B82F6"})
	require.NoError(t, err)

	_, err = s.Create(ctx, tags.Tag{Name: "alpha", Color: "#EF4444"})
	assert.ErrorIs(t, err, tags.ErrConflict)
}

func TestTags_GetNonExistent_NotFound(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	_, err := s.Get(context.Background(), uuid.New())
	assert.ErrorIs(t, err, tags.ErrNotFound)
}

func TestTags_Delete_NonExistent_NotFound(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	err := s.Delete(context.Background(), uuid.New())
	assert.ErrorIs(t, err, tags.ErrNotFound)
}

func TestTags_List_HostCount(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	// Use a name not in the 13 built-in tags seeded by migration v19
	tag, err := s.Create(ctx, tags.Tag{Name: "z-test-linux", Color: "#6366F1"})
	require.NoError(t, err)

	// Insert a host and assign the tag directly via SQL
	var hostID uuid.UUID
	err = pool.QueryRow(ctx,
		`INSERT INTO manage_hosts (ip, hostname, os) VALUES ('10.0.2.1'::inet, 'h1', 'linux') RETURNING id`,
	).Scan(&hostID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO manage_host_tags (host_id, tag_id) VALUES ($1, $2)`,
		hostID, tag.ID,
	)
	require.NoError(t, err)

	// 13 built-in tags + 1 test tag = 14 total; find the test tag by ID
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 14)
	var found *tags.Tag
	for i := range list {
		if list[i].ID == tag.ID {
			found = &list[i]
			break
		}
	}
	require.NotNil(t, found, "test tag must appear in list")
	assert.Equal(t, 1, found.HostCount)
}
