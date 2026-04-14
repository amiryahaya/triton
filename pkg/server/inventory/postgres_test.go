//go:build integration

package inventory

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// testFixture provisions a fresh PostgresStore (for inventory) bound to a
// truncated DB, plus a seeded org + user used as FK parents. Skips if
// TRITON_TEST_DB_URL is unset AND the default local URL is unreachable.
type testFixture struct {
	Store  *PostgresStore
	OrgID  uuid.UUID
	UserID uuid.UUID
}

func setup(t *testing.T) *testFixture {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	ps, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	// Clean inventory_* (not covered by store.TruncateAll) in dependency
	// order before/after each test so FK parents can be deleted.
	truncInv := func() {
		_, _ = ps.Pool().Exec(ctx, `TRUNCATE inventory_tags, inventory_hosts, inventory_groups CASCADE`)
	}
	truncInv()
	require.NoError(t, ps.TruncateAll(ctx))
	t.Cleanup(func() {
		truncInv()
		_ = ps.TruncateAll(ctx)
		ps.Close()
	})

	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	// Seed parent rows required by inventory_* FKs.
	_, err = ps.Pool().Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgID, "Org-"+orgID.String()[:8],
	)
	require.NoError(t, err)

	_, err = ps.Pool().Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, role, password, must_change_password, created_at, updated_at)
		 VALUES ($1, $2, $3, 'Test User', 'org_admin', '$2a$10$x', false, NOW(), NOW())`,
		userID, orgID, userID.String()+"@test.com",
	)
	require.NoError(t, err)

	invStore := NewPostgresStore(ps.Pool())
	return &testFixture{Store: invStore, OrgID: orgID, UserID: userID}
}

func TestPostgresStore_CreateAndListGroups(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	g := Group{
		ID:        uuid.Must(uuid.NewV7()),
		OrgID:     f.OrgID,
		Name:      "production",
		CreatedBy: f.UserID,
	}
	created, err := f.Store.CreateGroup(ctx, g)
	require.NoError(t, err)
	assert.Equal(t, "production", created.Name)
	assert.False(t, created.CreatedAt.IsZero())

	list, err := f.Store.ListGroups(ctx, f.OrgID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "production", list[0].Name)
}

func TestPostgresStore_HostWithTags(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	g, err := f.Store.CreateGroup(ctx, Group{
		ID: uuid.Must(uuid.NewV7()), OrgID: f.OrgID, Name: "g1", CreatedBy: f.UserID,
	})
	require.NoError(t, err)

	h := Host{
		ID:       uuid.Must(uuid.NewV7()),
		OrgID:    f.OrgID,
		GroupID:  g.ID,
		Hostname: "host-a.example.com",
		Address:  net.ParseIP("10.0.0.5"),
		OS:       "linux",
		Mode:     "agentless",
	}
	created, err := f.Store.CreateHost(ctx, h)
	require.NoError(t, err)

	tags := []Tag{{Key: "env", Value: "prod"}, {Key: "team", Value: "sec"}}
	require.NoError(t, f.Store.SetTags(ctx, created.ID, tags))

	got, err := f.Store.GetHost(ctx, f.OrgID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "host-a.example.com", got.Hostname)
	assert.Equal(t, "10.0.0.5", got.Address.String())
	require.Len(t, got.Tags, 2)
	assert.Equal(t, "env", got.Tags[0].Key)
	assert.Equal(t, "prod", got.Tags[0].Value)
}

func TestPostgresStore_OrgScopingBlocksCrossTenant(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	// Seed a second org.
	orgB := uuid.Must(uuid.NewV7())
	_, err := f.Store.pool.Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgB, "OrgB-"+orgB.String()[:8],
	)
	require.NoError(t, err)

	g, err := f.Store.CreateGroup(ctx, Group{
		ID: uuid.Must(uuid.NewV7()), OrgID: f.OrgID, Name: "g-a", CreatedBy: f.UserID,
	})
	require.NoError(t, err)

	// Try to read it using the wrong org's ID.
	_, err = f.Store.GetGroup(ctx, orgB, g.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPostgresStore_AddressOnlyHostDedup(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	g, err := f.Store.CreateGroup(ctx, Group{
		ID: uuid.Must(uuid.NewV7()), OrgID: f.OrgID, Name: "g", CreatedBy: f.UserID,
	})
	require.NoError(t, err)

	h1 := Host{
		ID:      uuid.Must(uuid.NewV7()),
		OrgID:   f.OrgID,
		GroupID: g.ID,
		Address: net.ParseIP("192.168.1.10"),
		Mode:    "agentless",
	}
	_, err = f.Store.CreateHost(ctx, h1)
	require.NoError(t, err)

	h2 := Host{
		ID:      uuid.Must(uuid.NewV7()),
		OrgID:   f.OrgID,
		GroupID: g.ID,
		Address: net.ParseIP("192.168.1.10"),
		Mode:    "agentless",
	}
	_, err = f.Store.CreateHost(ctx, h2)
	require.Error(t, err, "expected partial-unique-index violation on duplicate address-only host")
}
