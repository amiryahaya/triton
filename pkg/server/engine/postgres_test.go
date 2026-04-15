//go:build integration

package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

func setup(t *testing.T) (*PostgresStore, uuid.UUID) {
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

	trunc := func() {
		_, _ = ps.Pool().Exec(ctx, `TRUNCATE engines, engine_cas CASCADE`)
		_, _ = ps.Pool().Exec(ctx, `TRUNCATE inventory_tags, inventory_hosts, inventory_groups CASCADE`)
	}
	trunc()
	require.NoError(t, ps.TruncateAll(ctx))
	t.Cleanup(func() {
		trunc()
		_ = ps.TruncateAll(ctx)
		ps.Close()
	})

	orgID := uuid.Must(uuid.NewV7())
	_, err = ps.Pool().Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgID, "Org-"+orgID.String()[:8],
	)
	require.NoError(t, err)

	return NewPostgresStore(ps.Pool()), orgID
}

func newCA(t *testing.T) *CA {
	t.Helper()
	master := make([]byte, 32)
	_, err := rand.Read(master)
	require.NoError(t, err)
	ca, err := GenerateCA(master)
	require.NoError(t, err)
	return ca
}

func newFingerprint(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func TestPostgresStore_CAUpsertGet(t *testing.T) {
	s, orgID := setup(t)
	ctx := context.Background()

	ca := newCA(t)
	require.NoError(t, s.UpsertCA(ctx, orgID, ca))

	got, err := s.GetCA(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, ca.CACertPEM, got.CACertPEM)
	assert.Equal(t, ca.CAKeyEncrypted, got.CAKeyEncrypted)
	assert.Equal(t, ca.CAKeyNonce, got.CAKeyNonce)
}

func TestPostgresStore_CAUpsert_Idempotent(t *testing.T) {
	s, orgID := setup(t)
	ctx := context.Background()

	ca1 := newCA(t)
	ca2 := newCA(t)
	require.NoError(t, s.UpsertCA(ctx, orgID, ca1))
	require.NoError(t, s.UpsertCA(ctx, orgID, ca2))

	got, err := s.GetCA(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, ca2.CACertPEM, got.CACertPEM, "second upsert overwrites")
	assert.NotEqual(t, ca1.CACertPEM, got.CACertPEM)
}

func TestPostgresStore_CreateAndListEngines(t *testing.T) {
	s, orgID := setup(t)
	ctx := context.Background()

	e1 := Engine{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID,
		Label: "alpha", CertFingerprint: newFingerprint(t),
	}
	e2 := Engine{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID,
		Label: "bravo", CertFingerprint: newFingerprint(t),
	}
	_, err := s.CreateEngine(ctx, e1)
	require.NoError(t, err)
	_, err = s.CreateEngine(ctx, e2)
	require.NoError(t, err)

	list, err := s.ListEngines(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "alpha", list[0].Label, "ordered by label asc")
	assert.Equal(t, "bravo", list[1].Label)
	assert.Equal(t, StatusEnrolled, list[0].Status, "default status")
}

func TestPostgresStore_FirstSeenIsSingleUse(t *testing.T) {
	s, orgID := setup(t)
	ctx := context.Background()

	e := Engine{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID,
		Label: "engine-a", CertFingerprint: newFingerprint(t),
	}
	_, err := s.CreateEngine(ctx, e)
	require.NoError(t, err)

	first, err := s.RecordFirstSeen(ctx, e.ID, "10.0.0.7")
	require.NoError(t, err)
	assert.True(t, first, "first claim must succeed")

	second, err := s.RecordFirstSeen(ctx, e.ID, "10.0.0.7")
	require.NoError(t, err, "replay must not error")
	assert.False(t, second, "replay must report not-first")

	got, err := s.GetEngine(ctx, orgID, e.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusOnline, got.Status, "first-seen flips status to online")
	require.NotNil(t, got.FirstSeenAt)
	assert.Equal(t, "10.0.0.7", got.PublicIP.String())
}

func TestPostgresStore_GetByFingerprint_NotFound(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()

	_, err := s.GetEngineByFingerprint(ctx, "deadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPostgresStore_GetByFingerprint_Revoked(t *testing.T) {
	s, orgID := setup(t)
	ctx := context.Background()

	e := Engine{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID,
		Label: "to-revoke", CertFingerprint: newFingerprint(t),
	}
	_, err := s.CreateEngine(ctx, e)
	require.NoError(t, err)

	require.NoError(t, s.Revoke(ctx, orgID, e.ID))

	got, err := s.GetEngineByFingerprint(ctx, e.CertFingerprint)
	require.NoError(t, err, "revoked engines still resolve at the store layer")
	assert.Equal(t, StatusRevoked, got.Status)
	require.NotNil(t, got.RevokedAt)
}
