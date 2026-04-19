//go:build integration

package ca_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// testSchemaSeq generates unique per-test schema names.
var testSchemaSeq atomic.Int64

// newTestPool mirrors the isolation pattern in zones_test.go.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_ca_%d", testSchemaSeq.Add(1))

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

// insertAgent creates a parent row in manage_agents so we can insert a
// revocation (the revocation table FKs the agent id).
func insertAgent(t *testing.T, pool *pgxpool.Pool, serial string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_agents (id, name, cert_serial, cert_expires_at, status)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '365 days', 'pending')`,
		id, "test-agent", serial,
	)
	require.NoError(t, err)
	return id
}

func TestCAStore_Bootstrap_Idempotent(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)

	c1, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)
	require.NotNil(t, c1)

	c2, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)
	assert.Equal(t, c1.CACertPEM, c2.CACertPEM, "Bootstrap must return the same CA on repeat calls")
	assert.Equal(t, c1.CAKeyPEM, c2.CAKeyPEM)
}

func TestCAStore_Load_NotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)

	_, err := s.Load(ctx)
	assert.ErrorIs(t, err, ca.ErrNotFound)
}

func TestCAStore_Revoke_IsRevoked_Cached(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)

	_, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)

	serial := "deadbeefcafebabe"
	agentID := insertAgent(t, pool, serial)

	// Not yet revoked.
	revoked, err := s.IsRevoked(ctx, serial)
	require.NoError(t, err)
	assert.False(t, revoked)

	// Revoke + immediate IsRevoked must return true because Revoke
	// invalidates the cache proactively.
	require.NoError(t, s.Revoke(ctx, serial, agentID, "test"))
	revoked, err = s.IsRevoked(ctx, serial)
	require.NoError(t, err)
	assert.True(t, revoked, "IsRevoked must reflect Revoke immediately without waiting 30s")
}

func TestCAStore_Revoke_Idempotent(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)
	_, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)

	serial := "abc123"
	agentID := insertAgent(t, pool, serial)
	require.NoError(t, s.Revoke(ctx, serial, agentID, "first"))
	require.NoError(t, s.Revoke(ctx, serial, agentID, "second"), "duplicate revoke must be a no-op")
}

func TestCAStore_RefreshRevocationCache_PicksUpExternalWrite(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)
	_, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)

	serial := "beef1234"
	agentID := insertAgent(t, pool, serial)

	// Prime the cache with an empty read.
	revoked, err := s.IsRevoked(ctx, serial)
	require.NoError(t, err)
	require.False(t, revoked)

	// Insert a revocation directly (simulating another process).
	_, err = pool.Exec(ctx,
		`INSERT INTO manage_agent_cert_revocations (cert_serial, agent_id, revoke_reason)
		 VALUES ($1, $2, $3)`,
		serial, agentID, "external",
	)
	require.NoError(t, err)

	// Forcing a refresh should pick it up (tests the direct-refresh path
	// rather than waiting 30s for the TTL).
	require.NoError(t, s.RefreshRevocationCache(ctx))
	revoked, err = s.IsRevoked(ctx, serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestCAStore_IssueServerCert_ChainValidates(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)

	caBundle, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)

	pair, err := s.IssueServerCert(ctx, "127.0.0.1")
	require.NoError(t, err)
	require.Len(t, pair.Certificate, 1, "server pair should carry exactly one leaf cert")

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", leaf.Subject.CommonName)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Len(t, leaf.IPAddresses, 1, "IP-literal hostname populates IPAddresses, not DNSNames")
	assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), leaf.NotAfter, 24*time.Hour)

	// Chain must verify against the CA.
	caBlock, _ := pem.Decode(caBundle.CACertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	pool2 := x509.NewCertPool()
	pool2.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool2,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "server leaf must chain to CA")
}

func TestCAStore_IssueServerCert_DNSName(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)
	_, err := s.Bootstrap(ctx, "inst-1")
	require.NoError(t, err)

	pair, err := s.IssueServerCert(ctx, "manage.example.com")
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"manage.example.com"}, leaf.DNSNames)
	assert.Empty(t, leaf.IPAddresses, "DNS-name hostname must not populate IPAddresses")
}

func TestCAStore_IssueServerCert_NoBootstrap(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := ca.NewPostgresStore(pool)

	_, err := s.IssueServerCert(ctx, "127.0.0.1")
	assert.ErrorIs(t, err, ca.ErrNotFound)
}
