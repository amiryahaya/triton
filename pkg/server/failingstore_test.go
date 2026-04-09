//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// failingStore wraps a real *PostgresStore and lets specific methods be
// toggled to return errors mid-test. Used to exercise handler error paths
// that aren't reachable via the normal client flow.
//
// Pattern: create the underlying store via testServerWithJWT, wrap it,
// rebuild a new server with the wrapper, and toggle errors after setup.
type failingStore struct {
	*store.PostgresStore
	listUsersFails atomic.Bool
}

func newFailingStore(real *store.PostgresStore) *failingStore {
	return &failingStore{PostgresStore: real}
}

// ListUsers returns a sentinel error when the toggle is set; otherwise
// it forwards to the underlying real store. Used to test error-path
// behavior in handlers that call ListUsers (e.g., the last-org-admin
// guard in handleDeleteUser).
func (f *failingStore) ListUsers(ctx context.Context, filter store.UserFilter) ([]store.User, error) {
	if f.listUsersFails.Load() {
		return nil, errors.New("simulated ListUsers failure")
	}
	return f.PostgresStore.ListUsers(ctx, filter)
}

// setupServerWithFailingStore returns a server backed by the failing
// store wrapper plus a fresh JWT keypair. The wrapper itself is returned
// so tests can toggle failures mid-flow.
func setupServerWithFailingStore(t *testing.T) (*Server, *store.PostgresStore, *failingStore) {
	t.Helper()
	_, real := testServer(t) // returns a fresh truncated store
	wrap := newFailingStore(real)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := &Config{
		ListenAddr:    ":0",
		JWTSigningKey: priv,
		JWTPublicKey:  pub,
	}
	srv, err := New(cfg, wrap)
	require.NoError(t, err)
	t.Cleanup(func() {
		ts := httptest.NewServer(srv.Router())
		ts.Close()
	})
	return srv, real, wrap
}
