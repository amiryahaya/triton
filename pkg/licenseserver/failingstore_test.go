//go:build integration

package licenseserver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// setupTestServerWithStore builds a license server using the provided store
// (typically a wrapper around a real *PostgresStore) and registers the
// httptest.Server with t.Cleanup. Use this when you need a server that
// dispatches through a test wrapper (e.g., failingStore) for error-path
// coverage that isn't reachable via the normal flow.
func setupTestServerWithStore(t *testing.T, store licensestore.Store) *httptest.Server {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: t.TempDir(),
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(func() { ts.Close() })
	return ts
}

// failingStore wraps a real *PostgresStore and lets specific methods be
// toggled to return errors mid-test. This enables unit tests for handler
// error paths that aren't reachable via normal client flows — e.g., what
// handleLogout does when DeleteSession fails after a successful login.
//
// Usage pattern:
//
//	realTs, store := setupTestServer(t)
//	wrap := newFailingStore(store)
//	failTs := newServerWithStore(t, wrap)
//	// 1. Use realTs to do setup that needs the un-failing store
//	// 2. Toggle a failure: wrap.deleteSessionFails.Store(true)
//	// 3. Use failTs to exercise the failing path
//
// The wrapper embeds *PostgresStore so it satisfies licensestore.Store
// without forwarding every method by hand.
type failingStore struct {
	*licensestore.PostgresStore
	deleteSessionFails atomic.Bool
}

func newFailingStore(real *licensestore.PostgresStore) *failingStore {
	return &failingStore{PostgresStore: real}
}

// DeleteSession returns a sentinel error when the toggle is set; otherwise
// it forwards to the underlying real store.
func (f *failingStore) DeleteSession(ctx context.Context, id string) error {
	if f.deleteSessionFails.Load() {
		return errors.New("simulated DeleteSession failure")
	}
	return f.PostgresStore.DeleteSession(ctx, id)
}
