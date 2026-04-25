// security_fixes_test.go — unit tests for D6, D4/C1, D2 fixes.
// These tests use in-process fakes and do NOT require PostgreSQL.
package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/auth/sessioncache"
	"github.com/amiryahaya/triton/pkg/store"
)

// ─── Fix D6: platform_admin bypasses session cache ────────────────────────────

// TestJWTAuth_CacheHit_PlatformAdmin_HitsDB verifies that a platform_admin
// with a valid cache entry still incurs a DB session check on every request
// (D6 fix). This ensures that session revocation for the highest-privilege
// role is always immediate rather than eventually-consistent.
func TestJWTAuth_CacheHit_PlatformAdmin_HitsDB(t *testing.T) {
	pub, priv := newKeyPair(t)

	claims := &auth.UserClaims{
		Sub:  "admin-1",
		Role: "platform_admin",
		Name: "Platform Admin",
	}
	tok, err := auth.SignJWT(claims, priv, time.Hour)
	require.NoError(t, err)

	fs := &fakeJWTStore{
		user:    &store.User{ID: "admin-1", Role: "platform_admin"},
		session: &store.Session{ID: "s1", UserID: "admin-1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})

	// First request: cache miss → DB hit → entry put into cache.
	if code := runJWTAuth(t, pub, fs, cache, tok); code != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", code)
	}
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("after first (miss): GetSessionByHash = %d, want 1", got)
	}

	// Second request: cache has a platform_admin entry, but D6 fix requires
	// that GetSessionByHash is still called (not skipped by the cache).
	if code := runJWTAuth(t, pub, fs, cache, tok); code != http.StatusOK {
		t.Fatalf("second request: status=%d, want 200", code)
	}
	if got := fs.getSessN.Load(); got != 2 {
		t.Errorf("after second (platform_admin should bypass cache): GetSessionByHash = %d, want 2", got)
	}

	// Third request: consistent — always hits DB for platform_admin.
	if code := runJWTAuth(t, pub, fs, cache, tok); code != http.StatusOK {
		t.Fatalf("third request: status=%d, want 200", code)
	}
	if got := fs.getSessN.Load(); got != 3 {
		t.Errorf("after third: GetSessionByHash = %d, want 3", got)
	}
}

// TestJWTAuth_CacheHit_OrgUser_SkipsDB confirms that the D6 change does not
// regress regular org users — their cache hits must still skip the DB.
func TestJWTAuth_CacheHit_OrgUser_SkipsDB(t *testing.T) {
	pub, priv := newKeyPair(t)

	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: &store.Session{ID: "s1", UserID: "u1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})
	token, _ := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	// First: cache miss → DB called.
	runJWTAuth(t, pub, fs, cache, token)
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("after miss: GetSessionByHash = %d, want 1", got)
	}

	// Subsequent requests: cache hit for org_user → DB not called.
	for i := 0; i < 3; i++ {
		if code := runJWTAuth(t, pub, fs, cache, token); code != http.StatusOK {
			t.Fatalf("cached request %d: status=%d, want 200", i, code)
		}
	}
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("after cache hits: GetSessionByHash = %d, want 1 (D6 must not regress org users)", got)
	}
}

// TestJWTAuth_PlatformAdmin_RevokedSessionRejected verifies that a revoked
// platform_admin session is rejected even though there may be a cached entry.
// Because the D6 fix forces platform_admin through the full DB path, a
// sessionErr is detected and the request is returned 401.
func TestJWTAuth_PlatformAdmin_RevokedSessionRejected(t *testing.T) {
	pub, priv := newKeyPair(t)

	claims := &auth.UserClaims{
		Sub:  "admin-2",
		Role: "platform_admin",
		Name: "Platform Admin",
	}
	tok, err := auth.SignJWT(claims, priv, time.Hour)
	require.NoError(t, err)

	// GetSessionByHash always returns ErrNotFound — simulates a revoked session.
	fs := &fakeJWTStore{
		user:       &store.User{ID: "admin-2", Role: "platform_admin"},
		sessionErr: &store.ErrNotFound{Resource: "session", ID: "?"},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})

	if code := runJWTAuth(t, pub, fs, cache, tok); code != http.StatusUnauthorized {
		t.Fatalf("revoked platform_admin: status=%d, want 401", code)
	}
	// DB must have been called (not bypassed via any cache short-circuit).
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("GetSessionByHash = %d, want 1 (must not be bypassed)", got)
	}
}

// ─── Fix D4/C1: SetupGuard atomic skip ───────────────────────────────────────

// setupGuardMockStore embeds licenceMockStore and overrides ListUsers so the
// test controls the response without PostgreSQL.
type setupGuardMockStore struct {
	licenceMockStore
	listUsersFn func() ([]store.User, error)
	callCount   atomic.Int32
}

func (s *setupGuardMockStore) ListUsers(_ context.Context, _ store.UserFilter) ([]store.User, error) {
	s.callCount.Add(1)
	if s.listUsersFn != nil {
		return s.listUsersFn()
	}
	return nil, nil
}

// TestSetupGuard_SkipsDBAfterSetupComplete verifies that after the first
// request that confirms a platform_admin exists, subsequent requests skip the
// ListUsers DB query entirely.
func TestSetupGuard_SkipsDBAfterSetupComplete(t *testing.T) {
	ms := &setupGuardMockStore{
		listUsersFn: func() ([]store.User, error) {
			return []store.User{{ID: "admin-1", Role: "platform_admin"}}, nil
		},
	}
	srv := newServerWithMockStore(t, ms)

	handler := srv.SetupGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	makeRequest := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// First request: DB queried, admin found → setupComplete set.
	assert.Equal(t, http.StatusOK, makeRequest())
	assert.Equal(t, int32(1), ms.callCount.Load(), "first request must query DB")

	// Second request: setupComplete=true, DB must be skipped.
	assert.Equal(t, http.StatusOK, makeRequest())
	assert.Equal(t, int32(1), ms.callCount.Load(), "second request must skip DB query")

	// Third: still skipped.
	assert.Equal(t, http.StatusOK, makeRequest())
	assert.Equal(t, int32(1), ms.callCount.Load(), "all subsequent requests must skip DB query")

	assert.True(t, srv.setupComplete.Load(), "setupComplete must be set")
}

// TestSetupGuard_RedirectsWhenNoAdmin verifies that when no admin exists,
// non-setup paths are redirected to /ui/ and setupComplete stays false.
func TestSetupGuard_RedirectsWhenNoAdmin(t *testing.T) {
	ms := &setupGuardMockStore{
		listUsersFn: func() ([]store.User, error) {
			return nil, nil // no platform_admin yet
		},
	}
	srv := newServerWithMockStore(t, ms)

	handler := srv.SetupGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler must not be called when setup is incomplete")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	assert.Equal(t, "/ui/", rec.Header().Get("Location"))
	assert.False(t, srv.setupComplete.Load(), "setupComplete must remain false when no admin")
}

// TestSetupGuard_SetupPathsBypassGuard verifies that setup/auth/health paths
// are always let through without touching the DB, even before setup.
func TestSetupGuard_SetupPathsBypassGuard(t *testing.T) {
	ms := &setupGuardMockStore{
		listUsersFn: func() ([]store.User, error) {
			t.Fatal("ListUsers must not be called for setup/auth/health paths")
			return nil, nil
		},
	}
	srv := newServerWithMockStore(t, ms)

	handler := srv.SetupGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{
		"/api/v1/setup/status",
		"/api/v1/setup",
		"/ui/index.html",
		"/api/v1/auth/login",
		"/api/v1/health",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "setup path %q must bypass guard", path)
	}
}

// ─── Fix D2: classifyActivationError does not leak raw msg ───────────────────

// activationTestErr is a minimal error type for classifyActivationError tests.
type activationTestErr struct{ msg string }

func (e *activationTestErr) Error() string { return e.msg }

func TestClassifyActivationError_GenericDenialIsOpaque(t *testing.T) {
	err := &activationTestErr{"activation denied: some internal portal detail leaked"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	// Must return the safe generic message, not the raw portal error (D2 fix).
	assert.Equal(t, "licence activation denied", msg)
	assert.NotContains(t, msg, "internal portal detail")
}

func TestClassifyActivationError_RevokedIsOpaque(t *testing.T) {
	err := &activationTestErr{"activation denied: revoked reason=policy-violation extra=detail"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "licence revoked", msg)
}

func TestClassifyActivationError_ExpiredIsOpaque(t *testing.T) {
	err := &activationTestErr{"activation denied: expired on 2025-01-01T00:00:00Z"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "licence expired", msg)
}

func TestClassifyActivationError_NoSeats(t *testing.T) {
	err := &activationTestErr{"no seats available"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "no seats available", msg)
}

func TestClassifyActivationError_NotFound(t *testing.T) {
	err := &activationTestErr{"licence not found"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "licence not found", msg)
}

func TestClassifyActivationError_ServerUnavailable(t *testing.T) {
	err := &activationTestErr{"connection refused to portal"}
	status, msg := classifyActivationError(err)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "licence server unavailable", msg)
}
