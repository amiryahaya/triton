package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/auth/sessioncache"
	"github.com/amiryahaya/triton/pkg/store"
)

// fakeJWTStore is a counting in-memory implementation of jwtAuthStore.
// It lets cache tests assert exactly how many DB round-trips a series
// of requests would have made.
type fakeJWTStore struct {
	user       *store.User
	session    *store.Session
	sessionErr error // if non-nil, GetSessionByHash returns this
	getUserN   atomic.Int64
	getSessN   atomic.Int64
}

func (f *fakeJWTStore) GetUser(_ context.Context, id string) (*store.User, error) {
	f.getUserN.Add(1)
	if f.user == nil || f.user.ID != id {
		return nil, &store.ErrNotFound{Resource: "user", ID: id}
	}
	// Return a copy so handler mutations cannot bleed into test state.
	u := *f.user
	return &u, nil
}

func (f *fakeJWTStore) GetSessionByHash(_ context.Context, _ string) (*store.Session, error) {
	f.getSessN.Add(1)
	if f.sessionErr != nil {
		return nil, f.sessionErr
	}
	if f.session == nil {
		return nil, &store.ErrNotFound{Resource: "session", ID: "?"}
	}
	s := *f.session
	return &s, nil
}

// newTestJWT builds a valid signed JWT + its sha256 hash for the cache key.
func newTestJWT(t *testing.T, priv ed25519.PrivateKey, sub, org string, exp time.Duration) (string, string) {
	t.Helper()
	claims := &auth.UserClaims{
		Jti:  "jti-" + sub,
		Sub:  sub,
		Org:  org,
		Role: "org_user",
		Name: "Test User",
	}
	tok, err := auth.SignJWT(claims, priv, exp)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	h := sha256.Sum256([]byte(tok))
	return tok, hex.EncodeToString(h[:])
}

func runJWTAuth(t *testing.T, pub ed25519.PublicKey, s jwtAuthStore, cache *sessioncache.SessionCache, token string) int {
	t.Helper()
	var gotStatus int
	handler := JWTAuth(pub, s, cache)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	gotStatus = rec.Code
	return gotStatus
}

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestJWTAuth_NilCache_AlwaysHitsDB(t *testing.T) {
	pub, priv := newKeyPair(t)
	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: &store.Session{ID: "s1", UserID: "u1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	token, _ := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	for i := 0; i < 3; i++ {
		if code := runJWTAuth(t, pub, fs, nil, token); code != http.StatusOK {
			t.Fatalf("request %d: status=%d, want 200", i, code)
		}
	}
	if got := fs.getSessN.Load(); got != 3 {
		t.Errorf("GetSessionByHash calls = %d, want 3 (nil cache)", got)
	}
	if got := fs.getUserN.Load(); got != 3 {
		t.Errorf("GetUser calls = %d, want 3 (nil cache)", got)
	}
}

func TestJWTAuth_CacheHitSkipsDB(t *testing.T) {
	pub, priv := newKeyPair(t)
	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: &store.Session{ID: "s1", UserID: "u1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})
	token, _ := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	// First request: miss, populates cache.
	if code := runJWTAuth(t, pub, fs, cache, token); code != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", code)
	}
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("after miss: GetSessionByHash = %d, want 1", got)
	}
	if got := fs.getUserN.Load(); got != 1 {
		t.Errorf("after miss: GetUser = %d, want 1", got)
	}

	// Next 5 requests: pure cache hits, zero additional DB calls.
	for i := 0; i < 5; i++ {
		if code := runJWTAuth(t, pub, fs, cache, token); code != http.StatusOK {
			t.Fatalf("cached request %d: status=%d, want 200", i, code)
		}
	}
	if got := fs.getSessN.Load(); got != 1 {
		t.Errorf("after hits: GetSessionByHash = %d, want 1 (still)", got)
	}
	if got := fs.getUserN.Load(); got != 1 {
		t.Errorf("after hits: GetUser = %d, want 1 (still)", got)
	}
	if s := cache.Stats(); s.Hits != 5 || s.Misses != 1 {
		t.Errorf("cache stats: hits=%d misses=%d, want 5/1", s.Hits, s.Misses)
	}
}

func TestJWTAuth_CacheExpiryForcesRefresh(t *testing.T) {
	pub, priv := newKeyPair(t)
	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: &store.Session{ID: "s1", UserID: "u1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: 20 * time.Millisecond})
	token, _ := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	runJWTAuth(t, pub, fs, cache, token)
	time.Sleep(30 * time.Millisecond)
	runJWTAuth(t, pub, fs, cache, token)

	if got := fs.getSessN.Load(); got != 2 {
		t.Errorf("after TTL expiry: GetSessionByHash = %d, want 2", got)
	}
}

func TestJWTAuth_CacheDeleteInvalidatesHit(t *testing.T) {
	pub, priv := newKeyPair(t)
	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: &store.Session{ID: "s1", UserID: "u1", TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)},
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})
	token, hash := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	runJWTAuth(t, pub, fs, cache, token) // populate
	cache.Delete(hash)
	runJWTAuth(t, pub, fs, cache, token)

	if got := fs.getSessN.Load(); got != 2 {
		t.Errorf("after Delete: GetSessionByHash = %d, want 2", got)
	}
}

func TestHandleFlushSessionCache(t *testing.T) {
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})
	cache.Put("a", sessioncache.Entry{UserID: "u1", OrgID: "o1", JWTExpiry: time.Now().Add(time.Minute)})
	cache.Put("b", sessioncache.Entry{UserID: "u2", OrgID: "o1", JWTExpiry: time.Now().Add(time.Minute)})
	srv := &Server{sessionCache: cache}

	rec := httptest.NewRecorder()
	srv.handleFlushSessionCache(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/flush", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len = %d, want 0", cache.Len())
	}
	// Response body should contain flushed count = 2.
	body := rec.Body.String()
	if !strings.Contains(body, `"flushed":2`) {
		t.Errorf("body=%q, want flushed:2", body)
	}
}

func TestHandleFlushSessionCache_NilCache(t *testing.T) {
	srv := &Server{sessionCache: nil}
	rec := httptest.NewRecorder()
	srv.handleFlushSessionCache(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/flush", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"flushed":0`) {
		t.Errorf("nil cache should report flushed:0, got %s", rec.Body.String())
	}
}

func TestJWTAuth_CacheNotPopulatedOnRevokedSession(t *testing.T) {
	pub, priv := newKeyPair(t)
	fs := &fakeJWTStore{
		user:    &store.User{ID: "u1", OrgID: "o1", Role: "org_user"},
		session: nil, // GetSessionByHash will return ErrNotFound
	}
	cache := sessioncache.New(sessioncache.Config{MaxEntries: 16, TTL: time.Minute})
	token, _ := newTestJWT(t, priv, "u1", "o1", 15*time.Minute)

	if code := runJWTAuth(t, pub, fs, cache, token); code != http.StatusUnauthorized {
		t.Fatalf("first: status=%d, want 401", code)
	}
	// A revoked session must NOT be cached — the next attempt must
	// still go to the DB so an admin who re-activates a session sees
	// it immediately, and so that negative caching doesn't leak.
	if code := runJWTAuth(t, pub, fs, cache, token); code != http.StatusUnauthorized {
		t.Fatalf("second: status=%d, want 401", code)
	}
	if got := fs.getSessN.Load(); got != 2 {
		t.Errorf("no negative cache: GetSessionByHash = %d, want 2", got)
	}
	if cache.Len() != 0 {
		t.Errorf("cache should be empty after two 401s, Len=%d", cache.Len())
	}
}
