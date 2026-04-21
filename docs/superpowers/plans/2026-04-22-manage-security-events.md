# Manage Security Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the in-memory login rate-limiter state as an admin REST API (`GET/DELETE /admin/security-events`) and a Security view in the Manage Portal so operators can see and clear active lockouts.

**Architecture:** The `loginRateLimiter` gains a clock abstraction (testable `now` field) plus two new methods — `ActiveLockouts()` returning a sorted snapshot and `Clear(email, ip)` for manual unlock. Two new HTTP handlers wrap these methods and are mounted inside the existing `RequireRole("admin")` group. The frontend adds a Pinia store, a Security.vue view, and a nav entry that mirror the Users pattern exactly.

**Tech Stack:** Go 1.25 / chi/v5 (backend), Vue 3 + Pinia + Vitest / `@vue/test-utils` (frontend), pnpm monorepo, `//go:build integration` for handler tests, no build tag for rate-limiter unit tests.

---

## File Map

| File | Action |
|---|---|
| `pkg/manageserver/rate_limit.go` | Modify — add `now` field, `Lockout` type, `ActiveLockouts()`, `Clear()`, `setNowForTest()` |
| `pkg/manageserver/rate_limit_test.go` | Create — 7 unit tests (no integration tag) |
| `pkg/manageserver/handlers_security.go` | Create — `handleListSecurityEvents` + `handleClearSecurityEvent` |
| `pkg/manageserver/server.go` | Modify — mount two routes inside admin-only group |
| `pkg/manageserver/handlers_security_test.go` | Create — 6 integration tests |
| `web/packages/api-client/src/manageServer.types.ts` | Modify — add `Lockout` + `SecurityEventsResponse` |
| `web/packages/api-client/src/manageServer.ts` | Modify — add `listLockouts()` + `clearLockout()` |
| `web/packages/api-client/tests/manageServer.test.ts` | Modify — add 2 api-client tests |
| `web/apps/manage-portal/src/stores/security.ts` | Create — `useSecurityStore` |
| `web/apps/manage-portal/src/views/Security.vue` | Create — table + unlock + refresh |
| `web/apps/manage-portal/tests/views/Security.spec.ts` | Create — 4 Vitest component tests |
| `web/apps/manage-portal/src/nav.ts` | Modify — add Security entry to Admin section |
| `web/apps/manage-portal/src/router.ts` | Modify — add `/admin/security` route |
| `web/apps/manage-portal/src/App.vue` | Modify — add `security: 'Security'` to crumb labels |

---

## Task 1: Rate limiter — clock abstraction + Lockout type + ActiveLockouts + Clear (TDD)

**Files:**
- Modify: `pkg/manageserver/rate_limit.go`
- Create: `pkg/manageserver/rate_limit_test.go`

The rate limiter currently calls `time.Now()` directly inside `Locked` and `Record`. This task adds a `now func() time.Time` field (defaults to `time.Now`) so tests can inject a deterministic clock, then adds the `Lockout` type and two new methods.

- [ ] **Step 1: Write the failing tests**

Create `pkg/manageserver/rate_limit_test.go`:

```go
package manageserver

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLimiter returns a limiter with a fixed clock anchored at base.
// tick is a pointer the caller can advance before calling Record.
func newTestLimiter(base time.Time) (*loginRateLimiter, *time.Time) {
	tick := base
	l := newLoginRateLimiter()
	l.setNowForTest(func() time.Time { return tick })
	return l, &tick
}

func TestActiveLockouts_ReturnsOnlyOverThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	// Record 3 failures for user-a — under threshold (max=5).
	for i := 0; i < 3; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.1.1.1")
	}
	// Record 5 failures for user-b — at threshold.
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("b@example.com", "2.2.2.2")
	}

	out := l.ActiveLockouts()
	require.Len(t, out, 1, "only b should be locked")
	assert.Equal(t, "b@example.com", out[0].Email)
}

func TestActiveLockouts_PrunesExpired(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("user@example.com", "1.2.3.4")
	}
	// Advance clock past the 15-minute window.
	*tick = base.Add(16 * time.Minute)

	out := l.ActiveLockouts()
	assert.Empty(t, out, "all failures expired — no lockout")
}

func TestActiveLockouts_FieldsPopulated(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.2.3.4")
	}
	// Clock still at base+4s when ActiveLockouts is called.

	out := l.ActiveLockouts()
	require.Len(t, out, 1)
	got := out[0]
	assert.Equal(t, "a@example.com", got.Email)
	assert.Equal(t, "1.2.3.4", got.IP)
	assert.Equal(t, 5, got.Failures)
	assert.Equal(t, base, got.FirstFailure)
	assert.Equal(t, base.Add(4*time.Second), got.LastFailure)
	assert.Equal(t, base.Add(l.window), got.LockedUntil)
}

func TestActiveLockouts_SortedByLockedUntilDesc(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	// a's first failure at base — LockedUntil = base+15min
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.1.1.1")
	}
	// b's first failure at base+1min — LockedUntil = base+16min (fresher)
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Minute + time.Duration(i)*time.Second)
		l.Record("b@example.com", "2.2.2.2")
	}

	out := l.ActiveLockouts()
	require.Len(t, out, 2)
	assert.Equal(t, "b@example.com", out[0].Email, "b has fresher LockedUntil — should be first")
	assert.Equal(t, "a@example.com", out[1].Email)
}

func TestClear_RemovesEntry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("user@example.com", "1.2.3.4")
	}
	require.Len(t, l.ActiveLockouts(), 1)

	cleared := l.Clear("user@example.com", "1.2.3.4")
	assert.True(t, cleared)
	assert.Empty(t, l.ActiveLockouts())
}

func TestClear_MissingEntryReturnsFalse(t *testing.T) {
	l := newLoginRateLimiter()
	cleared := l.Clear("nobody@example.com", "0.0.0.0")
	assert.False(t, cleared)
}

func TestActiveLockouts_IsConcurrencySafe(t *testing.T) {
	l := newLoginRateLimiter()
	for i := 0; i < 5; i++ {
		l.Record("user@example.com", "127.0.0.1")
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = l.ActiveLockouts()
		}()
		go func() {
			defer wg.Done()
			l.Record("other@example.com", "10.0.0.1")
		}()
		go func() {
			defer wg.Done()
			_ = l.Clear("other@example.com", "10.0.0.1")
		}()
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events
go test -v -run 'TestActiveLockouts|TestClear' ./pkg/manageserver/
```

Expected: FAIL — `l.setNowForTest undefined`, `l.window undefined`, `l.ActiveLockouts undefined`, `l.Clear undefined`, `Lockout type undefined`

- [ ] **Step 3: Implement clock abstraction, Lockout, ActiveLockouts, Clear, setNowForTest**

Replace the entire contents of `pkg/manageserver/rate_limit.go`:

```go
package manageserver

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Lockout is the serialisable snapshot of one (email, IP) pair currently
// over the failure threshold.
type Lockout struct {
	Email        string    `json:"email"`
	IP           string    `json:"ip"`
	Failures     int       `json:"failures"`
	FirstFailure time.Time `json:"first_failure"`
	LastFailure  time.Time `json:"last_failure"`
	LockedUntil  time.Time `json:"locked_until"`
}

// loginRateLimiter tracks failed login attempts per (email, IP) pair.
// It is intentionally in-memory and non-persistent — a restart resets
// the counters, which is acceptable for the Manage Server's threat model.
type loginRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = email+"|"+ip
	window   time.Duration
	max      int
	now      func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		failures: make(map[string][]time.Time),
		window:   15 * time.Minute,
		max:      5,
		now:      time.Now,
	}
}

// Locked returns true if the (email, ip) pair has exceeded the failure
// threshold within the sliding window. It prunes expired entries inline.
func (l *loginRateLimiter) Locked(email, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	cutoff := l.now().Add(-l.window)
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.failures[key] = kept
	return len(kept) >= l.max
}

// Record appends a failure timestamp for the given (email, ip) pair.
func (l *loginRateLimiter) Record(email, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	l.failures[key] = append(l.failures[key], l.now())
}

// ActiveLockouts returns a snapshot of all (email, IP) pairs currently
// over the failure threshold. Prunes expired entries inline (same
// semantics as Locked). Returned slice is freshly allocated — safe to
// mutate by the caller. Results are sorted by LockedUntil DESC.
func (l *loginRateLimiter) ActiveLockouts() []Lockout {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.window)
	var out []Lockout
	for k, ts := range l.failures {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		l.failures[k] = kept
		if len(kept) < l.max {
			continue
		}
		idx := strings.Index(k, "|")
		out = append(out, Lockout{
			Email:        k[:idx],
			IP:           k[idx+1:],
			Failures:     len(kept),
			FirstFailure: kept[0],
			LastFailure:  kept[len(kept)-1],
			LockedUntil:  kept[0].Add(l.window),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LockedUntil.After(out[j].LockedUntil)
	})
	return out
}

// Clear removes the tracked failures for the given (email, IP) pair.
// Returns true if the entry existed, false otherwise.
func (l *loginRateLimiter) Clear(email, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	if _, exists := l.failures[key]; !exists {
		return false
	}
	delete(l.failures, key)
	return true
}

// setNowForTest replaces the clock function for deterministic tests.
// Never called in production code.
func (l *loginRateLimiter) setNowForTest(fn func() time.Time) {
	l.now = fn
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test -v -run 'TestActiveLockouts|TestClear' ./pkg/manageserver/
```

Expected: All 7 tests PASS. If the race detector is available:

```bash
go test -v -race -run 'TestActiveLockouts|TestClear' ./pkg/manageserver/
```

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/rate_limit.go pkg/manageserver/rate_limit_test.go
git commit -m "feat(manage): rate limiter clock abstraction + Lockout + ActiveLockouts + Clear"
```

---

## Task 2: Backend handlers + route wiring

**Files:**
- Create: `pkg/manageserver/handlers_security.go`
- Modify: `pkg/manageserver/server.go` (inside the `RequireRole("admin")` group)

- [ ] **Step 1: Create the security handlers**

Create `pkg/manageserver/handlers_security.go`:

```go
package manageserver

import (
	"net/http"
)

// handleListSecurityEvents returns the current set of active (email, IP)
// login lockouts.
// GET /api/v1/admin/security-events
// Response: {"active_lockouts": [...]} — empty slice, never null. 200 always.
func (s *Server) handleListSecurityEvents(w http.ResponseWriter, r *http.Request) {
	lockouts := s.loginLimiter.ActiveLockouts()
	if lockouts == nil {
		lockouts = []Lockout{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_lockouts": lockouts,
	})
}

// handleClearSecurityEvent removes the lockout for one (email, IP) pair.
// DELETE /api/v1/admin/security-events?email=<email>&ip=<ip>
// 204 on success, 404 if the entry does not exist, 400 if params missing.
func (s *Server) handleClearSecurityEvent(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	ip := r.URL.Query().Get("ip")
	if email == "" || ip == "" {
		writeError(w, http.StatusBadRequest, "email and ip query parameters are required")
		return
	}
	if !s.loginLimiter.Clear(email, ip) {
		writeError(w, http.StatusNotFound, "no active lockout for the given email and ip")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 2: Mount the routes inside the admin-only group in server.go**

Open `pkg/manageserver/server.go`. Find the `RequireRole("admin")` group (around line 279). It currently looks like:

```go
r.Group(func(r chi.Router) {
    r.Use(RequireRole("admin"))
    r.Route("/users", func(r chi.Router) {
        r.Get("/", s.handleListUsers)
        r.Post("/", s.handleCreateUser)
        r.Delete("/{id}", s.handleDeleteUser)
    })
    r.Route("/enrol", func(r chi.Router) { agents.MountEnrolRoutes(r, s.agentsAdmin) })
})
```

Add the two security-events routes **inside** the same group, after the `/enrol` route:

```go
r.Group(func(r chi.Router) {
    r.Use(RequireRole("admin"))
    r.Route("/users", func(r chi.Router) {
        r.Get("/", s.handleListUsers)
        r.Post("/", s.handleCreateUser)
        r.Delete("/{id}", s.handleDeleteUser)
    })
    r.Route("/enrol", func(r chi.Router) { agents.MountEnrolRoutes(r, s.agentsAdmin) })
    r.Get("/security-events", s.handleListSecurityEvents)
    r.Delete("/security-events", s.handleClearSecurityEvent)
})
```

- [ ] **Step 3: Build to verify compilation**

```bash
go build ./pkg/manageserver/...
```

Expected: Exits 0, no errors.

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/handlers_security.go pkg/manageserver/server.go
git commit -m "feat(manage): security-events handlers + route wiring"
```

---

## Task 3: Handler integration tests

**Files:**
- Create: `pkg/manageserver/handlers_security_test.go`

This file is integration-tagged (`//go:build integration`) and lives in `package manageserver_test`. It reuses `openOperationalServer`, `seedAdminUser`, `loginViaHTTP`, and `seedExtraUser` from `middleware_test.go` and `handlers_users_test.go`.

- [ ] **Step 1: Create the integration test file**

Create `pkg/manageserver/handlers_security_test.go`:

```go
//go:build integration

package manageserver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedLockout drives count bad-password login attempts for the given email
// against the test server to populate the in-memory rate limiter.
func seedLockout(t *testing.T, serverURL, email string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		body, _ := json.Marshal(map[string]string{
			"email":    email,
			"password": "definitely-wrong-password",
		})
		resp, err := http.Post(serverURL+"/api/v1/auth/login",
			"application/json", bytes.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
	}
}

// TestSecurityEvents_ListReturnsActiveLockouts: seed 6 bad logins, GET
// /admin/security-events, assert the locked (email, IP) appears in the list.
func TestSecurityEvents_ListReturnsActiveLockouts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Trigger lockout: 6 bad-password attempts (threshold is 5).
	seedLockout(t, ts.URL, admin.Email, 6)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		ActiveLockouts []map[string]any `json:"active_lockouts"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.ActiveLockouts)
	assert.Equal(t, admin.Email, out.ActiveLockouts[0]["email"])
}

// TestSecurityEvents_ListEmptyWhenNoLockouts: fresh server, GET returns
// {"active_lockouts": []} — never null.
func TestSecurityEvents_ListEmptyWhenNoLockouts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		ActiveLockouts []map[string]any `json:"active_lockouts"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.NotNil(t, out.ActiveLockouts, "active_lockouts must not be null")
	assert.Empty(t, out.ActiveLockouts)
}

// TestSecurityEvents_NonAdminRejected: network_engineer caller gets 403.
func TestSecurityEvents_NonAdminRejected(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	_ = seedAdminUser(t, store)
	engEmail := fmt.Sprintf("eng-sec-%d@example.com", serverTestSeq.Add(1))
	seedExtraUser(t, store, engEmail, "network_engineer")
	token := loginViaHTTP(t, ts.URL, engEmail, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurityEvents_ClearRemovesLockout: after triggering a lockout,
// DELETE /admin/security-events clears it, subsequent login succeeds.
func TestSecurityEvents_ClearRemovesLockout(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Trigger lockout.
	seedLockout(t, ts.URL, admin.Email, 6)

	// Confirm the user is now locked out.
	lockedBody, _ := json.Marshal(map[string]string{
		"email": admin.Email, "password": "Password123!",
	})
	lockResp, err := http.Post(ts.URL+"/api/v1/auth/login",
		"application/json", bytes.NewReader(lockedBody))
	require.NoError(t, err)
	lockResp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, lockResp.StatusCode, "user should be locked")

	// Clear lockout. httptest.Server uses loopback so the IP is 127.0.0.1.
	deleteURL := ts.URL + "/api/v1/admin/security-events?email=" +
		url.QueryEscape(admin.Email) + "&ip=127.0.0.1"
	delReq, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// User can now log in again.
	loginResp, err := http.Post(ts.URL+"/api/v1/auth/login",
		"application/json", bytes.NewReader(lockedBody))
	require.NoError(t, err)
	loginResp.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp.StatusCode, "user should be unlocked")
}

// TestSecurityEvents_ClearMissing404: DELETE with an unknown (email, IP)
// pair returns 404.
func TestSecurityEvents_ClearMissing404(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?email=nobody%40example.com&ip=9.9.9.9", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestSecurityEvents_ClearMissingQueryParams400: DELETE without email or
// ip returns 400.
func TestSecurityEvents_ClearMissingQueryParams400(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Missing ip param.
	req1, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?email=test%40example.com", nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)

	// Missing email param.
	req2, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?ip=1.2.3.4", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
}
```

- [ ] **Step 2: Run integration tests**

```bash
go test -v -tags integration -run 'TestSecurityEvents' ./pkg/manageserver/
```

Expected: All 6 tests PASS. If Postgres is not running locally this requires `TRITON_TEST_DB_URL` to be set.

- [ ] **Step 3: Commit**

```bash
git add pkg/manageserver/handlers_security_test.go
git commit -m "test(manage): integration tests for security-events handlers"
```

---

## Task 4: api-client — types + methods + tests

**Files:**
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/tests/manageServer.test.ts`

- [ ] **Step 1: Write the failing api-client tests first**

Append two new `it` blocks to the `describe('createManageApi', ...)` block in `web/packages/api-client/tests/manageServer.test.ts`:

```ts
  it('listLockouts GETs /v1/admin/security-events', async () => {
    await api.listLockouts();
    expect(fake.calls[0]).toEqual({ method: 'GET', path: '/v1/admin/security-events' });
  });

  it('clearLockout DELETEs /v1/admin/security-events with encoded email + ip', async () => {
    await api.clearLockout('user@example.com', '127.0.0.1');
    expect(fake.calls[0]).toEqual({
      method: 'DELETE',
      path: '/v1/admin/security-events?email=user%40example.com&ip=127.0.0.1',
    });
  });
```

Insert these two `it` blocks **before the closing** `});` of the `describe('createManageApi', ...)` block (before the `describe('enrolAgent (direct fetch)', ...)` block).

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events/web
pnpm --filter @triton/api-client test
```

Expected: FAIL — `api.listLockouts is not a function`, `api.clearLockout is not a function`

- [ ] **Step 3: Add types to manageServer.types.ts**

Append to the end of `web/packages/api-client/src/manageServer.types.ts`:

```ts
// Lockout mirrors pkg/manageserver.Lockout — one active (email, IP) pair
// over the login failure threshold.
export interface Lockout {
  email: string;
  ip: string;
  failures: number;
  first_failure: string;
  last_failure: string;
  locked_until: string;
}

// SecurityEventsResponse mirrors the body of GET /v1/admin/security-events.
export interface SecurityEventsResponse {
  active_lockouts: Lockout[];
}
```

- [ ] **Step 4: Add methods to manageServer.ts**

In `web/packages/api-client/src/manageServer.ts`:

1. Add `Lockout, SecurityEventsResponse` to the imports from `./manageServer.types`:

```ts
import type {
  SetupStatus, CreateAdminReq, CreateAdminResp,
  ActivateLicenseReq, ActivateLicenseResp,
  LoginResp, ManageUser,
  Zone, Host, CreateHostReq, UpdateHostReq,
  Agent, ScanJob, EnqueueReq, PushStatus,
  CreateUserReq, CreateUserResp,
  LicenceSummary, SettingsSummary, GatewayHealthResponse,
  Lockout, SecurityEventsResponse,
} from './manageServer.types';
```

2. Add the two new methods **after** `getGatewayHealth` (at the end of the returned object, before the closing `};`):

```ts
    // Security events (login lockouts)
    listLockouts: () => http.get<SecurityEventsResponse>('/v1/admin/security-events'),
    clearLockout: (email: string, ip: string) =>
      http.del<void>(
        `/v1/admin/security-events?email=${encodeURIComponent(email)}&ip=${encodeURIComponent(ip)}`,
      ),
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pnpm --filter @triton/api-client test
```

Expected: All tests PASS (the 2 new + all existing).

- [ ] **Step 6: Commit**

```bash
git add web/packages/api-client/src/manageServer.types.ts \
        web/packages/api-client/src/manageServer.ts \
        web/packages/api-client/tests/manageServer.test.ts
git commit -m "feat(api-client): Lockout type + listLockouts + clearLockout"
```

---

## Task 5: Portal store

**Files:**
- Create: `web/apps/manage-portal/src/stores/security.ts`

The store mirrors `stores/users.ts`: `items` + `loading` refs, `fetch()` populates from the API, `remove(email, ip)` calls the API and optimistically prunes the local list.

- [ ] **Step 1: Create the store**

Create `web/apps/manage-portal/src/stores/security.ts`:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Lockout } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useSecurityStore = defineStore('security', () => {
  const items = ref<Lockout[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try {
      const resp = await useApiClient().get().listLockouts();
      items.value = resp.active_lockouts;
    } finally {
      loading.value = false;
    }
  }

  async function remove(email: string, ip: string): Promise<void> {
    await useApiClient().get().clearLockout(email, ip);
    items.value = items.value.filter((l) => !(l.email === email && l.ip === ip));
  }

  return { items, loading, fetch, remove };
});
```

- [ ] **Step 2: Build to verify TypeScript compiles**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events/web
pnpm --filter manage-portal build 2>&1 | tail -20
```

Expected: Build succeeds (exit 0).

- [ ] **Step 3: Commit**

```bash
git add web/apps/manage-portal/src/stores/security.ts
git commit -m "feat(manage-portal): useSecurityStore — lockout state + fetch + remove"
```

---

## Task 6: Security.vue view + component tests

**Files:**
- Create: `web/apps/manage-portal/src/views/Security.vue`
- Create: `web/apps/manage-portal/tests/views/Security.spec.ts`

- [ ] **Step 1: Write the failing component tests first**

Create `web/apps/manage-portal/tests/views/Security.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Security from '../../src/views/Security.vue';
import { useSecurityStore } from '../../src/stores/security';

beforeEach(() => {
  vi.clearAllMocks();
});

const LOCKOUT_A = {
  email: 'alice@example.com',
  ip: '127.0.0.1',
  failures: 5,
  first_failure: '2026-04-22T08:45:12Z',
  last_failure: '2026-04-22T08:47:33Z',
  locked_until: '2026-04-22T09:00:12Z',
};

const LOCKOUT_B = {
  email: 'bob@example.com',
  ip: '10.0.0.1',
  failures: 7,
  first_failure: '2026-04-22T09:00:00Z',
  last_failure: '2026-04-22T09:01:00Z',
  locked_until: '2026-04-22T09:15:00Z',
};

function mountWithItems(items = [LOCKOUT_A, LOCKOUT_B]) {
  return mount(Security, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: {
            security: { items, loading: false },
          },
        }),
      ],
    },
  });
}

describe('Security view', () => {
  it('renders rows from store items and calls fetch on mount', async () => {
    const wrapper = mountWithItems();
    const store = useSecurityStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('alice@example.com');
    expect(html).toContain('127.0.0.1');
    expect(html).toContain('bob@example.com');
    wrapper.unmount();
  });

  it('clicking Unlock opens the confirm dialog with email in the message', async () => {
    const wrapper = mountWithItems();
    await flushPromises();

    // Find the Unlock button for alice's row.
    const unlockBtn = wrapper
      .findAll('button')
      .find((b) => b.attributes('data-test') === 'unlock-alice@example.com|127.0.0.1');
    expect(unlockBtn).toBeTruthy();
    await unlockBtn!.trigger('click');
    await flushPromises();

    // Confirm dialog should contain alice's email.
    const dialog = document.querySelector('[data-test="confirm-dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog!.textContent).toContain('alice@example.com');
    wrapper.unmount();
  });

  it('confirming unlock calls store.remove and closes the dialog', async () => {
    const wrapper = mountWithItems();
    const store = useSecurityStore();
    await flushPromises();

    const unlockBtn = wrapper
      .findAll('button')
      .find((b) => b.attributes('data-test') === 'unlock-alice@example.com|127.0.0.1');
    await unlockBtn!.trigger('click');
    await flushPromises();

    const okBtn = document.querySelector('.t-confirm-ok') as HTMLButtonElement | null;
    expect(okBtn).not.toBeNull();
    okBtn!.click();
    await flushPromises();

    expect(store.remove).toHaveBeenCalledWith('alice@example.com', '127.0.0.1');
    expect(document.querySelector('[data-test="confirm-dialog"]')).toBeNull();
    wrapper.unmount();
  });

  it('clicking Refresh calls store.fetch', async () => {
    const wrapper = mountWithItems();
    const store = useSecurityStore();
    await flushPromises();

    const refreshBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('Refresh'));
    expect(refreshBtn).toBeTruthy();
    await refreshBtn!.trigger('click');
    await flushPromises();

    // fetch is called once on mount + once on Refresh = 2 total.
    expect(store.fetch).toHaveBeenCalledTimes(2);
    wrapper.unmount();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events/web
pnpm --filter manage-portal test -- Security.spec.ts
```

Expected: FAIL — `Security.vue` not found.

- [ ] **Step 3: Create Security.vue**

Create `web/apps/manage-portal/src/views/Security.vue`:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TDataTable,
  TButton,
  TConfirmDialog,
  useToast,
  type Column,
} from '@triton/ui';
import type { Lockout } from '@triton/api-client';
import { useSecurityStore } from '../stores/security';

const security = useSecurityStore();
const toast = useToast();
const confirmOpen = ref(false);
const pendingUnlock = ref<Lockout | null>(null);

const columns: Column<Lockout>[] = [
  { key: 'email',        label: 'Email' },
  { key: 'ip',           label: 'IP' },
  { key: 'failures',     label: 'Failures' },
  { key: 'first_failure', label: 'First failure' },
  { key: 'locked_until', label: 'Locked until' },
  { key: 'ip',           label: '',  width: '120px', align: 'right' },
];

onMounted(() => { void security.fetch(); });

function askUnlock(lockout: Lockout) {
  pendingUnlock.value = lockout;
  confirmOpen.value = true;
}

async function onConfirmUnlock() {
  const l = pendingUnlock.value;
  if (!l) return;
  try {
    await security.remove(l.email, l.ip);
    toast.success({ title: 'Lockout cleared', description: l.email });
  } catch (e) {
    toast.error({ title: 'Unlock failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingUnlock.value = null;
  }
}
</script>

<template>
  <section class="security-view">
    <header class="security-head">
      <div>
        <h1>Security</h1>
        <p class="security-sub">Active login lockouts. Each entry represents an (email, IP) pair blocked by the rate limiter.</p>
      </div>
      <TButton
        variant="ghost"
        size="sm"
        @click="security.fetch()"
      >
        Refresh
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="security.items"
      :row-key="(row: Lockout) => row.email + '|' + row.ip"
      :empty-text="security.loading ? 'Loading…' : 'No active lockouts.'"
    >
      <template #[`cell:first_failure`]="{ row }">
        {{ new Date(row.first_failure).toLocaleString() }}
      </template>
      <template #[`cell:locked_until`]="{ row }">
        {{ new Date(row.locked_until).toLocaleString() }}
      </template>
      <template #[`cell:ip`]="{ row, column }">
        <template v-if="column.width === '120px'">
          <TButton
            variant="danger"
            size="sm"
            :data-test="`unlock-${row.email}|${row.ip}`"
            @click="askUnlock(row)"
          >
            Unlock
          </TButton>
        </template>
        <template v-else>
          {{ row.ip }}
        </template>
      </template>
    </TDataTable>

    <TConfirmDialog
      :open="confirmOpen"
      title="Unlock user?"
      :message="pendingUnlock
        ? `Unlock ${pendingUnlock.email} from IP ${pendingUnlock.ip}? They'll be able to log in again immediately.`
        : ''"
      confirm-label="Unlock"
      variant="primary"
      data-test="confirm-dialog"
      @confirm="onConfirmUnlock"
      @cancel="confirmOpen = false; pendingUnlock = null"
    />
  </section>
</template>

<style scoped>
.security-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.security-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.security-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.security-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
</style>
```

**Note on the `cell:ip` template slot:** There are two columns using `key: 'ip'` — the data column and the actions column (distinguished by `width: '120px'`). The slot `#[`cell:ip`]` is shared by both, so we branch on `column.width` to decide whether to render a cell value or an Unlock button. This is a minor workaround — if `TDataTable` supports a unique key per column (e.g. `cell:actions`), use that instead and rename the actions column key to `'actions'` with an explicit cast `key: 'actions' as keyof Lockout`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pnpm --filter manage-portal test -- Security.spec.ts
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/views/Security.vue \
        web/apps/manage-portal/tests/views/Security.spec.ts
git commit -m "feat(manage-portal): Security.vue — lockout table + unlock + refresh"
```

---

## Task 7: Nav + router + crumb label wiring

**Files:**
- Modify: `web/apps/manage-portal/src/nav.ts`
- Modify: `web/apps/manage-portal/src/router.ts`
- Modify: `web/apps/manage-portal/src/App.vue`

- [ ] **Step 1: Add Security entry to nav.ts**

In `web/apps/manage-portal/src/nav.ts`, add the Security entry to the Admin section:

```ts
{
  label: 'Admin',
  items: [
    { href: '#/admin/users',    label: 'Users' },
    { href: '#/admin/security', label: 'Security' },
    { href: '#/admin/licence',  label: 'Licence' },
    { href: '#/admin/settings', label: 'Settings' },
  ],
},
```

- [ ] **Step 2: Add route to router.ts**

In `web/apps/manage-portal/src/router.ts`, add the Security route after the `admin/users` route:

```ts
  { path: '/admin/security', name: 'security', component: () => import('./views/Security.vue') },
```

The full routes array excerpt (showing context around where to insert):

```ts
  { path: '/admin/users',                  name: 'users',       component: () => import('./views/Users.vue') },
  { path: '/admin/security',               name: 'security',    component: () => import('./views/Security.vue') },
  { path: '/admin/licence',                name: 'licence',     component: () => import('./views/Licence.vue') },
```

- [ ] **Step 3: Add crumb label to App.vue**

In `web/apps/manage-portal/src/App.vue`, add `security: 'Security'` to the `labels` record:

```ts
const labels: Record<string, string> = {
  dashboard: 'Dashboard',
  inventory: 'Inventory',
  operations: 'Operations',
  admin: 'Admin',
  zones: 'Zones',
  hosts: 'Hosts',
  agents: 'Agents',
  'scan-jobs': 'Scan Jobs',
  'push-status': 'Push Status',
  users: 'Users',
  security: 'Security',
  licence: 'Licence',
  settings: 'Settings',
  setup: 'Setup',
};
```

- [ ] **Step 4: Build to verify everything compiles**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events/web
pnpm --filter manage-portal build 2>&1 | tail -20
```

Expected: Build succeeds.

- [ ] **Step 5: Run all portal tests**

```bash
pnpm --filter manage-portal test
```

Expected: All tests pass.

- [ ] **Step 6: Run all Go unit tests**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-security-events
go test ./pkg/manageserver/...
```

Expected: All unit tests pass (no `-tags integration` needed for this check).

- [ ] **Step 7: Commit**

```bash
git add web/apps/manage-portal/src/nav.ts \
        web/apps/manage-portal/src/router.ts \
        web/apps/manage-portal/src/App.vue
git commit -m "feat(manage-portal): Security nav entry + route + crumb label"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `GET /admin/security-events` returns `{active_lockouts:[...]}` | Task 1 (limiter), Task 2 (handler) |
| `DELETE /admin/security-events?email=...&ip=...` | Task 1 (Clear), Task 2 (handler) |
| 404 for missing entry on DELETE | Task 2 handler, Task 3 integration test |
| 400 for missing query params | Task 2 handler, Task 3 integration test |
| Security.vue table (email, IP, failures, first/locked_until, Unlock) | Task 6 |
| Manual Refresh button | Task 6 |
| TConfirmDialog before unlock | Task 6 |
| New "Security" sidebar entry | Task 7 |
| Router route `/admin/security` | Task 7 |
| Crumb label `security: 'Security'` | Task 7 |
| 7 rate-limiter unit tests | Task 1 |
| 6 handler integration tests | Task 3 |
| 4 Vitest component tests | Task 6 |
| 2 api-client tests | Task 4 |
| `locked_until = kept[0] + window` | Task 1 (rate_limit.go) |
| Empty list: `{"active_lockouts":[]}`, never null | Task 2 (handler nil guard) |
| Sorted by `locked_until DESC` | Task 1 (sort.Slice) |
| 403 for non-admin | Task 3 (integration test) |

All spec requirements are covered. No placeholders. Types are consistent: `Lockout` struct (Go) → `Lockout` interface (TS) → `useSecurityStore.items` → `Security.vue`. Method names `ActiveLockouts`/`Clear` (Go), `listLockouts`/`clearLockout` (TS) are internally consistent.

**Column key note:** The Security.vue uses two columns with `key: 'ip'` and distinguishes them by `column.width`. If the project's `Column<T>` type allows a separate `id` field distinct from `key`, prefer `{ id: 'actions', key: 'ip', ... }` to avoid the branch. Check `@triton/ui` source — if `Column<T>` only has `key: keyof T & string`, the workaround is required.
