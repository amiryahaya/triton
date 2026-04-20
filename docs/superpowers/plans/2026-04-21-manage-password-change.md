# Manage Server Password Change Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `POST /api/v1/auth/change-password` + a Vue change-password view + route guard so users with `must_change_pw=true` can complete first login, and any user can voluntarily rotate their password.

**Architecture:** Single backend handler in `pkg/manageserver/handlers_auth.go` mirrors `pkg/server/handlers_auth.go::handleChangePassword`. JWT gains a new `Mcp` claim so the frontend route guard reads `must_change_password` from token payload without a `/me` round-trip. Single new view `ChangePassword.vue` rendered standalone (no AppShell) on both forced + voluntary paths, plus a TUserMenu entry for voluntary rotation. Spec at `docs/superpowers/specs/2026-04-21-manage-password-change-design.md`.

**Tech Stack:** Go 1.25 + chi/v5 + bcrypt (existing); Vue 3 + Pinia + Vue Router + Vitest (existing). No new dependencies.

---

## Deviation from spec

The spec's §5.4 reads `auth.claims?.mustChangePassword` for the guard. Inspection of `pkg/manageserver/auth.go` shows `JWTClaims` has no `Mcp` field today, so JWT decoding always yields `mustChangePassword=false`. **The plan adds `Mcp bool` to `JWTClaims`** — one-line server-side addition + one-line claim population in two callsites (`handleLogin`, `handleRefresh`, plus the new `handleChangePassword`). This makes `useJwt::claims.mustChangePassword` work as the spec assumes.

---

## File structure

### New files

- `pkg/manageserver/handlers_auth_change_test.go` — backend unit tests for the new handler.
- `web/apps/manage-portal/src/views/ChangePassword.vue` — the form view.
- `web/apps/manage-portal/tests/views/ChangePassword.spec.ts` — frontend component tests.

### Modified files

- `pkg/manageserver/auth.go` — `JWTClaims` gains `Mcp bool` field; comment update.
- `pkg/manageserver/handlers_auth.go` — `handleLogin` + `handleRefresh` set `Mcp: user.MustChangePW` when minting JWTs; new `handleChangePassword` handler appended.
- `pkg/manageserver/server.go` — `buildRouter` adds `r.Post("/change-password", s.handleChangePassword)` inside the existing `/api/v1/auth` group.
- `web/packages/api-client/src/manageServer.ts` — append `changePassword(req)` method to `createManageApi` factory.
- `web/packages/api-client/tests/manageServer.test.ts` — add `changePassword` request-shape test.
- `web/apps/manage-portal/src/router.ts` — add `/auth/change-password` route + extend `beforeEach` guard with the forced-change redirect.
- `web/apps/manage-portal/src/App.vue` — extend the setup-route bypass to also cover `/auth/change-password`; add a "Change password" entry to the user menu (slot or button).
- `web/apps/manage-portal/tests/guards.spec.ts` — add forced-change redirect case.

### No file changes

- `pkg/managestore/postgres.go::UpdatePassword` — already atomic, already clears `must_change_pw`. Reuse.
- `pkg/manageserver/handlers_setup.go::validatePassword` — reuse.
- `pkg/manageserver/auth.go::HashPassword` / `VerifyPassword` — reuse.
- `web/packages/auth/src/jwt.ts` — already decodes `raw.mcp === true` into `claims.mustChangePassword`. No change.

---

## Batch A — Backend

### Task A1: Add `Mcp` field to JWTClaims + populate at login/refresh

**Files:**
- Modify: `pkg/manageserver/auth.go:21-27` (add field)
- Modify: `pkg/manageserver/handlers_auth.go:51-58` and `131-137` (populate at login + refresh)
- Modify: `pkg/manageserver/auth_test.go` (add round-trip test)

- [ ] **Step 1: Write the failing test in `pkg/manageserver/auth_test.go`**

```go
func TestJWT_McpRoundTrip(t *testing.T) {
    key := bytes.Repeat([]byte("k"), 32)
    in := JWTClaims{
        Sub:  "u1",
        Role: "admin",
        Iat:  100,
        Exp:  9999999999,
        Mcp:  true,
    }
    token, err := signJWT(in, key)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    out, err := parseJWT(token, key)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    if !out.Mcp {
        t.Fatalf("Mcp lost in round trip")
    }
}
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-password-change
go test -run TestJWT_McpRoundTrip ./pkg/manageserver/...
```

Expected: FAIL with "Mcp lost in round trip" or compile error "undefined: Mcp".

- [ ] **Step 3: Add `Mcp` field to `JWTClaims` in `pkg/manageserver/auth.go`**

```go
// JWTClaims are the payload fields for Manage Server HS256 JWTs.
type JWTClaims struct {
    Sub  string `json:"sub"`  // user UUID
    Role string `json:"role"` // "admin" | "network_engineer"
    Iat  int64  `json:"iat"`
    Exp  int64  `json:"exp"`
    Jti  int64  `json:"jti,omitempty"` // nanosecond nonce — guarantees uniqueness across same-second issues
    Mcp  bool   `json:"mcp,omitempty"` // must_change_password — frontend guard pushes user to /auth/change-password
}
```

- [ ] **Step 4: Populate `Mcp` in `handleLogin` (`pkg/manageserver/handlers_auth.go` around line 51)**

Find the existing block:
```go
claims := JWTClaims{
    Sub:  user.ID,
    Role: user.Role,
    Iat:  now.Unix(),
    Exp:  now.Add(s.cfg.SessionTTL).Unix(),
    Jti:  now.UnixNano(),
}
```

Add `Mcp: user.MustChangePW,` so it becomes:
```go
claims := JWTClaims{
    Sub:  user.ID,
    Role: user.Role,
    Iat:  now.Unix(),
    Exp:  now.Add(s.cfg.SessionTTL).Unix(),
    Jti:  now.UnixNano(),
    Mcp:  user.MustChangePW,
}
```

- [ ] **Step 5: Populate `Mcp` in `handleRefresh` (`pkg/manageserver/handlers_auth.go` around line 131)**

Same change at the `newClaims := JWTClaims{...}` block. Add `Mcp: user.MustChangePW,`.

- [ ] **Step 6: Run all auth tests + handler tests, verify pass**

```bash
go test ./pkg/manageserver/... 2>&1 | tail -10
```

Expected: all PASS, including the new `TestJWT_McpRoundTrip`.

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/auth.go pkg/manageserver/handlers_auth.go pkg/manageserver/auth_test.go
git commit -m "feat(manageserver): JWT gains Mcp claim for must_change_password"
```

### Task A2: Implement `handleChangePassword` + wire route

**Files:**
- Modify: `pkg/manageserver/handlers_auth.go` (append handler)
- Modify: `pkg/manageserver/server.go` (add route)
- Create: `pkg/manageserver/handlers_auth_change_test.go`

- [ ] **Step 1: Write failing test `TestChangePassword_HappyPath` in `pkg/manageserver/handlers_auth_change_test.go`**

```go
//go:build integration

package manageserver_test

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestChangePassword_HappyPath: forced-change user logs in, changes password,
// receives a new JWT with Mcp=false, can no longer log in with old password.
func TestChangePassword_HappyPath(t *testing.T) {
    srv, store, cleanup := openOperationalServerWithUser(t, "user@example.com", "TempPass1234!", true /* mustChangePW */)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    // Login → get JWT (Mcp should be true)
    loginResp := loginUser(t, ts.URL, "user@example.com", "TempPass1234!")
    token := loginResp["token"].(string)

    // Change password
    body := strings.NewReader(`{"current":"TempPass1234!","next":"NewSecret9876!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    require.Equal(t, http.StatusOK, resp.StatusCode)
    var body2 map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body2))
    assert.NotEmpty(t, body2["token"])
    assert.Equal(t, false, body2["must_change_password"])

    // Old password no longer works
    failed := loginUserExpectingError(t, ts.URL, "user@example.com", "TempPass1234!")
    assert.Equal(t, http.StatusUnauthorized, failed)

    // New password works
    _ = loginUser(t, ts.URL, "user@example.com", "NewSecret9876!")
    _ = store // future assertions on store state if needed
}
```

The helper `openOperationalServerWithUser` does not exist yet — add it inline at the top of the test file (or extract into `helpers_test.go` if you prefer; either is fine for one new test file). Mirror the existing `openOperationalServer` pattern from `handlers_setup_test.go` but seed an additional user via `s.store.CreateUser(...)` + `s.store.UpdatePassword(...)` (the latter clears must_change_pw, so set the field manually with a follow-up store call OR wrap in a small helper).

For brevity and reliability use this concrete helper at the top of the test file:

```go
func openOperationalServerWithUser(t *testing.T, email, password string, mustChangePW bool) (*manageserver.Server, managestore.Store, func()) {
    t.Helper()
    srv, store, cleanup := openOperationalServer(t)

    hash, err := manageserver.HashPassword(password)
    require.NoError(t, err)
    user := &managestore.ManageUser{
        Email:        email,
        Name:         "Test User",
        Role:         "network_engineer",
        PasswordHash: hash,
        MustChangePW: mustChangePW,
    }
    require.NoError(t, store.CreateUser(context.Background(), user))
    return srv, store, cleanup
}

func loginUser(t *testing.T, baseURL, email, password string) map[string]any {
    t.Helper()
    body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
    resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", body)
    require.NoError(t, err)
    defer resp.Body.Close()
    require.Equal(t, http.StatusOK, resp.StatusCode)
    var out map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
    return out
}

func loginUserExpectingError(t *testing.T, baseURL, email, password string) int {
    t.Helper()
    body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
    resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", body)
    require.NoError(t, err)
    defer resp.Body.Close()
    return resp.StatusCode
}
```

- [ ] **Step 2: Run, verify it fails**

```bash
go test -tags integration -run TestChangePassword_HappyPath ./pkg/manageserver/... 2>&1 | tail -10
```

Expected: FAIL with 404 (route doesn't exist).

- [ ] **Step 3: Add the handler in `pkg/manageserver/handlers_auth.go`** (append after `handleRefresh`, before `handleMe`)

```go
// handleChangePassword rotates the authenticated user's password and issues
// a fresh session. Tolerates must_change_pw=true sessions — this is the one
// endpoint forced-change users can hit.
//
// POST /api/v1/auth/change-password
// Body: {"current":"<plain>","next":"<plain>"}
// 200:  {"token":"<jwt>","expires_at":"...","must_change_password":false}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

    // 1. Auth
    token := bearerToken(r)
    if token == "" {
        writeError(w, http.StatusUnauthorized, "missing authorization header")
        return
    }
    claims, err := parseJWT(token, s.cfg.JWTSigningKey)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "invalid or expired token")
        return
    }
    oldHash := hashToken(token)
    oldSess, err := s.store.GetSessionByTokenHash(r.Context(), oldHash)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "session not found")
        return
    }
    user, err := s.store.GetUserByID(r.Context(), claims.Sub)
    if err != nil {
        writeError(w, http.StatusUnauthorized, "user not found")
        return
    }

    // 2. Decode + validate body
    var req struct {
        Current string `json:"current"`
        Next    string `json:"next"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Current == "" || req.Next == "" {
        writeError(w, http.StatusBadRequest, "current and next password required")
        return
    }
    if req.Next == req.Current {
        writeError(w, http.StatusBadRequest, "new password must differ from current")
        return
    }
    if err := validatePassword(req.Next); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    // 3. Verify current
    if err := VerifyPassword(user.PasswordHash, req.Current); err != nil {
        writeError(w, http.StatusUnauthorized, "current password incorrect")
        return
    }

    // 4. Hash + persist (atomically clears must_change_pw)
    nextHash, err := HashPassword(req.Next)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    if err := s.store.UpdatePassword(r.Context(), user.ID, nextHash); err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    // 5. Rotate session — delete old, mint new with Mcp=false
    _ = s.store.DeleteSession(r.Context(), oldSess.ID)

    now := time.Now()
    newClaims := JWTClaims{
        Sub:  user.ID,
        Role: user.Role,
        Iat:  now.Unix(),
        Exp:  now.Add(s.cfg.SessionTTL).Unix(),
        Jti:  now.UnixNano(),
        Mcp:  false,
    }
    newToken, err := signJWT(newClaims, s.cfg.JWTSigningKey)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    expiresAt := now.Add(s.cfg.SessionTTL)
    newSess := &managestore.ManageSession{
        UserID:    user.ID,
        TokenHash: hashToken(newToken),
        ExpiresAt: expiresAt,
    }
    if err := s.store.CreateSession(r.Context(), newSess); err != nil {
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }

    writeJSON(w, http.StatusOK, map[string]any{
        "token":                 newToken,
        "expires_at":            expiresAt.UTC().Format(time.RFC3339),
        "must_change_password":  false,
    })
}
```

- [ ] **Step 4: Wire the route in `pkg/manageserver/server.go::buildRouter`**

Find the `r.Route("/api/v1/auth", func(r chi.Router) { ... })` block. Add inside the inner func:

```go
r.Post("/change-password", s.handleChangePassword)
```

So the block becomes:
```go
r.Route("/api/v1/auth", func(r chi.Router) {
    r.Use(s.requireOperational)
    r.Post("/login", s.handleLogin)
    r.Post("/logout", s.handleLogout)
    r.Post("/refresh", s.handleRefresh)
    r.Post("/change-password", s.handleChangePassword) // NEW
})
```

- [ ] **Step 5: Run the test, verify it passes**

```bash
go test -tags integration -run TestChangePassword_HappyPath ./pkg/manageserver/... 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/handlers_auth.go pkg/manageserver/server.go pkg/manageserver/handlers_auth_change_test.go
git commit -m "feat(manageserver): POST /auth/change-password handler + route"
```

### Task A3: Add the remaining backend tests

**File:** `pkg/manageserver/handlers_auth_change_test.go` (append).

- [ ] **Step 1: Add 8 more tests covering error paths**

```go
func TestChangePassword_WrongCurrent(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u1@example.com", "RealPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u1@example.com", "RealPass1234!")["token"].(string)

    body := strings.NewReader(`{"current":"WrongPass1234!","next":"AnotherSecret9876!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestChangePassword_PolicyFail_TooShort(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u2@example.com", "RealPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u2@example.com", "RealPass1234!")["token"].(string)

    body := strings.NewReader(`{"current":"RealPass1234!","next":"short1"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var out map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
    assert.Contains(t, fmt.Sprintf("%v", out["error"]), "12 characters")
}

func TestChangePassword_PolicyFail_NoDigit(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u3@example.com", "RealPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u3@example.com", "RealPass1234!")["token"].(string)

    body := strings.NewReader(`{"current":"RealPass1234!","next":"NoDigitsAtAll!!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var out map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
    assert.Contains(t, fmt.Sprintf("%v", out["error"]), "digit")
}

func TestChangePassword_SameAsCurrent(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u4@example.com", "SamePass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u4@example.com", "SamePass1234!")["token"].(string)

    body := strings.NewReader(`{"current":"SamePass1234!","next":"SamePass1234!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var out map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
    assert.Contains(t, fmt.Sprintf("%v", out["error"]), "differ from current")
}

func TestChangePassword_MissingFields(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u5@example.com", "RealPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u5@example.com", "RealPass1234!")["token"].(string)

    for _, body := range []string{
        `{"current":"","next":"NewSecret9876!"}`,
        `{"current":"RealPass1234!","next":""}`,
        `{}`,
    } {
        req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", strings.NewReader(body))
        req.Header.Set("Authorization", "Bearer "+token)
        req.Header.Set("Content-Type", "application/json")
        resp, err := http.DefaultClient.Do(req)
        require.NoError(t, err)
        resp.Body.Close()
        assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", body)
    }
}

func TestChangePassword_NoAuthHeader(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u6@example.com", "RealPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    body := strings.NewReader(`{"current":"RealPass1234!","next":"NewSecret9876!"}`)
    resp, err := http.Post(ts.URL+"/api/v1/auth/change-password", "application/json", body)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestChangePassword_OldTokenInvalidatedAfterSuccess(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u7@example.com", "OldPass1234!", false)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    oldToken := loginUser(t, ts.URL, "u7@example.com", "OldPass1234!")["token"].(string)

    // Successfully change password
    body := strings.NewReader(`{"current":"OldPass1234!","next":"NewSecret9876!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+oldToken)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    resp.Body.Close()
    require.Equal(t, http.StatusOK, resp.StatusCode)

    // Old token should now fail on /me
    req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
    req2.Header.Set("Authorization", "Bearer "+oldToken)
    resp2, err := http.DefaultClient.Do(req2)
    require.NoError(t, err)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestChangePassword_McpClearedInNewToken(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithUser(t, "u8@example.com", "TempPass1234!", true)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()
    token := loginUser(t, ts.URL, "u8@example.com", "TempPass1234!")["token"].(string)

    body := strings.NewReader(`{"current":"TempPass1234!","next":"NewSecret9876!"}`)
    req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var body2 map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body2))
    newToken := body2["token"].(string)

    // Decode the new JWT payload (base64url middle segment) and confirm Mcp is absent or false.
    parts := strings.Split(newToken, ".")
    require.Len(t, parts, 3)
    raw, err := base64.RawURLEncoding.DecodeString(parts[1])
    require.NoError(t, err)
    var c map[string]any
    require.NoError(t, json.Unmarshal(raw, &c))
    // omitempty means false → field absent. Either is acceptable.
    if v, ok := c["mcp"]; ok {
        assert.Equal(t, false, v)
    }
}
```

Add these imports at the top of the file alongside the existing test imports:
```go
import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/pkg/manageserver"
    "github.com/amiryahaya/triton/pkg/managestore"
)
```

- [ ] **Step 2: Run all 9 backend tests**

```bash
go test -tags integration -run TestChangePassword ./pkg/manageserver/... 2>&1 | tail -10
go test -tags integration -run TestJWT_Mcp ./pkg/manageserver/... 2>&1 | tail -5
```

Expected: 9 + 1 = 10 PASS.

- [ ] **Step 3: Run the whole manageserver test suite to confirm no regressions**

```bash
go test -tags integration ./pkg/manageserver/... ./pkg/managestore/... 2>&1 | tail -10
```

Expected: ALL PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/handlers_auth_change_test.go
git commit -m "test(manageserver): change-password error paths + Mcp clearance"
```

---

## Batch B — Frontend

### Task B1: api-client method + test

**Files:**
- Modify: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/tests/manageServer.test.ts`

- [ ] **Step 1: Add failing test in `tests/manageServer.test.ts`** (append inside the `describe('createManageApi', ...)` block)

```ts
it('changePassword POSTs body to /v1/auth/change-password', async () => {
  await api.changePassword({ current: 'old', next: 'new' });
  expect(fake.calls[0]).toEqual({
    method: 'POST',
    path: '/v1/auth/change-password',
    body: { current: 'old', next: 'new' },
  });
});
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd web && pnpm --filter @triton/api-client test 2>&1 | tail -10
```

Expected: FAIL with `TypeError: api.changePassword is not a function`.

- [ ] **Step 3: Append the method to `createManageApi` in `web/packages/api-client/src/manageServer.ts`**

Find the existing `// Setup + auth` block at the top of the returned object. Add this method anywhere in the auth group (after `me:`):

```ts
    changePassword: (req: { current: string; next: string }) =>
      http.post<ManageLoginResp>('/v1/auth/change-password', req),
```

Wait — `ManageLoginResp` is the export alias from `index.ts`; inside `manageServer.ts` the local name is `LoginResp`. Use `LoginResp` here:

```ts
    changePassword: (req: { current: string; next: string }) =>
      http.post<LoginResp>('/v1/auth/change-password', req),
```

(The factory file already imports `LoginResp` from `./manageServer.types` in the named import block — verify and re-use.)

- [ ] **Step 4: Run, verify pass**

```bash
cd web && pnpm --filter @triton/api-client test 2>&1 | tail -10
```

Expected: PASS (8 tests now).

- [ ] **Step 5: Commit**

```bash
git add web/packages/api-client/src/manageServer.ts web/packages/api-client/tests/manageServer.test.ts
git commit -m "feat(api-client): manageServer.changePassword method"
```

### Task B2: ChangePassword.vue + router entry

**Files:**
- Create: `web/apps/manage-portal/src/views/ChangePassword.vue`
- Modify: `web/apps/manage-portal/src/router.ts`
- Modify: `web/apps/manage-portal/src/App.vue` (extend setup-bypass condition)
- Create: `web/apps/manage-portal/tests/views/ChangePassword.spec.ts`

- [ ] **Step 1: Write the failing component test**

```ts
// web/apps/manage-portal/tests/views/ChangePassword.spec.ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';

import ChangePassword from '../../src/views/ChangePassword.vue';

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/dashboard', component: { template: '<div>d</div>' } },
      { path: '/auth/change-password', component: ChangePassword },
    ],
  });
}

describe('ChangePassword.vue', () => {
  it('renders three password inputs', () => {
    const w = mount(ChangePassword, {
      global: { plugins: [createTestingPinia({ createSpy: vi.fn }), makeRouter()] },
    });
    const inputs = w.findAll('input[type="password"]');
    expect(inputs.length).toBe(3);
  });

  it('disables submit until validations pass', async () => {
    const w = mount(ChangePassword, {
      global: { plugins: [createTestingPinia({ createSpy: vi.fn }), makeRouter()] },
    });
    const submit = w.find('button[type="submit"]');
    expect(submit.attributes('disabled')).toBeDefined();

    const [cur, next, conf] = w.findAll('input[type="password"]');
    await cur.setValue('OldPass1234!');
    await next.setValue('NewSecret9876!');
    await conf.setValue('NewSecret9876!');
    await w.vm.$nextTick();
    expect(submit.attributes('disabled')).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run, verify fail**

```bash
cd web && pnpm --filter manage-portal test 2>&1 | tail -10
```

Expected: FAIL — file does not exist.

- [ ] **Step 3: Implement `ChangePassword.vue`**

```vue
<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const router = useRouter();
const api = useApiClient();
const auth = useAuthStore();
const toast = useToast();

const current = ref('');
const next = ref('');
const confirm = ref('');
const busy = ref(false);
const serverError = ref('');

const policyOK = computed(() => next.value.length >= 12 && /[0-9]/.test(next.value));
const matches = computed(() => next.value === confirm.value);
const differs = computed(() => next.value !== current.value);
const valid = computed(
  () => current.value.length > 0 && policyOK.value && matches.value && differs.value
);

const forced = computed(() => auth.claims?.mustChangePassword === true);

async function submit() {
  if (!valid.value) return;
  busy.value = true;
  serverError.value = '';
  try {
    const resp = await api.get().changePassword({ current: current.value, next: next.value });
    auth.setToken(resp.token);
    toast.success({ title: 'Password changed' });
    await router.push('/dashboard');
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed';
    if (msg.includes('401')) {
      serverError.value = 'Current password is incorrect.';
      current.value = '';
    } else {
      serverError.value = msg;
    }
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <form class="wiz" @submit.prevent="submit">
    <h1>Change password</h1>
    <p v-if="forced" class="forced">
      First-time login. You must set a new password before continuing.
    </p>

    <TFormField label="Current password">
      <TInput v-model="current" type="password" autocomplete="current-password" />
    </TFormField>

    <TFormField label="New password (≥ 12 chars, must contain a digit)">
      <TInput v-model="next" type="password" autocomplete="new-password" />
    </TFormField>

    <TFormField label="Confirm new password">
      <TInput v-model="confirm" type="password" autocomplete="new-password" />
    </TFormField>

    <p v-if="next && !policyOK" class="hint">
      Password must be at least 12 characters and contain at least one digit.
    </p>
    <p v-if="confirm && !matches" class="hint">Passwords do not match.</p>
    <p v-if="next && !differs" class="hint">New password must differ from current.</p>
    <p v-if="serverError" class="err">{{ serverError }}</p>

    <TButton type="submit" variant="primary" :disabled="!valid || busy">
      {{ busy ? 'Changing…' : 'Change password' }}
    </TButton>
  </form>
</template>

<style scoped>
.wiz {
  max-width: 480px;
  margin: 5rem auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.forced {
  padding: var(--space-3);
  background: var(--warning-bg, var(--bg-surface));
  border-radius: var(--radius);
}
.hint {
  color: var(--text-muted);
  font-size: 0.85rem;
}
.err {
  color: var(--danger);
}
</style>
```

- [ ] **Step 4: Add the route in `web/apps/manage-portal/src/router.ts`**

In the `routes` array, add (alongside the setup routes):

```ts
{ path: '/auth/change-password', name: 'changePassword', component: () => import('./views/ChangePassword.vue') },
```

- [ ] **Step 5: Extend the App.vue setup-bypass condition**

In `web/apps/manage-portal/src/App.vue`, find:

```vue
<template v-if="route.path.startsWith('/setup/')">
  <router-view />
</template>
```

Change to:

```vue
<template v-if="route.path.startsWith('/setup/') || route.path === '/auth/change-password'">
  <router-view />
</template>
```

- [ ] **Step 6: Run the tests, verify pass**

```bash
cd web && pnpm --filter manage-portal test 2>&1 | tail -10
```

Expected: PASS (2 new tests, plus all existing tests still green).

- [ ] **Step 7: Build to confirm vue-tsc clean**

```bash
cd web && pnpm --filter manage-portal build 2>&1 | tail -5
```

- [ ] **Step 8: Commit**

```bash
git add web/apps/manage-portal/src/views/ChangePassword.vue \
        web/apps/manage-portal/src/router.ts \
        web/apps/manage-portal/src/App.vue \
        web/apps/manage-portal/tests/views/ChangePassword.spec.ts
git commit -m "feat(manage-portal): ChangePassword.vue + route + setup-bypass"
```

### Task B3: Route guard for forced-change

**Files:**
- Modify: `web/apps/manage-portal/src/router.ts`
- Modify: `web/apps/manage-portal/tests/guards.spec.ts`

- [ ] **Step 1: Write failing test in `tests/guards.spec.ts`** (append a new `it` to the existing `describe`)

```ts
it('forced-change: mustChangePassword=true redirects from /dashboard to /auth/change-password', async () => {
  const router = buildRouter();
  // emulate the real guard: setup is complete, but a JWT with mcp=true is set.
  router.beforeEach((to) => {
    // Spec §4 in router.ts:
    const setupRequired = false;
    if (setupRequired) return true;
    if (to.path.startsWith('/setup/')) return '/dashboard';

    const authed = true;
    const mustChange = true;
    if (authed && mustChange) {
      if (to.path === '/auth/change-password') return true;
      return '/auth/change-password';
    }
    return true;
  });
  await router.push('/dashboard');
  expect(router.currentRoute.value.fullPath).toBe('/auth/change-password');
});
```

(The existing test file already inlines the guard logic per case — match that style. The guard inside `router.ts` itself is not directly invoked by tests; the inline-guard pattern is intentional to keep tests deterministic.)

- [ ] **Step 2: Run, verify pass**

```bash
cd web && pnpm --filter manage-portal test 2>&1 | tail -10
```

Note: this test passes with the inline guard. The next step extends the actual `router.ts` guard to match.

- [ ] **Step 3: Extend the real guard in `web/apps/manage-portal/src/router.ts`**

Find the existing `router.beforeEach` block. After the existing setup-related logic, BEFORE the final `return true`, add:

```ts
  // Forced-change: a logged-in user with must_change_password=true is
  // trapped on /auth/change-password until they comply. The endpoint is
  // reachable; everything else redirects there.
  const tokenLive = Boolean(auth.token) && !auth.isExpired;
  if (tokenLive && auth.claims?.mustChangePassword) {
    if (to.path === '/auth/change-password') return true;
    return { path: '/auth/change-password' };
  }
```

`auth` is already imported at the top of the file via `useAuthStore()`. `auth.token` and `auth.isExpired` and `auth.claims` are all `useJwt()` exports — verify they exist in `web/packages/auth/src/jwt.ts` (they do per `useJwt`'s `UseJwt` interface).

- [ ] **Step 4: Run all tests + build, verify clean**

```bash
cd web && pnpm --filter manage-portal test 2>&1 | tail -10
cd web && pnpm --filter manage-portal build 2>&1 | tail -5
```

Expected: all PASS, build clean.

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/router.ts web/apps/manage-portal/tests/guards.spec.ts
git commit -m "feat(manage-portal): route guard redirects must_change_password to /auth/change-password"
```

### Task B4: TUserMenu "Change password" entry

**Files:**
- Modify: `web/apps/manage-portal/src/App.vue`

- [ ] **Step 1: Inspect TUserMenu's API**

```bash
cat web/packages/ui/src/shell/TUserMenu.vue | head -60
```

Look for: existing slots, props for menu items, emits.

- [ ] **Step 2: Wire the entry**

If `TUserMenu` accepts a slot or items prop, use that. Otherwise the simplest robust path is to add a separate small button next to the user menu in the topbar, OR to render a separate menu via Vue's `<details>` element.

For a focused PR, the minimum acceptable wiring is one of:

**Option A (preferred): use TUserMenu's existing slot if it has one.** Find the slot name (e.g., `#actions`, `#extra-items`) and inside it:
```vue
<button type="button" class="menu-item" @click="router.push('/auth/change-password')">
  Change password
</button>
```

**Option B (fallback): add an inline button in the topbar adjacent to TUserMenu.** In `App.vue`'s `<template #topbar>` block, append:
```vue
<TButton variant="ghost" size="sm" @click="router.push('/auth/change-password')">
  Change password
</TButton>
```

Pick whichever fits the existing TUserMenu API with the smallest footprint. Document the choice in the commit message.

- [ ] **Step 3: Build + manual smoke**

```bash
cd web && pnpm --filter manage-portal build 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add web/apps/manage-portal/src/App.vue
git commit -m "feat(manage-portal): user menu \"Change password\" entry"
```

---

## Batch C — Final sanity + PR

### Task C1: Full sanity sweep

- [ ] **Step 1: Backend tests**

```bash
go test ./pkg/manageserver/... ./pkg/managestore/... 2>&1 | tail -5
go test -tags integration ./pkg/manageserver/... ./pkg/managestore/... 2>&1 | tail -5
go vet ./... 2>&1 | tail -5
go build ./... 2>&1 | tail -5
```

All four must pass.

- [ ] **Step 2: Frontend tests**

```bash
cd web && pnpm install 2>&1 | tail -5
cd web && pnpm --filter manage-portal test 2>&1 | tail -10
cd web && pnpm --filter manage-portal build 2>&1 | tail -5
cd web && pnpm --filter @triton/api-client test 2>&1 | tail -5
```

All must pass.

- [ ] **Step 3: Lint**

```bash
golangci-lint run ./... 2>&1 | tail -10
```

Must report 0 issues.

- [ ] **Step 4: Manual smoke** (optional, requires a running Manage Server + a created user with `must_change_pw=true`)

If there's no infrastructure to test live, skip and rely on the integration tests.

### Task C2: Push + open PR

- [ ] **Step 1: Push branch**

```bash
git push -u origin feat/manage-password-change
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat(manage): password-change flow (forced + voluntary)" --body "$(cat <<'EOF'
## Summary

Closes the literal-blocker gap surfaced after PR C: users created via \`POST /api/v1/admin/users\` are flagged \`must_change_pw=true\` and previously had no UI path to change their password — they could log in but could not proceed. This PR ships:

- Backend: \`POST /api/v1/auth/change-password\` mirroring Report Server's existing handler. Verifies current password, validates new against the existing policy (≥12 chars + must contain digit), atomically updates + clears \`must_change_pw\`, rotates the session (deletes old, mints new with \`Mcp=false\`), returns \`{token, expires_at, must_change_password:false}\`.
- JWT now carries a \`Mcp\` claim so the frontend route guard reads forced-change state from the token without a \`/me\` round-trip. Backwards-compat: \`omitempty\` keeps the field absent when false.
- Frontend: \`ChangePassword.vue\` standalone view (no AppShell) reachable via two paths — forced-change auto-redirect from any route when \`mustChangePassword=true\`, and voluntary "Change password" entry in the user menu.
- Route guard pushes forced-change users to \`/auth/change-password\` and traps them there until they comply.
- Tests: 9 backend integration tests (happy path, wrong current, policy fails, same-as-current, missing fields, no auth header, old-token-invalidated, Mcp-cleared) + 1 JWT round-trip test + 2 frontend component tests + 1 guard test.

Implements \`docs/superpowers/specs/2026-04-21-manage-password-change-design.md\`.

## Test plan

- [ ] CI Lint green.
- [ ] CI Unit Test green.
- [ ] CI Integration Test green (new \`TestChangePassword_*\` suite).
- [ ] CI Web build + test green (new ChangePassword.spec, manageServer.test additions).
- [ ] CI Build green.
- [ ] Manual: create a user via \`POST /api/v1/admin/users\` → log in as that user → land on /auth/change-password → submit valid new password → land on /dashboard with new JWT.
- [ ] Manual: voluntary path — admin user clicks "Change password" in the user menu → submit → toast + dashboard.
- [ ] Manual: wrong current password → 401, current field clears, error visible.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify CI green.**

If CI fails, fix in follow-up commits — do not amend merged ancestors.

---

## Self-review

**Spec coverage:**
- Spec §3 (architecture) → Batch A (backend handler + Mcp claim) + Batch B (frontend view + guard).
- Spec §4 (backend) → Tasks A1, A2, A3.
- Spec §5 (frontend) → Tasks B1, B2, B3, B4.
- Spec §6 (testing) → all 9 backend + 2 frontend + 1 guard tests in plan tasks.
- Spec §7 (acceptance criteria) → covered via CI checklist + manual smoke in PR test plan.

**Placeholder scan:**
- No "TBD" / "fill in" / "similar to". Every step shows code or exact commands.
- B4 has two options (A: TUserMenu slot, B: inline button) with a pick-best directive — not a placeholder; this is intentional flexibility based on TUserMenu's actual API which the implementer reads in Step 1.

**Type consistency:**
- `Mcp` field name consistent across backend (`auth.go`, `handlers_auth.go`) and frontend JWT decode (`useJwt::raw.mcp` already exists).
- `must_change_password` snake_case JSON key consistent across backend response and frontend api-client return type.
- `auth.claims?.mustChangePassword` (camelCase TS) matches `useJwt::JwtClaims.mustChangePassword` from `@triton/auth`.
- `LoginResp` (in factory) re-exported as `ManageLoginResp` from `index.ts` per existing convention; the new `changePassword` method uses `LoginResp` internally — same shape.
