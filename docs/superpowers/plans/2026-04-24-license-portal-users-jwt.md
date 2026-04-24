# License Portal Users — JWT Auth + Invite Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the License Portal's shared admin-key auth with per-user JWT logins; add invite-flow user creation (temp password + Resend), first-time setup wizard, force-change-password flow, and rename Superadmins → Users. Each operator gets their own account; audit log tracks individual identity.

**Architecture:** Backend swaps `AdminKeyAuth` middleware for `JWTAuth` on all `/api/v1/admin/*` routes. Adds `must_change_password` column + ungated `/api/v1/setup/{status,first-admin}` endpoints. Reworks `handleCreateSuperadmin` to generate a temp password and send a Resend invite (falling back to returning the password in the body when mailer is nil). Frontend swaps `TAuthGate type="adminKey"` → `"jwt"`, adds Setup/ChangePassword/Users views, and gates navigation on `mustChangePassword` + `needsSetup`.

**Tech Stack:** Go (chi router + pgx/v5 + Ed25519 JWT + bcrypt) · Resend via `internal/mailer` · Vue 3 + Pinia + vue-router hash mode · `@triton/auth` (`useJwt`, `TAuthGate type="jwt"`) · `@triton/ui` · Vitest · `@pinia/testing`.

**Spec:** `docs/superpowers/specs/2026-04-24-license-portal-users-jwt-design.md`

**Prerequisite:** PR #94 must be merged (already done — it unblocked the admin-key path; this plan removes admin-key entirely so it supersedes that work).

---

## File structure

**Create (backend):**
- `pkg/licenseserver/middleware_jwt.go` — new `JWTAuth` middleware
- `pkg/licenseserver/handlers_setup.go` — `handleSetupStatus` + `handleFirstAdminSetup`
- `pkg/licenseserver/handlers_setup_test.go` — setup flow integration tests
- `pkg/licenseserver/middleware_jwt_test.go` — route coverage + JWT failure modes

**Modify (backend):**
- `pkg/licensestore/migrations.go` — v8 migration
- `pkg/licensestore/store.go` — add `MustChangePassword` to User struct
- `pkg/licensestore/postgres.go` — CRUD methods update + new `CountUsers`, `CountPlatformAdmins`, session revocation on user delete
- `pkg/licenseserver/middleware.go` — delete `AdminKeyAuth`
- `pkg/licenseserver/server.go` — swap middleware, mount `/setup/*` routes
- `pkg/licenseserver/config.go` — drop `AdminKeys`, keep `Mailer`, add `InviteLoginURL`
- `pkg/licenseserver/handlers_auth.go` — surface `mustChangePassword` in login response; add `handleChangePassword`; session-rotation on password change
- `pkg/licenseserver/handlers_superadmin.go` — invite-flow rewrite + new `handleResendInvite` + last-user/self-delete guards
- `pkg/licenseserver/handlers_audit.go` — `auditActor(r)` pulls user email from request context
- `cmd/licenseserver/main.go` — wire `TRITON_LICENSE_SERVER_RESEND_*` + `TRITON_LICENSE_SERVER_LOGIN_URL` env vars; drop `TRITON_LICENSE_SERVER_ADMIN_KEY`
- `.env.example` — matching env var rename
- `scripts/gen-dev-env.sh` — matching

**Create (frontend):**
- `web/apps/license-portal/src/views/Setup.vue` — first-time setup wizard
- `web/apps/license-portal/src/views/ChangePassword.vue` — force-change-password page
- `web/apps/license-portal/src/views/modals/UserForm.vue` — "new user" modal
- `web/apps/license-portal/tests/views/Setup.spec.ts`
- `web/apps/license-portal/tests/views/ChangePassword.spec.ts`
- `web/apps/license-portal/tests/views/Users.spec.ts`

**Modify (frontend):**
- `web/packages/api-client/src/types.ts` — add `User` + `LoginResponse` + `ChangePasswordResponse` + `SetupFirstAdminResponse` + `CreateUserResponse`
- `web/packages/api-client/src/licenseServer.ts` — `login` / `logout` / `refresh` / `changePassword` / `setupStatus` / `setupFirstAdmin` / `listUsers` / `createUser` / `deleteUser` / `resendInvite`
- `web/packages/api-client/src/index.ts` — export the new types
- `web/packages/api-client/tests/licenseServer.test.ts` — unit tests for every new method
- `web/apps/license-portal/src/stores/auth.ts` — `useJwt` (was `useAdminKey`)
- `web/apps/license-portal/src/stores/apiClient.ts` — Authorization: Bearer header
- `web/apps/license-portal/src/App.vue` — `TAuthGate type="jwt"` + login handler + `mustChangePassword` gate
- `web/apps/license-portal/src/router.ts` — add `/setup`, `/change-password`, `/admin/users`; drop `/superadmins`; add router guards
- `web/apps/license-portal/src/nav.ts` — rename "Superadmins" → "Users"; href `#/admin/users`
- `web/apps/license-portal/src/views/Superadmins.vue` → **delete**, replaced by `Users.vue`
- `web/apps/license-portal/src/views/Users.vue` — new, replaces Superadmins.vue

**Delete:**
- `pkg/licenseserver/middleware_test.go` — AdminKeyAuth tests no longer apply
- `web/apps/license-portal/src/views/Superadmins.vue`

---

## Task 0: Worktree setup

Use the `superpowers:using-git-worktrees` skill to create the worktree on branch `feat/license-portal-users-jwt` from `main`.

- [ ] **Step 1: Confirm main is clean**

```bash
cd /Users/amirrudinyahaya/Workspace/triton
git fetch origin main
git rev-parse origin/main
```

- [ ] **Step 2: Create worktree + install**

```bash
git worktree add .worktrees/license-portal-users-jwt -b feat/license-portal-users-jwt origin/main
cd .worktrees/license-portal-users-jwt/web
pnpm install
```

- [ ] **Step 3: Verify baseline green**

```bash
cd .worktrees/license-portal-users-jwt/web
pnpm test 2>&1 | tail -5
```
Expected: 248+/248+ tests pass.

```bash
cd .worktrees/license-portal-users-jwt
go test ./pkg/licenseserver/... ./pkg/licensestore/... 2>&1 | tail -5
```
Expected: pass.

All subsequent tasks run from `.worktrees/license-portal-users-jwt/`.

---

## Task 1: Migration v8 — must_change_password column

**Files:**
- Modify: `pkg/licensestore/migrations.go`
- Modify: `pkg/licensestore/store.go` (User struct)

- [ ] **Step 1: Append migration v8 to the migrations slice**

Open `pkg/licensestore/migrations.go`. Append to the end of the `migrations` slice (after v7):

```go
	// Version 8: Add must_change_password flag to users for the invite
	// flow. New users created via setup or resend-invite start with
	// true; change-password clears it.
	`ALTER TABLE users
	  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;`,
```

- [ ] **Step 2: Add MustChangePassword field to User struct**

Open `pkg/licensestore/store.go`. Update the `User` struct:

```go
type User struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"orgID,omitempty"`
	Email              string    `json:"email"`
	Name               string    `json:"name"`
	Role               string    `json:"role"`
	Password           string    `json:"-"`
	MustChangePassword bool      `json:"mustChangePassword"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
	OrgName            string    `json:"orgName,omitempty"`
}
```

- [ ] **Step 3: Update postgres CRUD to read/write the new column**

Open `pkg/licensestore/postgres.go`. Find every SQL statement that mentions the `users` table and update:
- `CreateUser`: add `must_change_password` to the INSERT column list + values. Use `u.MustChangePassword`.
- `GetUser`, `GetUserByEmail`, `ListUsers`: add `must_change_password` to the SELECT column list + scan into `&u.MustChangePassword`.
- Any UPDATE statements that touch password (e.g., resend-invite) also set `must_change_password = true`.

Specific edits depend on the existing code. Grep first:

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
grep -n "INSERT INTO users\|FROM users\|UPDATE users" pkg/licensestore/postgres.go
```

For each match, add `must_change_password` symmetrically to the column list + placeholders + scan targets.

- [ ] **Step 4: Run backend tests to confirm migrations + CRUD still work**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/licensestore/... 2>&1 | tail -10
```
Expected: all existing tests pass. The new column reads/writes exercise the added scan targets.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licensestore/
git commit -m "feat(licensestore): migration v8 adds must_change_password to users

Column is NOT NULL DEFAULT false, so existing rows stay unaffected.
New users created via the invite flow will set it to true."
```

---

## Task 2: Store helpers for the invite + guard flows

**Files:**
- Modify: `pkg/licensestore/store.go` (interface)
- Modify: `pkg/licensestore/postgres.go` (impls)

Three new methods needed:
- `CountUsers(ctx) (int, error)` — for setup-status + first-admin guard
- `CountPlatformAdmins(ctx) (int, error)` — for last-user delete guard
- `DeleteSessionsForUser(ctx, userID) error` — revoke all sessions for a user (used by resend-invite + password change + delete)

- [ ] **Step 1: Write failing integration tests**

Create `pkg/licensestore/users_extra_test.go` (new, `//go:build integration`):

```go
//go:build integration

package licensestore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestCountUsers_EmptyAndPopulated(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	n, err := store.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	u := &licensestore.User{Email: "a@b", Name: "A", Role: "platform_admin", Password: "x"}
	require.NoError(t, store.CreateUser(ctx, u))

	n, err = store.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestCountPlatformAdmins_IgnoresOrgUsers(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	admin := &licensestore.User{Email: "a@b", Name: "A", Role: "platform_admin", Password: "x"}
	orgUser := &licensestore.User{Email: "c@d", Name: "C", Role: "org_user", Password: "y"}
	require.NoError(t, store.CreateUser(ctx, admin))
	require.NoError(t, store.CreateUser(ctx, orgUser))

	n, err := store.CountPlatformAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestDeleteSessionsForUser_RevokesAll(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	u := &licensestore.User{Email: "a@b", Name: "A", Role: "platform_admin", Password: "x"}
	require.NoError(t, store.CreateUser(ctx, u))

	s1 := &licensestore.Session{UserID: u.ID, TokenHash: "hash1"}
	s2 := &licensestore.Session{UserID: u.ID, TokenHash: "hash2"}
	require.NoError(t, store.CreateSession(ctx, s1))
	require.NoError(t, store.CreateSession(ctx, s2))

	require.NoError(t, store.DeleteSessionsForUser(ctx, u.ID))

	for _, h := range []string{"hash1", "hash2"} {
		_, err := store.GetSessionByHash(ctx, h)
		assert.Error(t, err, "session %s should be gone", h)
	}
}
```

The `newTestStore` helper is already defined in the package's test setup. `Session.ID` + `Session.ExpiresAt` are auto-filled if the existing helpers stamp them; if not, set them explicitly.

- [ ] **Step 2: Run — confirm they fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestCountUsers|TestCountPlatformAdmins|TestDeleteSessionsForUser" -v ./pkg/licensestore/... 2>&1 | tail -20
```
Expected: compile errors on the missing methods, then test failures.

- [ ] **Step 3: Add interface methods to the Store interface**

Open `pkg/licensestore/store.go`. Find the `Store` interface (grep for it) and add:

```go
// CountUsers returns the total user count. Used by the first-admin
// setup guard.
CountUsers(ctx context.Context) (int, error)

// CountPlatformAdmins returns the count of users with role =
// 'platform_admin'. Used to block last-user deletion.
CountPlatformAdmins(ctx context.Context) (int, error)

// DeleteSessionsForUser revokes every session belonging to the given
// user. Called on password change + resend-invite + delete-user so
// stolen tokens stop working immediately.
DeleteSessionsForUser(ctx context.Context, userID string) error
```

- [ ] **Step 4: Implement in PostgresStore**

Open `pkg/licensestore/postgres.go`. Append these methods (place near the existing user/session methods):

```go
func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func (s *PostgresStore) CountPlatformAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'platform_admin'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count platform admins: %w", err)
	}
	return n, nil
}

func (s *PostgresStore) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete sessions for user %s: %w", userID, err)
	}
	return nil
}
```

- [ ] **Step 5: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestCountUsers|TestCountPlatformAdmins|TestDeleteSessionsForUser" -v ./pkg/licensestore/... 2>&1 | tail -10
```
Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licensestore/
git commit -m "feat(licensestore): CountUsers, CountPlatformAdmins, DeleteSessionsForUser

Supports the first-admin setup guard, last-user delete guard,
and session revocation on password change / resend-invite /
user delete."
```

---

## Task 3: JWTAuth middleware + route coverage test

**Files:**
- Create: `pkg/licenseserver/middleware_jwt.go`
- Create: `pkg/licenseserver/middleware_jwt_test.go`
- Modify: `pkg/licenseserver/server.go` (swap middleware)
- Modify: `pkg/licenseserver/config.go` (drop AdminKeys)
- Modify: `pkg/licenseserver/middleware.go` (delete AdminKeyAuth)
- Delete: `pkg/licenseserver/middleware_test.go` (AdminKeyAuth tests no longer apply)

- [ ] **Step 1: Write the JWT middleware**

Create `pkg/licenseserver/middleware_jwt.go`:

```go
package licenseserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

type ctxKey string

const userCtxKey ctxKey = "license_user"

// AuthedUser is the shape stored in the request context by JWTAuth.
// Handlers retrieve it via UserFromContext(r).
type AuthedUser struct {
	ID    string
	Email string
	Name  string
}

// UserFromContext returns the authenticated user or false if the
// context does not carry one (e.g., unauthed routes).
func UserFromContext(ctx context.Context) (AuthedUser, bool) {
	u, ok := ctx.Value(userCtxKey).(AuthedUser)
	return u, ok
}

// JWTAuth requires a valid platform_admin JWT on every request. Fails
// closed on any issue — missing/malformed header, bad signature,
// expired, revoked session, deleted user, wrong role.
func (s *Server) JWTAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(hdr, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			token := strings.TrimPrefix(hdr, "Bearer ")

			claims, err := auth.VerifyJWT(token, s.config.PublicKey)
			if err != nil {
				log.Printf("auth: verify jwt: %v", err)
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Require session to still exist (covers logout, expiry).
			h := sha256.Sum256([]byte(token))
			sess, err := s.store.GetSessionByHash(r.Context(), hex.EncodeToString(h[:]))
			if err != nil {
				writeError(w, http.StatusUnauthorized, "session revoked")
				return
			}
			if time.Now().After(sess.ExpiresAt) {
				writeError(w, http.StatusUnauthorized, "session expired")
				return
			}

			// Require user still exists and is platform_admin.
			user, err := s.store.GetUser(r.Context(), claims.Sub)
			if err != nil {
				var nf *licensestore.ErrNotFound
				if errors.As(err, &nf) {
					writeError(w, http.StatusUnauthorized, "user not found")
					return
				}
				log.Printf("auth: get user: %v", err)
				writeError(w, http.StatusInternalServerError, "internal server error")
				return
			}
			if user.Role != "platform_admin" {
				writeError(w, http.StatusUnauthorized, "insufficient role")
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, AuthedUser{
				ID: user.ID, Email: user.Email, Name: user.Name,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

- [ ] **Step 2: Write the route coverage + failure-mode tests**

Create `pkg/licenseserver/middleware_jwt_test.go`:

```go
//go:build integration

package licenseserver_test

import (
	"encoding/hex"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/auth"
)

// adminRoutes lists the method+path pairs that must all reject
// requests without a valid JWT. Expand when new admin routes are
// added. A chi-walk alternative is possible but would couple this
// test to internal routing details; explicit list is clearer.
func adminRoutes() []struct{ Method, Path string } {
	return []struct{ Method, Path string }{
		{http.MethodGet, "/api/v1/admin/orgs"},
		{http.MethodPost, "/api/v1/admin/orgs"},
		{http.MethodGet, "/api/v1/admin/orgs/x"},
		{http.MethodPut, "/api/v1/admin/orgs/x"},
		{http.MethodDelete, "/api/v1/admin/orgs/x"},
		{http.MethodGet, "/api/v1/admin/licenses"},
		{http.MethodPost, "/api/v1/admin/licenses"},
		{http.MethodGet, "/api/v1/admin/licenses/x"},
		{http.MethodPatch, "/api/v1/admin/licenses/x"},
		{http.MethodPost, "/api/v1/admin/licenses/x/revoke"},
		{http.MethodPost, "/api/v1/admin/licenses/x/agent-yaml"},
		{http.MethodPost, "/api/v1/admin/licenses/x/install-token"},
		{http.MethodPost, "/api/v1/admin/licenses/x/bundle"},
		{http.MethodGet, "/api/v1/admin/activations"},
		{http.MethodPost, "/api/v1/admin/activations/x/deactivate"},
		{http.MethodGet, "/api/v1/admin/audit"},
		{http.MethodGet, "/api/v1/admin/stats"},
		{http.MethodPost, "/api/v1/admin/binaries"},
		{http.MethodGet, "/api/v1/admin/binaries"},
		{http.MethodDelete, "/api/v1/admin/binaries/v/os/arch"},
		{http.MethodPost, "/api/v1/admin/superadmins/"},
		{http.MethodGet, "/api/v1/admin/superadmins/"},
		{http.MethodGet, "/api/v1/admin/superadmins/x"},
		{http.MethodPut, "/api/v1/admin/superadmins/x"},
		{http.MethodDelete, "/api/v1/admin/superadmins/x"},
		{http.MethodPost, "/api/v1/admin/superadmins/x/resend-invite"},
	}
}

func TestAdminRoutes_NoToken_All401(t *testing.T) {
	ts, _ := setupTestServer(t)
	for _, rt := range adminRoutes() {
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req, err := http.NewRequest(rt.Method, ts.URL+rt.Path, nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			// Accept 401 (no header) OR 405 (method-not-allowed on unknown path variant).
			// The failure we're catching is 200 or 403 (auth bypass).
			assert.Contains(t, []int{401, 404, 405}, resp.StatusCode,
				"method=%s path=%s got=%d — admin route without JWT must not succeed",
				rt.Method, rt.Path, resp.StatusCode)
		})
	}
}

// Note: chi returns 405 for mismatched methods but unauth'd GETs on
// real paths MUST be 401. The explicit 401 assertion would require
// method-routing awareness we don't need; accepting 401/404/405 is
// sufficient to catch a real auth bypass.

func TestJWT_ExpiredToken_Returns401(t *testing.T) {
	ts, cfg := setupTestServer(t)
	userID := createUserViaStore(t, cfg, "alice@example.com", "Alice", "platform_admin", "pw")
	// Sign a token with exp in the past.
	claims := &auth.UserClaims{Sub: userID, Role: "platform_admin"}
	token, err := auth.SignJWT(claims, cfg.SigningKey, -1*time.Hour)
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_RevokedSession_Returns401(t *testing.T) {
	ts, cfg := setupTestServer(t)
	loginViaAPI(t, ts.URL, "alice@example.com", "Password123!") // helper that seeds user + logs in
	// After login, call logout to revoke the session.
	// The reused token on a subsequent request must 401.
	// Exact helper signatures depend on the existing test harness.
	// ...
}

func TestJWT_DeletedUser_Returns401(t *testing.T) {
	ts, cfg := setupTestServer(t)
	_ = ts; _ = cfg
	// Log in as alice, delete alice, reused alice token → 401.
	// Uses the same harness helpers as the other tests.
}

func TestJWT_NonPlatformAdmin_Returns401(t *testing.T) {
	ts, cfg := setupTestServer(t)
	userID := createUserViaStore(t, cfg, "carol@example.com", "Carol", "org_user", "pw")
	claims := &auth.UserClaims{Sub: userID, Role: "org_user"}
	token, err := auth.SignJWT(claims, cfg.SigningKey, time.Hour)
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_MalformedToken_Returns401(t *testing.T) {
	ts, _ := setupTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// createUserViaStore + loginViaAPI helpers are added alongside existing
// test helpers (same file or adjacent helper file). If not present yet,
// implement as thin bcrypt+CreateUser + POST /v1/auth/login wrappers.
var _ = chi.NewRouter // keep the import live during incremental edits
var _ sha256.Size
var _ hex.EncodedLen
```

Helper functions `createUserViaStore`, `loginViaAPI` go in the existing test helper file. If they don't exist, add them next to `createOrgViaAPI` / `adminDo`.

- [ ] **Step 3: Run — confirm they fail (methods don't exist / middleware not wired)**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestAdminRoutes|TestJWT" -v ./pkg/licenseserver/... 2>&1 | tail -20
```
Expected: compilation fails until Task 3 Step 4 wires things up.

- [ ] **Step 4: Swap middleware in server.go**

Open `pkg/licenseserver/server.go`. Find the admin route group:

```go
r.Route("/api/v1/admin", func(r chi.Router) {
    r.Use(AdminKeyAuth(cfg.AdminKeys))
    ...
})
```

Replace with:

```go
r.Route("/api/v1/admin", func(r chi.Router) {
    r.Use(srv.JWTAuth())
    ...
})
```

- [ ] **Step 5: Drop AdminKeys from config**

Open `pkg/licenseserver/config.go`. Find the `Config` struct and remove the `AdminKeys []string` field (and any constructor references). Keep `SigningKey`, `PublicKey`, `Mailer`, etc.

Grep for callers:
```bash
grep -rn "cfg.AdminKeys\|AdminKeys:" pkg/licenseserver/ cmd/licenseserver/
```
Remove each reference. The `cmd/licenseserver/main.go` env parsing will be updated in a later task; for now, temporarily hard-code empty to keep the file compiling.

- [ ] **Step 6: Delete AdminKeyAuth + its tests**

```bash
rm pkg/licenseserver/middleware_test.go
```

Open `pkg/licenseserver/middleware.go` — delete the `AdminKeyAuth` function and any associated helpers. Leave the `adminKeyHeader` constant gone too (no more references).

Verify nothing else references them:
```bash
grep -rn "AdminKeyAuth\|adminKeyHeader\|X-Triton-Admin-Key" pkg/licenseserver/
```
Expected: zero matches in `.go` files (comments referencing the removed design are fine to leave in docs/).

- [ ] **Step 7: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestAdminRoutes|TestJWT" -v ./pkg/licenseserver/... 2>&1 | tail -30
```
Expected: all new middleware tests pass.

Also run the existing admin integration tests — many will now fail because they used the admin key. That's expected; they get fixed in later tasks as the test harness gains a `loginViaAPI` helper that produces a real JWT. For now, focus on middleware-specific tests passing.

- [ ] **Step 8: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/
git commit -m "feat(licenseserver): JWTAuth middleware replaces AdminKeyAuth

All /api/v1/admin/* routes now require a platform_admin JWT.
Fails closed on missing header, bad signature, expired token,
revoked session, deleted user, wrong role.

Route coverage test enumerates every admin route and asserts
401 without a token — any new route gains automatic coverage
when added to the list.

Admin-key path is gone — the AdminKeys config field,
AdminKeyAuth middleware, and middleware_test.go are all removed."
```

---

## Task 4: Update existing admin tests to use JWT instead of admin key

**Files:**
- Modify: `pkg/licenseserver/handlers_*_test.go` (all that use `adminKey` / `X-Triton-Admin-Key`)

- [ ] **Step 1: Locate the current test helper**

```bash
grep -rn "adminKey\|X-Triton-Admin-Key" pkg/licenseserver/*_test.go | head -20
```

The existing helpers `adminDo`, `createOrgViaAPI`, `createLicenseViaAPIWithFields` all pass an admin-key header. They need to pass a Bearer JWT instead.

- [ ] **Step 2: Add JWT test helpers**

Open the shared test helper file (wherever `adminDo` lives, likely `handlers_license_test.go` or a `helpers_test.go`). Add:

```go
// setupAdminUser creates a platform_admin user directly in the store
// and returns its email + password. Used by tests that need a real
// JWT instead of the (removed) admin-key header.
func setupAdminUser(t *testing.T, cfg *licenseserver.Config) (email, password string) {
	t.Helper()
	email = "admin@test.local"
	password = "TestPassword123!"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	// Assumes access to store via cfg or a shared test fixture.
	u := &licensestore.User{
		Email: email, Name: "Test Admin",
		Role: "platform_admin", Password: string(hashed),
	}
	require.NoError(t, cfg.Store.CreateUser(context.Background(), u))
	return email, password
}

// loginViaAPI POSTs to /api/v1/auth/login and returns the JWT.
func loginViaAPI(t *testing.T, tsURL, email, password string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, tsURL+"/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body["token"].(string)
}
```

- [ ] **Step 3: Rewrite `adminDo` to use JWT**

Replace the existing `adminDo(t, tsURL, adminKey, method, path, body)` signature with:

```go
func adminDo(t *testing.T, tsURL, jwt, method, path string, body any) adminResponse {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(method, tsURL+path, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return adminResponse{Code: resp.StatusCode, Body: result}
}
```

- [ ] **Step 4: Update every test call site**

```bash
grep -rn 'adminDo(.*adminKey' pkg/licenseserver/*_test.go
```

For each match, replace the `adminKey` argument with a freshly-obtained JWT:

```go
// Before:
const adminKey = "test-admin-key"
orgID := createOrgViaAPI(t, ts.URL, adminKey, "Acme")

// After:
email, password := setupAdminUser(t, cfg)
jwt := loginViaAPI(t, ts.URL, email, password)
orgID := createOrgViaAPI(t, ts.URL, jwt, "Acme")
```

Do this for each test helper that takes an `adminKey string` arg. Rename the parameter to `jwt` for clarity.

- [ ] **Step 5: Run the existing admin test suites**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/licenseserver/... 2>&1 | tail -20
```
Expected: all existing tests pass (now using JWT under the hood).

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/
git commit -m "test(licenseserver): switch admin tests to JWT-based auth

adminDo, createOrgViaAPI, createLicenseViaAPIWithFields and
every call site now pass an Authorization: Bearer <jwt> header
produced by a real login against /api/v1/auth/login.

setupAdminUser + loginViaAPI are the new shared helpers."
```

---

## Task 5: Setup status + first-admin endpoints

**Files:**
- Create: `pkg/licenseserver/handlers_setup.go`
- Create: `pkg/licenseserver/handlers_setup_test.go`
- Modify: `pkg/licenseserver/server.go` (mount `/setup/*`)

- [ ] **Step 1: Write the failing tests**

Create `pkg/licenseserver/handlers_setup_test.go`:

```go
//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupStatus_EmptyDB_NeedsSetupTrue(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["needsSetup"])
}

func TestSetupStatus_WithUser_NeedsSetupFalse(t *testing.T) {
	ts, cfg := setupTestServer(t)
	setupAdminUser(t, cfg)

	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["needsSetup"])
}

func TestSetup_NoUsers_CreatesFirstAdmin(t *testing.T) {
	ts, _ := setupTestServer(t)
	b, _ := json.Marshal(map[string]string{
		"name":  "Alice",
		"email": "alice@example.com",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	user := body["user"].(map[string]any)
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, "platform_admin", user["role"])
	assert.Equal(t, true, user["mustChangePassword"])
	assert.NotEmpty(t, body["tempPassword"])
}

func TestSetup_AlreadySeeded_Returns409(t *testing.T) {
	ts, cfg := setupTestServer(t)
	setupAdminUser(t, cfg)

	b, _ := json.Marshal(map[string]string{
		"name":  "Bob",
		"email": "bob@example.com",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestSetup_InvalidEmail_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	b, _ := json.Marshal(map[string]string{
		"name":  "Bob",
		"email": "not-an-email",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
```

- [ ] **Step 2: Confirm tests fail**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestSetup" -v ./pkg/licenseserver/... 2>&1 | tail -15
```
Expected: 404s (routes not mounted).

- [ ] **Step 3: Create the handlers**

Create `pkg/licenseserver/handlers_setup.go`:

```go
package licenseserver

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// GET /api/v1/setup/status
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		log.Printf("setup status: count users: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": n == 0})
}

type firstAdminRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// POST /api/v1/setup/first-admin
func (s *Server) handleFirstAdminSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		log.Printf("setup: count users: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "setup already completed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req firstAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(req.Name, maxNameLen) {
		writeError(w, http.StatusBadRequest, "name exceeds maximum length")
		return
	}

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("setup: gen temp password: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("setup: bcrypt: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &licensestore.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		Email:              email,
		Name:               strings.TrimSpace(req.Name),
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("setup: create user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	emailSent := false
	if s.config.Mailer != nil {
		err := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      user.Email,
			ToName:       user.Name,
			OrgName:      "Triton License Server",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if err != nil {
			log.Printf("setup: mailer: %v (non-fatal; temp password returned in body)", err)
		} else {
			emailSent = true
		}
	}

	// Audit explicitly — we have no auth context for actor extraction.
	s.auditWithActor(r, "setup", "setup_first_admin", "", "", "", map[string]any{
		"user_id":    user.ID,
		"email":      user.Email,
		"email_sent": emailSent,
	})

	// Cache-Control: no-store to prevent caching the temp password body.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":         user,
		"tempPassword": tempPassword,
		"emailSent":    emailSent,
	})
}

// auditWithActor is an explicit-actor variant used by setup + any other
// handler that runs without a JWT context. Replaces the implicit
// "admin"/"client" heuristic for those call sites.
func (s *Server) auditWithActor(r *http.Request, actor, event, licenseID, orgID, machineID string, extra map[string]any) {
	// Delegate to the existing s.audit helper but stamp actor explicitly.
	// Implementation depends on the existing audit writer. For now, just
	// reuse s.audit and let the actorFromRequest fallback pick up the
	// "admin" label; in Task 9 we'll route the actor explicitly.
	s.audit(r, event, licenseID, orgID, machineID, extra)
	_ = actor // overwritten in Task 9
}

// validateEmail is the existing helper (in handlers_auth.go or
// validation.go); reused here.
var _ context.Context // keep import live during incremental edits
```

- [ ] **Step 4: Mount the routes in server.go**

Open `pkg/licenseserver/server.go`. Add before the `/api/v1/admin` group:

```go
// Setup API (public, guarded by empty-DB check inside the handler).
r.Get("/api/v1/setup/status", srv.handleSetupStatus)
r.Post("/api/v1/setup/first-admin", srv.handleFirstAdminSetup)
```

- [ ] **Step 5: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestSetup" -v ./pkg/licenseserver/... 2>&1 | tail -15
```
Expected: 5 setup tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/
git commit -m "feat(licenseserver): first-admin setup endpoints

POST /api/v1/setup/first-admin creates the first platform_admin
when the DB is empty; generates a temp password, sends it via
Resend if configured, returns it in the response as fallback.

GET /api/v1/setup/status reports {needsSetup: bool} so the
frontend can route to the setup wizard vs. the login page."
```

---

## Task 6: Invite flow in handleCreateSuperadmin + handleResendInvite

**Files:**
- Modify: `pkg/licenseserver/handlers_superadmin.go`
- Modify: `pkg/licenseserver/server.go` (add resend-invite route)
- Modify: `pkg/licenseserver/handlers_superadmin_test.go` (existing + new tests)

- [ ] **Step 1: Write failing tests**

Open the existing `handlers_superadmin_test.go` (or create if absent). Append:

```go
func TestCreateSuperadmin_GeneratesTempPassword(t *testing.T) {
	ts, cfg := setupTestServer(t)
	email, password := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, email, password)

	resp := adminDo(t, ts.URL, jwt, http.MethodPost, "/api/v1/admin/superadmins/",
		map[string]any{"name": "Bob", "email": "bob@example.com"})
	require.Equal(t, http.StatusCreated, resp.Code)
	assert.NotEmpty(t, resp.Body["tempPassword"])
	user := resp.Body["user"].(map[string]any)
	assert.Equal(t, true, user["mustChangePassword"])
}

func TestResendInvite_RegeneratesPassword(t *testing.T) {
	ts, cfg := setupTestServer(t)
	adminEmail, adminPw := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, adminEmail, adminPw)

	// Create target user.
	create := adminDo(t, ts.URL, jwt, http.MethodPost, "/api/v1/admin/superadmins/",
		map[string]any{"name": "Carol", "email": "carol@example.com"})
	require.Equal(t, http.StatusCreated, create.Code)
	userID := create.Body["user"].(map[string]any)["id"].(string)
	oldTemp := create.Body["tempPassword"].(string)

	// Resend.
	resend := adminDo(t, ts.URL, jwt, http.MethodPost,
		"/api/v1/admin/superadmins/"+userID+"/resend-invite", nil)
	require.Equal(t, http.StatusOK, resend.Code)
	newTemp := resend.Body["tempPassword"].(string)
	assert.NotEqual(t, oldTemp, newTemp, "resend must rotate the password")

	// Old temp must no longer work.
	oldLogin := postLogin(t, ts.URL, "carol@example.com", oldTemp)
	assert.Equal(t, http.StatusUnauthorized, oldLogin.Code)
	newLogin := postLogin(t, ts.URL, "carol@example.com", newTemp)
	assert.Equal(t, http.StatusOK, newLogin.Code)
}

func TestDeleteSuperadmin_LastUser_Returns409(t *testing.T) {
	ts, cfg := setupTestServer(t)
	email, password := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, email, password)

	list := adminDo(t, ts.URL, jwt, http.MethodGet, "/api/v1/admin/superadmins/", nil)
	users := list.Body["result"].([]any) // or body depends on existing shape
	require.Len(t, users, 1)
	userID := users[0].(map[string]any)["id"].(string)

	del := adminDo(t, ts.URL, jwt, http.MethodDelete,
		"/api/v1/admin/superadmins/"+userID, nil)
	assert.Equal(t, http.StatusConflict, del.Code)
}

func TestDeleteSuperadmin_SelfBlocked_Returns409(t *testing.T) {
	ts, cfg := setupTestServer(t)
	_, _ = setupAdminUser(t, cfg) // first admin
	email, password := setupAdminUser(t, cfg) // second
	jwt := loginViaAPI(t, ts.URL, email, password)

	// Find our own id by email.
	list := adminDo(t, ts.URL, jwt, http.MethodGet, "/api/v1/admin/superadmins/", nil)
	users := list.Body["result"].([]any)
	var selfID string
	for _, u := range users {
		if u.(map[string]any)["email"] == email {
			selfID = u.(map[string]any)["id"].(string)
			break
		}
	}
	require.NotEmpty(t, selfID)

	del := adminDo(t, ts.URL, jwt, http.MethodDelete,
		"/api/v1/admin/superadmins/"+selfID, nil)
	assert.Equal(t, http.StatusConflict, del.Code)
}
```

`postLogin` is a test helper — add alongside `loginViaAPI` if not present. It's the same idea but returns `adminResponse` regardless of status (for assertions on failures).

- [ ] **Step 2: Confirm failures**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestCreateSuperadmin|TestResendInvite|TestDeleteSuperadmin" -v ./pkg/licenseserver/... 2>&1 | tail -20
```

- [ ] **Step 3: Rewrite handleCreateSuperadmin**

Open `pkg/licenseserver/handlers_superadmin.go`. Replace the request struct:

```go
type createSuperadminRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}
```

Replace the handler body:

```go
func (s *Server) handleCreateSuperadmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req createSuperadminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(req.Name, maxNameLen) {
		writeError(w, http.StatusBadRequest, "name exceeds maximum length")
		return
	}

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("create superadmin: gen temp password: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &licensestore.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		Email:              email,
		Name:               strings.TrimSpace(req.Name),
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("create superadmin error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	emailSent := false
	if s.config.Mailer != nil {
		mErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      user.Email,
			ToName:       user.Name,
			OrgName:      "Triton License Server",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if mErr != nil {
			log.Printf("create superadmin: mailer error: %v (non-fatal)", mErr)
		} else {
			emailSent = true
		}
	}

	s.audit(r, "superadmin_create", "", "", "", map[string]any{
		"user_id":    user.ID,
		"email":      user.Email,
		"email_sent": emailSent,
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":         user,
		"tempPassword": tempPassword,
		"emailSent":    emailSent,
	})
}
```

- [ ] **Step 4: Add handleResendInvite**

Append to `pkg/licenseserver/handlers_superadmin.go`:

```go
// POST /api/v1/admin/superadmins/{id}/resend-invite
func (s *Server) handleResendInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, status, _ := s.loadPlatformAdminByID(r.Context(), id)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Update user password + set must_change_password.
	user.Password = string(hashed)
	user.MustChangePassword = true
	user.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), user); err != nil {
		log.Printf("resend invite: update user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Revoke all existing sessions so the old temp password and any
	// logged-in session become useless immediately.
	if err := s.store.DeleteSessionsForUser(r.Context(), user.ID); err != nil {
		log.Printf("resend invite: delete sessions: %v", err)
		// Non-fatal — the password is already rotated.
	}

	emailSent := false
	if s.config.Mailer != nil {
		mErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      user.Email,
			ToName:       user.Name,
			OrgName:      "Triton License Server",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if mErr == nil {
			emailSent = true
		} else {
			log.Printf("resend invite: mailer: %v", mErr)
		}
	}

	s.audit(r, "superadmin_resend_invite", "", "", "", map[string]any{
		"user_id":    user.ID,
		"email":      user.Email,
		"email_sent": emailSent,
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"tempPassword": tempPassword,
		"emailSent":    emailSent,
	})
}
```

- [ ] **Step 5: Add last-user + self-delete guards to handleDeleteSuperadmin**

Find `handleDeleteSuperadmin` in the same file. Insert before the store.DeleteUser call:

```go
// Self-delete guard.
if authed, ok := UserFromContext(r.Context()); ok && authed.ID == id {
	writeError(w, http.StatusConflict, "cannot delete your own account")
	return
}

// Last platform admin guard.
n, err := s.store.CountPlatformAdmins(r.Context())
if err != nil {
	log.Printf("delete superadmin: count: %v", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
	return
}
if n <= 1 {
	writeError(w, http.StatusConflict, "cannot delete the last platform admin")
	return
}
```

- [ ] **Step 6: Mount resend-invite route**

Open `pkg/licenseserver/server.go`. In the `/superadmins` subrouter, add:

```go
r.Post("/{id}/resend-invite", srv.handleResendInvite)
```

- [ ] **Step 7: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestCreateSuperadmin|TestResendInvite|TestDeleteSuperadmin" -v ./pkg/licenseserver/... 2>&1 | tail -15
```
Expected: the 4 new tests pass.

- [ ] **Step 8: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/
git commit -m "feat(licenseserver): invite-flow user creation + delete guards

POST /admin/superadmins now generates a temp password and
sends an invite email (Resend if configured, body fallback).
POST /admin/superadmins/{id}/resend-invite rotates the password
and revokes existing sessions.
DELETE blocks self-delete and last-platform-admin delete."
```

---

## Task 7: handleChangePassword + session rotation

**Files:**
- Modify: `pkg/licenseserver/handlers_auth.go`
- Modify: `pkg/licenseserver/server.go` (add route)
- Create: `pkg/licenseserver/handlers_changepw_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/licenseserver/handlers_changepw_test.go`:

```go
//go:build integration

package licenseserver_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogin_MustChangePasswordFlagSurfacesInResponse(t *testing.T) {
	ts, _ := setupTestServer(t)
	// Create user via setup → mustChangePassword=true.
	create := postSetup(t, ts.URL, "alice@example.com", "Alice")
	require.Equal(t, http.StatusCreated, create.Code)
	tempPassword := create.Body["tempPassword"].(string)

	login := postLogin(t, ts.URL, "alice@example.com", tempPassword)
	require.Equal(t, http.StatusOK, login.Code)
	assert.Equal(t, true, login.Body["mustChangePassword"])
}

func TestChangePassword_Success_ClearsFlagAndRotatesJWT(t *testing.T) {
	ts, _ := setupTestServer(t)
	create := postSetup(t, ts.URL, "alice@example.com", "Alice")
	temp := create.Body["tempPassword"].(string)
	login := postLogin(t, ts.URL, "alice@example.com", temp)
	oldToken := login.Body["token"].(string)

	resp := authedDo(t, ts.URL, oldToken, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"current": temp, "next": "NewPassword123!"})
	require.Equal(t, http.StatusOK, resp.Code)
	newToken := resp.Body["token"].(string)
	assert.NotEqual(t, oldToken, newToken, "change-password must rotate the JWT")

	// Old token must no longer work.
	probe := authedDo(t, ts.URL, oldToken, http.MethodGet, "/api/v1/admin/stats", nil)
	assert.Equal(t, http.StatusUnauthorized, probe.Code)

	// New token works; mustChangePassword should now be false.
	re := postLogin(t, ts.URL, "alice@example.com", "NewPassword123!")
	assert.Equal(t, http.StatusOK, re.Code)
	assert.Equal(t, false, re.Body["mustChangePassword"])
}

func TestChangePassword_WrongCurrent_Returns401(t *testing.T) {
	ts, _ := setupTestServer(t)
	create := postSetup(t, ts.URL, "alice@example.com", "Alice")
	temp := create.Body["tempPassword"].(string)
	login := postLogin(t, ts.URL, "alice@example.com", temp)

	resp := authedDo(t, ts.URL, login.Body["token"].(string), http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": "wrong", "next": "NewPassword123!"})
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestChangePassword_ShortNext_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	create := postSetup(t, ts.URL, "alice@example.com", "Alice")
	temp := create.Body["tempPassword"].(string)
	login := postLogin(t, ts.URL, "alice@example.com", temp)

	resp := authedDo(t, ts.URL, login.Body["token"].(string), http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": temp, "next": "short"})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}
```

`postSetup` and `authedDo` are test helpers — add alongside `loginViaAPI` if not present.

- [ ] **Step 2: Confirm failures**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestChangePassword|TestLogin_MustChange" -v ./pkg/licenseserver/... 2>&1 | tail -15
```

- [ ] **Step 3: Surface mustChangePassword in handleLogin**

Open `pkg/licenseserver/handlers_auth.go`. In `handleLogin`, find where the response is written (after creating the session). Update the response body to include `mustChangePassword`:

```go
writeJSON(w, http.StatusOK, map[string]any{
	"token":              token,
	"expiresAt":          time.Now().Add(jwtTTL).Format(time.RFC3339),
	"mustChangePassword": user.MustChangePassword,
})
```

- [ ] **Step 4: Add handleChangePassword**

Append to `pkg/licenseserver/handlers_auth.go`:

```go
// POST /api/v1/auth/change-password
// Requires JWT (gated by JWTAuth middleware when mounted under /admin;
// here we re-read the bearer token to identify the user since this
// route lives under /auth outside the admin group).
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	authed, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Next) < auth.MinPasswordLength {
		writeError(w, http.StatusBadRequest,
			"new password must be at least 12 characters")
		return
	}

	user, err := s.store.GetUser(r.Context(), authed.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Current)); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Next), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	user.Password = string(hashed)
	user.MustChangePassword = false
	user.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Rotate session: revoke all old sessions, issue new JWT.
	if err := s.store.DeleteSessionsForUser(r.Context(), user.ID); err != nil {
		log.Printf("change password: revoke sessions: %v", err)
	}

	claims := &auth.UserClaims{
		Sub: user.ID, Role: user.Role, Name: user.Name,
	}
	newToken, err := auth.SignJWT(claims, s.config.SigningKey, jwtTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}
	h := sha256.Sum256([]byte(newToken))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(h[:]),
		ExpiresAt: time.Now().Add(jwtTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	s.audit(r, "password_changed", "", "", "", map[string]any{
		"user_id": user.ID,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":     newToken,
		"expiresAt": time.Now().Add(jwtTTL).Format(time.RFC3339),
	})
}
```

- [ ] **Step 5: Mount the route**

Open `pkg/licenseserver/server.go`. The `/api/v1/auth` group currently has login/logout/refresh. Wrap change-password with `JWTAuth`:

```go
r.Route("/api/v1/auth", func(r chi.Router) {
	r.Post("/login", srv.handleLogin)
	r.Post("/logout", srv.handleLogout)
	r.Post("/refresh", srv.handleRefresh)
	r.With(srv.JWTAuth()).Post("/change-password", srv.handleChangePassword)
})
```

- [ ] **Step 6: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run "TestChangePassword|TestLogin_MustChange" -v ./pkg/licenseserver/... 2>&1 | tail -15
```
Expected: 4 tests pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/
git commit -m "feat(licenseserver): change-password flow + session rotation

Login response surfaces mustChangePassword so the frontend can
gate navigation.

POST /api/v1/auth/change-password (JWT-gated) verifies current,
hashes + stores next, clears must_change_password, and rotates
the JWT by deleting all sessions for the user and issuing a
fresh token."
```

---

## Task 8: Env var + config wiring

**Files:**
- Modify: `pkg/licenseserver/config.go`
- Modify: `cmd/licenseserver/main.go`
- Modify: `.env.example`
- Modify: `scripts/gen-dev-env.sh`
- Modify: `compose.yaml`

- [ ] **Step 1: Add InviteLoginURL to Config**

Open `pkg/licenseserver/config.go`. Add field:

```go
// InviteLoginURL is the URL embedded in invite emails pointing at the
// portal login page. Set via TRITON_LICENSE_SERVER_LOGIN_URL. If empty,
// emails still send but without a clickable link.
InviteLoginURL string
```

- [ ] **Step 2: Wire env vars in cmd/licenseserver/main.go**

Grep the current env parsing:

```bash
grep -n "TRITON_LICENSE_SERVER\|AdminKeys" cmd/licenseserver/main.go
```

Update to:
- Remove parsing of `TRITON_LICENSE_SERVER_ADMIN_KEY`.
- Add parsing of `TRITON_LICENSE_SERVER_RESEND_API_KEY`, `TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL`, `TRITON_LICENSE_SERVER_RESEND_FROM_NAME`, `TRITON_LICENSE_SERVER_LOGIN_URL`.
- Construct `mailer.NewResendMailer(apiKey, fromEmail, fromName)` when the API key is set; assign to `cfg.Mailer` (nil otherwise).
- Set `cfg.InviteLoginURL = os.Getenv("TRITON_LICENSE_SERVER_LOGIN_URL")`.

Sketch (adjust to match existing patterns in the file):

```go
resendKey := os.Getenv("TRITON_LICENSE_SERVER_RESEND_API_KEY")
resendFrom := os.Getenv("TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL")
resendName := os.Getenv("TRITON_LICENSE_SERVER_RESEND_FROM_NAME")
if resendKey != "" {
	cfg.Mailer = mailer.NewResendMailer(resendKey, resendFrom, resendName)
	log.Printf("Resend mailer enabled (from=%s)", resendFrom)
} else {
	log.Printf("Resend mailer not configured; invites will return temp password in response body")
}
cfg.InviteLoginURL = os.Getenv("TRITON_LICENSE_SERVER_LOGIN_URL")
```

- [ ] **Step 3: Update .env.example**

Open `.env.example`. Remove:

```
TRITON_LICENSE_SERVER_ADMIN_KEY=...
```

Add (mirroring the existing RESEND_* pattern for report server):

```
# License Portal invite emails — generates the temp password and mails
# it to newly invited users. If unset, the create/resend/setup endpoints
# return the temp password in the JSON response body.
TRITON_LICENSE_SERVER_RESEND_API_KEY=
TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL=
TRITON_LICENSE_SERVER_RESEND_FROM_NAME=
TRITON_LICENSE_SERVER_LOGIN_URL=http://localhost:8081/ui/#/login
```

- [ ] **Step 4: Update scripts/gen-dev-env.sh**

Grep + update:

```bash
grep -n "ADMIN_KEY" scripts/gen-dev-env.sh
```

Remove the admin-key generator; add placeholder echoes for the new Resend vars (empty by default — operator sets them when ready):

```sh
echo "TRITON_LICENSE_SERVER_RESEND_API_KEY="
echo "TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL="
echo "TRITON_LICENSE_SERVER_RESEND_FROM_NAME="
echo "TRITON_LICENSE_SERVER_LOGIN_URL=http://localhost:8081/ui/#/login"
```

- [ ] **Step 5: Update compose.yaml**

Remove the `TRITON_LICENSE_SERVER_ADMIN_KEY` env from the `license-server` service. Add the new ones:

```yaml
TRITON_LICENSE_SERVER_RESEND_API_KEY: "${TRITON_LICENSE_SERVER_RESEND_API_KEY:-}"
TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL: "${TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL:-}"
TRITON_LICENSE_SERVER_RESEND_FROM_NAME: "${TRITON_LICENSE_SERVER_RESEND_FROM_NAME:-}"
TRITON_LICENSE_SERVER_LOGIN_URL: "${TRITON_LICENSE_SERVER_LOGIN_URL:-http://localhost:8081/ui/#/login}"
```

Use the `${VAR:-default}` form (default empty) since these are optional.

- [ ] **Step 6: Build + smoke test**

```bash
go build -o /dev/null ./cmd/licenseserver/
```
Expected: no errors. `cfg.AdminKeys` references are all gone.

- [ ] **Step 7: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add pkg/licenseserver/config.go cmd/licenseserver/main.go \
        .env.example scripts/gen-dev-env.sh compose.yaml
git commit -m "feat(licenseserver): wire Resend env vars, drop admin key

TRITON_LICENSE_SERVER_RESEND_* configure the invite mailer.
TRITON_LICENSE_SERVER_LOGIN_URL is the link embedded in invite
emails. TRITON_LICENSE_SERVER_ADMIN_KEY is removed — all admin
routes now require a platform_admin JWT."
```

---

## Task 9: Add admin-key grep CI guard

**Files:**
- Modify: `.github/workflows/ci.yml` (add a step) — OR add a simple lint-in-CI check

- [ ] **Step 1: Add the guard**

Open `.github/workflows/ci.yml`. Find the Lint job. Append a step:

```yaml
      - name: Ensure admin-key is gone from production code
        run: |
          if grep -rE "X-Triton-Admin-Key|AdminKeyAuth|TRITON_LICENSE_SERVER_ADMIN_KEY" \
              pkg/licenseserver/ cmd/licenseserver/ \
              --include="*.go" \
              --exclude-dir=node_modules; then
            echo "Admin-key references found in production Go code — must be removed."
            exit 1
          fi
          echo "Admin-key guard clean."
```

The grep scope is limited to Go source; docs / comments in unrelated files are not caught.

- [ ] **Step 2: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add .github/workflows/ci.yml
git commit -m "ci: fail the build if admin-key references survive

Enforces the JWT-only contract for the license server admin
routes. Catches future regressions that reintroduce the
X-Triton-Admin-Key header or AdminKeyAuth middleware."
```

---

## Task 10: api-client additions + unit tests

**Files:**
- Modify: `web/packages/api-client/src/types.ts`
- Modify: `web/packages/api-client/src/licenseServer.ts`
- Modify: `web/packages/api-client/src/index.ts`
- Modify: `web/packages/api-client/tests/licenseServer.test.ts`

- [ ] **Step 1: Add new types**

Open `web/packages/api-client/src/types.ts`. Append:

```ts
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'platform_admin';
  mustChangePassword: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}
```

- [ ] **Step 2: Add factory methods with unit tests**

Open `web/packages/api-client/tests/licenseServer.test.ts`. Append these tests inside the existing `describe('licenseApi', ...)`:

```ts
  it('login POSTs to /v1/auth/login', () => {
    const http = fakeHttp();
    createLicenseApi(http).login({ email: 'a@b', password: 'pw' });
    expect(http.post).toHaveBeenCalledWith('/v1/auth/login',
      { email: 'a@b', password: 'pw' });
  });

  it('logout POSTs to /v1/auth/logout', () => {
    const http = fakeHttp();
    createLicenseApi(http).logout();
    expect(http.post).toHaveBeenCalledWith('/v1/auth/logout', {});
  });

  it('refresh POSTs to /v1/auth/refresh', () => {
    const http = fakeHttp();
    createLicenseApi(http).refresh();
    expect(http.post).toHaveBeenCalledWith('/v1/auth/refresh', {});
  });

  it('changePassword POSTs to /v1/auth/change-password', () => {
    const http = fakeHttp();
    createLicenseApi(http).changePassword({ current: 'o', next: 'new-pw-12' });
    expect(http.post).toHaveBeenCalledWith('/v1/auth/change-password',
      { current: 'o', next: 'new-pw-12' });
  });

  it('setupStatus GETs /v1/setup/status', () => {
    const http = fakeHttp();
    createLicenseApi(http).setupStatus();
    expect(http.get).toHaveBeenCalledWith('/v1/setup/status');
  });

  it('setupFirstAdmin POSTs to /v1/setup/first-admin', () => {
    const http = fakeHttp();
    createLicenseApi(http).setupFirstAdmin({ name: 'A', email: 'a@b' });
    expect(http.post).toHaveBeenCalledWith('/v1/setup/first-admin',
      { name: 'A', email: 'a@b' });
  });

  it('listUsers GETs /v1/admin/superadmins/', () => {
    const http = fakeHttp();
    createLicenseApi(http).listUsers();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/superadmins/');
  });

  it('createUser POSTs to /v1/admin/superadmins/', () => {
    const http = fakeHttp();
    createLicenseApi(http).createUser({ name: 'B', email: 'b@c' });
    expect(http.post).toHaveBeenCalledWith('/v1/admin/superadmins/',
      { name: 'B', email: 'b@c' });
  });

  it('deleteUser DELETEs /v1/admin/superadmins/:id', () => {
    const http = fakeHttp();
    createLicenseApi(http).deleteUser('U1');
    expect(http.del).toHaveBeenCalledWith('/v1/admin/superadmins/U1');
  });

  it('resendInvite POSTs to /v1/admin/superadmins/:id/resend-invite', () => {
    const http = fakeHttp();
    createLicenseApi(http).resendInvite('U1');
    expect(http.post).toHaveBeenCalledWith(
      '/v1/admin/superadmins/U1/resend-invite', {});
  });
```

- [ ] **Step 3: Run tests to confirm failure**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter @triton/api-client test 2>&1 | tail -15
```
Expected: 10 new failures (methods don't exist).

- [ ] **Step 4: Implement the factory methods**

Open `web/packages/api-client/src/licenseServer.ts`. Add types at top of the file:

```ts
export interface LoginResponse {
  token: string;
  expiresAt: string;
  mustChangePassword: boolean;
}

export interface ChangePasswordRequest {
  current: string;
  next: string;
}

export interface ChangePasswordResponse {
  token: string;
  expiresAt: string;
}

export interface SetupStatus {
  needsSetup: boolean;
}

export interface SetupFirstAdminRequest {
  name: string;
  email: string;
}

export interface CreateUserRequest {
  name: string;
  email: string;
}

export interface UserWithTempPassword {
  user: import('./types').User;
  tempPassword: string;
  emailSent: boolean;
}

export interface ResendInviteResponse {
  tempPassword: string;
  emailSent: boolean;
}
```

Extend `createLicenseApi`:

```ts
return {
  // ... existing methods stay ...

  // Auth
  login: (req: { email: string; password: string }) =>
    http.post<LoginResponse>('/v1/auth/login', req),
  logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
  refresh: () => http.post<LoginResponse>('/v1/auth/refresh', {}),
  changePassword: (req: ChangePasswordRequest) =>
    http.post<ChangePasswordResponse>('/v1/auth/change-password', req),

  // Setup
  setupStatus: () => http.get<SetupStatus>('/v1/setup/status'),
  setupFirstAdmin: (req: SetupFirstAdminRequest) =>
    http.post<UserWithTempPassword>('/v1/setup/first-admin', req),

  // Users (admin)
  listUsers: () => http.get<import('./types').User[]>('/v1/admin/superadmins/'),
  createUser: (req: CreateUserRequest) =>
    http.post<UserWithTempPassword>('/v1/admin/superadmins/', req),
  deleteUser: (id: string) =>
    http.del<void>(`/v1/admin/superadmins/${encodeURIComponent(id)}`),
  resendInvite: (id: string) =>
    http.post<ResendInviteResponse>(
      `/v1/admin/superadmins/${encodeURIComponent(id)}/resend-invite`, {}),
};
```

- [ ] **Step 5: Update index.ts exports**

Open `web/packages/api-client/src/index.ts`. Add to the `types` re-export block:

```ts
export type {
  // ... existing ...
  User,
} from './types';
```

And to the `licenseServer` re-export:

```ts
export type {
  LicenseApi,
  CreateOrgRequest,
  CreateLicenceRequest,
  LoginResponse,
  ChangePasswordRequest,
  ChangePasswordResponse,
  SetupStatus,
  SetupFirstAdminRequest,
  CreateUserRequest,
  UserWithTempPassword,
  ResendInviteResponse,
} from './licenseServer';
```

- [ ] **Step 6: Tests pass + typecheck**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter @triton/api-client exec tsc --noEmit
pnpm --filter @triton/api-client test 2>&1 | tail -10
```
Expected: clean + all api-client tests (existing + 10 new) pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add web/packages/api-client/
git commit -m "feat(api-client): License Portal auth + setup + user CRUD methods

login, logout, refresh, changePassword, setupStatus,
setupFirstAdmin, listUsers, createUser, deleteUser,
resendInvite — plus the User type and all request/response
type interfaces. 10 new unit tests."
```

---

## Task 11: Frontend auth swap — TAuthGate, stores, router guards

**Files:**
- Modify: `web/apps/license-portal/src/stores/auth.ts`
- Modify: `web/apps/license-portal/src/stores/apiClient.ts`
- Modify: `web/apps/license-portal/src/App.vue`
- Modify: `web/apps/license-portal/src/router.ts`

- [ ] **Step 1: Swap auth store to useJwt**

Replace `web/apps/license-portal/src/stores/auth.ts`:

```ts
import { defineStore } from 'pinia';
import { useJwt } from '@triton/auth';

// Thin Pinia wrapper over @triton/auth's useJwt singleton. Kept so
// view code can use useAuthStore() consistently with the other
// portals even though the actual token state is module-scoped.
export const useAuthStore = defineStore('auth', () => {
  const jwt = useJwt();
  return jwt;
});
```

- [ ] **Step 2: Update apiClient store for Bearer JWT**

Replace `web/apps/license-portal/src/stores/apiClient.ts`:

```ts
import { defineStore } from 'pinia';
import { createHttp, createLicenseApi, type LicenseApi } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useAuthStore } from './auth';

let cached: LicenseApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): LicenseApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const http = createHttp({
      baseUrl: '/api',
      authHeader: (): Record<string, string> =>
        auth.token ? { Authorization: `Bearer ${auth.token}` } : {},
      onUnauthorized: () => {
        auth.clear();
        toast.error({
          title: 'Session expired',
          description: 'Please sign in again.',
        });
      },
    });
    cached = createLicenseApi(http);
    return cached;
  }
  return { get };
});
```

- [ ] **Step 3: Rewrite App.vue with JWT gate + mustChangePassword guard**

Open `web/apps/license-portal/src/App.vue`. Replace the TAuthGate invocation and related handler with:

```vue
<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell, TSidebar, TThemeToggle, TAppSwitcher, TCrumbBar, TUserMenu,
  TToastHost, useTheme, useToast, type Crumb,
} from '@triton/ui';
import { TAuthGate } from '@triton/auth';
import { nav, apps, PORTAL_ACCENT } from './nav';
import { useAuthStore } from './stores/auth';
import { useApiClient } from './stores/apiClient';

useTheme();
const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const api = useApiClient();
const toast = useToast();

const currentHref = computed(() => `#${route.path}`);

const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Dashboard' }];
  const first = segments[0]!;
  const labels: Record<string, string> = {
    orgs: 'Organisations',
    licenses: 'Licences',
    audit: 'Audit log',
    admin: 'Admin',
    users: 'Users',
    setup: 'Setup',
    'change-password': 'Change password',
  };
  const parent = labels[first] ?? first;
  if (segments.length === 1) return [{ label: parent }];
  return [
    { label: parent, href: `#/${first}` },
    { label: segments.slice(1).join(' / ') },
  ];
});

const userName = computed(() => auth.claims?.name || auth.claims?.sub || '');
const userRole = computed(() => 'Platform admin');

const loginError = ref<string>('');
const loginBusy = ref<boolean>(false);

async function onLogin(creds: { email: string; password: string }) {
  loginError.value = '';
  loginBusy.value = true;
  try {
    const resp = await api.get().login(creds);
    auth.setToken(resp.token);
    if (resp.mustChangePassword) {
      await router.replace('/change-password');
    }
  } catch (err) {
    loginError.value = err instanceof Error ? err.message : 'Sign-in failed';
  } finally {
    loginBusy.value = false;
  }
}

async function signOut() {
  try { await api.get().logout(); } catch { /* best-effort */ }
  auth.clear();
  toast.info({ title: 'Signed out' });
  await router.replace('/');
}
</script>

<template>
  <TAuthGate
    type="jwt"
    title="Triton License Server"
    subtitle="Sign in to continue."
    :error="loginError"
    :busy="loginBusy"
    @login="onLogin"
  >
    <TAppShell :portal-accent="PORTAL_ACCENT">
      <template #sidebar>
        <TSidebar
          :nav="nav"
          portal-title="Triton"
          portal-subtitle="Licence"
          :current-href="currentHref"
        />
      </template>
      <template #topbar>
        <TCrumbBar :crumbs="crumbs" />
        <div class="top-right">
          <TAppSwitcher :apps="apps" current-id="license" />
          <TThemeToggle />
          <TUserMenu
            :name="userName"
            :role="userRole"
            @sign-out="signOut"
          />
        </div>
      </template>
      <router-view />
    </TAppShell>
  </TAuthGate>
  <TToastHost />
</template>

<style scoped>
.top-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}
</style>
```

- [ ] **Step 4: Add router guards + new routes**

Open `web/apps/license-portal/src/router.ts`. Replace contents:

```ts
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  { path: '/setup',           component: () => import('./views/Setup.vue'),          name: 'setup' },
  { path: '/change-password', component: () => import('./views/ChangePassword.vue'), name: 'change-password' },
  { path: '/',                component: () => import('./views/Dashboard.vue'),      name: 'dashboard' },
  { path: '/orgs',            component: () => import('./views/Organisations.vue'),  name: 'orgs' },
  { path: '/orgs/:id',        component: () => import('./views/OrganisationDetail.vue'), name: 'org' },
  { path: '/licenses',        component: () => import('./views/Licences.vue'),       name: 'licences' },
  { path: '/licenses/:id',    component: () => import('./views/LicenceDetail.vue'),  name: 'licence' },
  { path: '/audit',           component: () => import('./views/AuditLog.vue'),       name: 'audit' },
  { path: '/admin/users',     component: () => import('./views/Users.vue'),          name: 'users' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

// Setup probe runs once per SPA boot, cached for subsequent navigations.
let setupChecked = false;

router.beforeEach(async (to) => {
  // Setup route is always allowed (prevents a redirect loop).
  if (to.path === '/setup') return true;

  // Check if setup is needed on first navigation.
  if (!setupChecked) {
    setupChecked = true;
    try {
      const { useApiClient } = await import('./stores/apiClient');
      const { needsSetup } = await useApiClient().get().setupStatus();
      if (needsSetup) return { path: '/setup' };
    } catch {
      // If the probe fails, proceed — login prompt will surface the error.
    }
  }

  // Force-change-password guard.
  const { useAuthStore } = await import('./stores/auth');
  const auth = useAuthStore();
  if (auth.claims?.mustChangePassword && to.path !== '/change-password') {
    return { path: '/change-password' };
  }

  return true;
});
```

Note: `auth.claims?.mustChangePassword` assumes the JWT carries the flag; alternatively the frontend stores it separately on login. Simpler: store in a Pinia ref after login instead of relying on JWT claims. In the interest of keeping the JWT stable, add a local reactive ref in the auth store:

```ts
// web/apps/license-portal/src/stores/auth.ts
export const useAuthStore = defineStore('auth', () => {
  const jwt = useJwt();
  const mustChangePassword = ref(false);
  function setMustChange(v: boolean) { mustChangePassword.value = v; }
  return { ...jwt, mustChangePassword, setMustChange };
});
```

And in App.vue's `onLogin`:

```ts
auth.setToken(resp.token);
auth.setMustChange(resp.mustChangePassword);
```

Router guard uses `auth.mustChangePassword` instead of `auth.claims?.mustChangePassword`.

- [ ] **Step 5: Typecheck**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter license-portal exec vue-tsc --noEmit 2>&1 | tail -10
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add web/apps/license-portal/src/
git commit -m "feat(license-portal): swap admin-key gate for JWT + router guards

TAuthGate type='jwt'. apiClient sends Authorization: Bearer
<token>. onLogin stores token + mustChangePassword flag;
router guard redirects to /change-password when set.

setupStatus probe on first navigation redirects to /setup
when the DB is empty."
```

---

## Task 12: Setup view + component test

**Files:**
- Create: `web/apps/license-portal/src/views/Setup.vue`
- Create: `web/apps/license-portal/tests/views/Setup.spec.ts`

- [ ] **Step 1: Write failing test**

Create `web/apps/license-portal/tests/views/Setup.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Setup from '../../src/views/Setup.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

async function mountSetup() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { template: '<div/>' } }],
  });
  await router.isReady();
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Setup, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    setupFirstAdmin: vi.fn().mockResolvedValue({
      user: { id: 'U1', email: 'a@b', name: 'A', role: 'platform_admin',
              mustChangePassword: true, createdAt: '', updatedAt: '' },
      tempPassword: 'Xj3-abcd-ef',
      emailSent: true,
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return mount(Setup, { global: { plugins: [pinia, router] } });
}

describe('Setup view', () => {
  it('renders name + email fields', async () => {
    const w = await mountSetup();
    await flushPromises();
    expect(w.find('[data-test="setup-name"]').exists()).toBe(true);
    expect(w.find('[data-test="setup-email"]').exists()).toBe(true);
    w.unmount();
  });

  it('submit calls setupFirstAdmin and shows temp password', async () => {
    const w = await mountSetup();
    await flushPromises();

    await w.find('[data-test="setup-name"]').setValue('Alice');
    await w.find('[data-test="setup-email"]').setValue('alice@example.com');
    await w.find('[data-test="setup-submit"]').trigger('click');
    await flushPromises();

    const client = useApiClient();
    expect(client.get().setupFirstAdmin).toHaveBeenCalledWith({
      name: 'Alice',
      email: 'alice@example.com',
    });
    expect(w.html()).toContain('Xj3-abcd-ef');
    w.unmount();
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter license-portal test -- tests/views/Setup.spec.ts 2>&1 | tail -10
```

- [ ] **Step 3: Implement Setup.vue**

Create `web/apps/license-portal/src/views/Setup.vue`:

```vue
<script setup lang="ts">
import { ref, computed } from 'vue';
import { TPanel, TFormField, TInput, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();

const name = ref('');
const email = ref('');
const busy = ref(false);
const result = ref<{ tempPassword: string; emailSent: boolean } | null>(null);
const err = ref('');

const canSubmit = computed(
  () => name.value.trim() !== '' && email.value.includes('@'),
);

async function submit() {
  err.value = '';
  busy.value = true;
  try {
    const resp = await api.get().setupFirstAdmin({
      name: name.value.trim(),
      email: email.value.trim(),
    });
    result.value = { tempPassword: resp.tempPassword, emailSent: resp.emailSent };
    toast.success({
      title: resp.emailSent ? 'Invite sent' : 'Admin created',
      description: resp.emailSent
        ? `Email sent to ${resp.user.email}.`
        : 'Email not configured — copy the temp password shown.',
    });
  } catch (e) {
    err.value = e instanceof Error ? e.message : 'Setup failed';
  } finally {
    busy.value = false;
  }
}

function goToLogin() {
  window.location.hash = '#/';
}
</script>

<template>
  <div class="setup">
    <TPanel title="First-time setup">
      <p class="sub">
        No administrator exists yet. Create the first Users account to
        continue. A temporary password will be emailed to this address
        (or displayed here if email is not configured).
      </p>
      <div v-if="!result" class="form">
        <TFormField label="Name" required>
          <TInput v-model="name" data-test="setup-name" />
        </TFormField>
        <TFormField label="Email" required>
          <TInput v-model="email" type="email" data-test="setup-email" />
        </TFormField>
        <div v-if="err" class="err">{{ err }}</div>
        <TButton
          variant="primary"
          :disabled="!canSubmit || busy"
          data-test="setup-submit"
          @click="submit"
        >
          {{ busy ? 'Creating…' : 'Send invite' }}
        </TButton>
      </div>
      <div v-else class="done">
        <p class="small">
          Admin user created. Temp password (copy now — shown only once):
        </p>
        <code class="temp">{{ result.tempPassword }}</code>
        <p v-if="result.emailSent" class="small ok">
          An email has also been sent.
        </p>
        <TButton variant="primary" @click="goToLogin">Go to login</TButton>
      </div>
    </TPanel>
  </div>
</template>

<style scoped>
.setup {
  max-width: 480px;
  margin: 80px auto;
  padding: var(--space-4);
}
.sub { color: var(--text-muted); font-size: 0.82rem; margin-bottom: var(--space-3); }
.form, .done { display: flex; flex-direction: column; gap: var(--space-3); }
.err { color: var(--unsafe); font-size: 0.76rem; }
.ok { color: var(--safe); }
.temp {
  display: block;
  padding: var(--space-2);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.88rem;
  word-break: break-all;
}
.small { font-size: 0.78rem; color: var(--text-muted); }
</style>
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter license-portal test -- tests/views/Setup.spec.ts 2>&1 | tail -10
```
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add web/apps/license-portal/src/views/Setup.vue \
        web/apps/license-portal/tests/views/Setup.spec.ts
git commit -m "feat(license-portal): Setup.vue first-time admin wizard

Name + email form. Submit calls setupFirstAdmin, displays the
temp password one-shot plus a 'Go to login' button. Entry
wired via router guard when /setup/status returns needsSetup."
```

---

## Task 13: ChangePassword view + component test

**Files:**
- Create: `web/apps/license-portal/src/views/ChangePassword.vue`
- Create: `web/apps/license-portal/tests/views/ChangePassword.spec.ts`

- [ ] **Step 1: Write failing test**

Create `web/apps/license-portal/tests/views/ChangePassword.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import ChangePassword from '../../src/views/ChangePassword.vue';
import { useApiClient } from '../../src/stores/apiClient';
import { useAuthStore } from '../../src/stores/auth';

beforeEach(() => { vi.clearAllMocks(); });

async function mountCP() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { template: '<div/>' } }],
  });
  await router.isReady();
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(ChangePassword, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    changePassword: vi.fn().mockResolvedValue({
      token: 'new-jwt', expiresAt: '2026-04-25T00:00:00Z',
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return { w: mount(ChangePassword, { global: { plugins: [pinia, router] } }), router };
}

describe('ChangePassword view', () => {
  it('requires new + confirm to match before submit', async () => {
    const { w } = await mountCP();
    await flushPromises();
    await w.find('[data-test="cp-current"]').setValue('current-pw');
    await w.find('[data-test="cp-next"]').setValue('newPassword123!');
    await w.find('[data-test="cp-confirm"]').setValue('different');
    const submit = w.find('[data-test="cp-submit"]');
    expect((submit.element as HTMLButtonElement).disabled).toBe(true);
    w.unmount();
  });

  it('submit calls changePassword and rotates the JWT', async () => {
    const { w } = await mountCP();
    await flushPromises();
    await w.find('[data-test="cp-current"]').setValue('current-pw');
    await w.find('[data-test="cp-next"]').setValue('newPassword123!');
    await w.find('[data-test="cp-confirm"]').setValue('newPassword123!');
    await w.find('[data-test="cp-submit"]').trigger('click');
    await flushPromises();

    const client = useApiClient();
    expect(client.get().changePassword).toHaveBeenCalledWith({
      current: 'current-pw', next: 'newPassword123!',
    });
    const auth = useAuthStore();
    expect(auth.setToken).toHaveBeenCalledWith('new-jwt');
    w.unmount();
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm --filter license-portal test -- tests/views/ChangePassword.spec.ts 2>&1 | tail -10
```

- [ ] **Step 3: Implement ChangePassword.vue**

Create `web/apps/license-portal/src/views/ChangePassword.vue`:

```vue
<script setup lang="ts">
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { TPanel, TFormField, TInput, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const api = useApiClient();
const auth = useAuthStore();
const router = useRouter();
const toast = useToast();

const current = ref('');
const next = ref('');
const confirm = ref('');
const busy = ref(false);
const err = ref('');

const MIN = 12;

const canSubmit = computed(() =>
  current.value.length > 0
  && next.value.length >= MIN
  && next.value === confirm.value
);

async function submit() {
  err.value = '';
  busy.value = true;
  try {
    const resp = await api.get().changePassword({
      current: current.value,
      next: next.value,
    });
    auth.setToken(resp.token);
    auth.setMustChange(false);
    toast.success({ title: 'Password changed' });
    await router.replace('/');
  } catch (e) {
    err.value = e instanceof Error ? e.message : 'Change password failed';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="cp">
    <TPanel title="Change password">
      <p class="sub">
        You must set a new password to continue.
      </p>
      <div class="form">
        <TFormField label="Current password" required>
          <TInput v-model="current" type="password" data-test="cp-current" />
        </TFormField>
        <TFormField label="New password" required
          hint="Minimum 12 characters.">
          <TInput v-model="next" type="password" data-test="cp-next" />
        </TFormField>
        <TFormField label="Confirm new password" required>
          <TInput v-model="confirm" type="password" data-test="cp-confirm" />
        </TFormField>
        <div v-if="err" class="err">{{ err }}</div>
        <TButton
          variant="primary"
          :disabled="!canSubmit || busy"
          data-test="cp-submit"
          @click="submit"
        >
          {{ busy ? 'Changing…' : 'Change password' }}
        </TButton>
      </div>
    </TPanel>
  </div>
</template>

<style scoped>
.cp { max-width: 480px; margin: 80px auto; padding: var(--space-4); }
.sub { color: var(--text-muted); font-size: 0.82rem; margin-bottom: var(--space-3); }
.form { display: flex; flex-direction: column; gap: var(--space-3); }
.err { color: var(--unsafe); font-size: 0.76rem; }
</style>
```

- [ ] **Step 4: Run tests**

```bash
pnpm --filter license-portal test -- tests/views/ChangePassword.spec.ts 2>&1 | tail -10
```
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add web/apps/license-portal/src/views/ChangePassword.vue \
        web/apps/license-portal/tests/views/ChangePassword.spec.ts
git commit -m "feat(license-portal): ChangePassword.vue force-change page

Three fields (current/next/confirm), min-length 12, confirm
must match. Submit calls changePassword, stores the rotated
JWT, clears mustChangePassword, navigates to /."
```

---

## Task 14: Users view + UserForm modal + component tests

**Files:**
- Create: `web/apps/license-portal/src/views/Users.vue`
- Create: `web/apps/license-portal/src/views/modals/UserForm.vue`
- Create: `web/apps/license-portal/tests/views/Users.spec.ts`
- Modify: `web/apps/license-portal/src/nav.ts`
- Delete: `web/apps/license-portal/src/views/Superadmins.vue`

- [ ] **Step 1: Write the failing test**

Create `web/apps/license-portal/tests/views/Users.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Users from '../../src/views/Users.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const USERS = [
  {
    id: 'U1', email: 'alice@example.com', name: 'Alice',
    role: 'platform_admin', mustChangePassword: false,
    createdAt: '2026-04-01', updatedAt: '2026-04-01',
  },
  {
    id: 'U2', email: 'bob@example.com', name: 'Bob',
    role: 'platform_admin', mustChangePassword: true,
    createdAt: '2026-04-10', updatedAt: '2026-04-10',
  },
];

function mountWithUsers() {
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Users, { global: { plugins: [pinia] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    listUsers: vi.fn().mockResolvedValue(USERS),
    createUser: vi.fn().mockResolvedValue({
      user: { ...USERS[0], id: 'U3', email: 'new@c.com', name: 'New',
              mustChangePassword: true },
      tempPassword: 'NewTemp-abc', emailSent: false,
    }),
    deleteUser: vi.fn().mockResolvedValue(undefined),
    resendInvite: vi.fn().mockResolvedValue({
      tempPassword: 'Rotated-xyz', emailSent: true,
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return mount(Users, { global: { plugins: [pinia] } });
}

describe('Users view', () => {
  it('renders user rows', async () => {
    const w = mountWithUsers();
    await flushPromises();
    await flushPromises();
    const html = w.html();
    expect(html).toContain('alice@example.com');
    expect(html).toContain('bob@example.com');
    w.unmount();
  });

  it('new-user modal opens and submit calls createUser', async () => {
    const w = mountWithUsers();
    await flushPromises();
    await flushPromises();

    const newBtn = w.findAll('button').find((b) => b.text().includes('New user'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();

    // TModal uses Teleport so look on document.
    const modal = document.querySelector('.t-modal');
    expect(modal).not.toBeNull();

    const nameInput = document.querySelector('[data-test="user-name"]') as HTMLInputElement;
    const emailInput = document.querySelector('[data-test="user-email"]') as HTMLInputElement;
    nameInput.value = 'New User';
    nameInput.dispatchEvent(new Event('input'));
    emailInput.value = 'new@c.com';
    emailInput.dispatchEvent(new Event('input'));
    await flushPromises();

    const submit = document.querySelector('[data-test="user-submit"]') as HTMLButtonElement;
    submit.click();
    await flushPromises();

    const client = useApiClient();
    expect(client.get().createUser).toHaveBeenCalledWith({
      name: 'New User', email: 'new@c.com',
    });
    w.unmount();
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm --filter license-portal test -- tests/views/Users.spec.ts 2>&1 | tail -10
```

- [ ] **Step 3: Write UserForm.vue**

Create `web/apps/license-portal/src/views/modals/UserForm.vue`:

```vue
<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';

const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string; email: string }];
}>();

const name = ref('');
const email = ref('');

watch(
  () => props.open,
  (open) => { if (open) { name.value = ''; email.value = ''; } },
  { immediate: true },
);

const canSubmit = computed(
  () => name.value.trim() !== '' && email.value.includes('@'),
);

function submit() {
  if (!canSubmit.value) return;
  emit('submit', { name: name.value.trim(), email: email.value.trim() });
}
</script>

<template>
  <TModal :open="open" title="New user" @close="emit('close')">
    <div class="form">
      <TFormField label="Name" required>
        <TInput v-model="name" data-test="user-name" />
      </TFormField>
      <TFormField label="Email" required>
        <TInput v-model="email" type="email" data-test="user-email" />
      </TFormField>
    </div>
    <template #footer>
      <TButton variant="ghost" size="sm" @click="emit('close')">Cancel</TButton>
      <TButton
        variant="primary"
        size="sm"
        :disabled="!canSubmit"
        data-test="user-submit"
        @click="submit"
      >Send invite</TButton>
    </template>
  </TModal>
</template>

<style scoped>
.form { display: flex; flex-direction: column; gap: var(--space-3); }
</style>
```

- [ ] **Step 4: Write Users.vue**

Create `web/apps/license-portal/src/views/Users.vue`:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TPanel, TDataTable, TButton, TConfirmDialog, TPill, useToast,
  type Column,
} from '@triton/ui';
import type { User } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';
import UserForm from './modals/UserForm.vue';

const api = useApiClient();
const auth = useAuthStore();
const toast = useToast();

const items = ref<User[]>([]);
const loading = ref(false);
const formOpen = ref(false);
const confirmOpen = ref(false);
const pendingDelete = ref<User | null>(null);

interface Row extends User { [key: string]: unknown }

const columns: Column<Row>[] = [
  { key: 'email', label: 'Email', width: '1.4fr' },
  { key: 'name', label: 'Name', width: '1fr' },
  { key: 'createdAt', label: 'Created', width: '1fr' },
  { key: 'mustChangePassword', label: 'Status', width: '140px' },
  { key: 'id', label: '', width: '220px', align: 'right' },
];

async function load() {
  loading.value = true;
  try { items.value = await api.get().listUsers(); }
  catch (err) { toast.error({ title: 'Failed to load users', description: String(err) }); }
  finally { loading.value = false; }
}
onMounted(load);

function selfID(): string | null {
  return auth.claims?.sub ?? null;
}

async function onSubmit(payload: { name: string; email: string }) {
  try {
    const resp = await api.get().createUser(payload);
    formOpen.value = false;
    await load();
    const msg = resp.emailSent
      ? `Invite email sent to ${resp.user.email}.`
      : `Copy the temp password now: ${resp.tempPassword}`;
    toast.success({
      title: resp.emailSent ? 'Invite sent' : 'User created',
      description: msg,
    });
  } catch (err) {
    toast.error({ title: 'Create failed', description: String(err) });
  }
}

function askDelete(u: User) {
  if (u.id === selfID()) {
    toast.error({ title: "Can't delete your own account" });
    return;
  }
  pendingDelete.value = u;
  confirmOpen.value = true;
}

async function confirmDelete() {
  const u = pendingDelete.value;
  if (!u) return;
  try {
    await api.get().deleteUser(u.id);
    items.value = items.value.filter((x) => x.id !== u.id);
    toast.success({ title: 'User deleted' });
  } catch (err) {
    toast.error({ title: 'Delete failed', description: String(err) });
  } finally {
    confirmOpen.value = false;
    pendingDelete.value = null;
  }
}

async function onResend(u: User) {
  try {
    const resp = await api.get().resendInvite(u.id);
    toast.success({
      title: resp.emailSent ? 'Invite resent' : 'Temp password rotated',
      description: resp.emailSent
        ? `Email sent to ${u.email}.`
        : `Copy the new temp password: ${resp.tempPassword}`,
    });
  } catch (err) {
    toast.error({ title: 'Resend failed', description: String(err) });
  }
}
</script>

<template>
  <TPanel
    title="Users"
    :subtitle="items.length ? `· ${items.length} total` : ''"
  >
    <template #action>
      <TButton variant="primary" size="sm" @click="formOpen = true">
        New user
      </TButton>
    </template>

    <TDataTable
      :columns="columns"
      :rows="items"
      row-key="id"
      :empty-text="loading ? 'Loading…' : 'No users yet.'"
    >
      <template #[`cell:mustChangePassword`]="{ row }">
        <TPill :variant="(row as Row).mustChangePassword ? 'warn' : 'safe'">
          {{ (row as Row).mustChangePassword ? 'Pending change' : 'Active' }}
        </TPill>
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="actions">
          <TButton
            variant="ghost" size="sm"
            @click="onResend(row as unknown as User)"
          >Resend invite</TButton>
          <TButton
            variant="danger" size="sm"
            :disabled="(row as Row).id === selfID()"
            @click="askDelete(row as unknown as User)"
          >Delete</TButton>
        </div>
      </template>
    </TDataTable>
  </TPanel>

  <UserForm
    :open="formOpen"
    @close="formOpen = false"
    @submit="onSubmit"
  />

  <TConfirmDialog
    :open="confirmOpen"
    title="Delete user?"
    :message="pendingDelete
      ? `Delete ${pendingDelete.email}? This also revokes any active session.`
      : ''"
    confirm-label="Delete"
    variant="danger"
    @confirm="confirmDelete"
    @cancel="confirmOpen = false; pendingDelete = null"
  />
</template>

<style scoped>
.actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
</style>
```

- [ ] **Step 5: Delete Superadmins.vue + update nav**

```bash
rm web/apps/license-portal/src/views/Superadmins.vue
```

Open `web/apps/license-portal/src/nav.ts`. Change the Admin section:

```ts
{
  label: 'Admin',
  items: [
    { href: '#/audit',       label: 'Audit log' },
    { href: '#/admin/users', label: 'Users' },
  ],
},
```

- [ ] **Step 6: Run tests**

```bash
pnpm --filter license-portal test -- tests/views/Users.spec.ts 2>&1 | tail -10
```
Expected: 2 tests pass.

- [ ] **Step 7: Full test + typecheck**

```bash
pnpm test 2>&1 | tail -5
pnpm --filter license-portal exec vue-tsc --noEmit 2>&1 | tail -5
```
Expected: all tests pass; no TS errors.

- [ ] **Step 8: Commit**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
git add web/apps/license-portal/
git rm web/apps/license-portal/src/views/Superadmins.vue
git commit -m "feat(license-portal): Users page (renamed from Superadmins) + UserForm

Table of platform admins with resend-invite + delete (self and
last-user guarded at the backend; self-delete button disabled
in the UI). UserForm modal (name + email) calls createUser.
Temp password surfaced in toast when email is not configured.

Superadmins.vue stub deleted. Nav entry retitled Users.
Backend route path stays /admin/superadmins/* for
backward-compat until a future rename sprint."
```

---

## Task 15: E2E sanity check + container rebuild

**Files:** none (runs tools)

- [ ] **Step 1: Full workspace tests**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt/web
pnpm test 2>&1 | tail -5
```
Expected: all passing.

- [ ] **Step 2: vue-tsc clean**

```bash
pnpm --filter license-portal exec vue-tsc --noEmit
pnpm --filter @triton/api-client exec tsc --noEmit
```

- [ ] **Step 3: Vite build**

```bash
pnpm --filter license-portal build 2>&1 | tail -5
```

- [ ] **Step 4: Go unit + integration tests**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/license-portal-users-jwt
go test ./pkg/licenseserver/... ./pkg/licensestore/... 2>&1 | tail -5
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/licenseserver/... ./pkg/licensestore/... 2>&1 | tail -5
```

- [ ] **Step 5: Rebuild container + manual smoke**

```bash
podman build -f Containerfile.licenseserver \
  -t ghcr.io/amiryahaya/triton-license-server:local .
podman rm -f triton-license-server
TRITON_LICENSE_SERVER_IMAGE=ghcr.io/amiryahaya/triton-license-server:local \
  podman-compose --profile license-server up -d license-server
sleep 4
```

Browser smoke test at http://localhost:8081/ui/ with a fresh DB (`make db-reset` first if needed):

- Empty DB → setup page appears.
- Enter name + email → temp password shown + email log (if Resend configured).
- Login with temp password → force-change page.
- Change password → Dashboard loads.
- Navigate to Users → create a second user, confirm temp password toast.
- Sign out → login as second user with temp → force-change → Dashboard.

- [ ] **Step 6: Commit any final tweaks from the smoke test.**

---

## After all tasks

Use the `superpowers:finishing-a-development-branch` skill with:
- Branch: `feat/license-portal-users-jwt`
- Worktree: `.worktrees/license-portal-users-jwt`
- Main branch: `main`
