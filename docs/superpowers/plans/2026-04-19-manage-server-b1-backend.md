# Manage Server B1 — Standalone Backend Shell Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Stand up the Manage Server as a standalone Go binary (`cmd/manageserver/`) with its own DB schema, JWT auth, first-admin setup flow, License Server v2 activation, and container/CI wiring. No scanner orchestrator and no mTLS scan-push yet — those ship in PR B2. The existing vanilla-JS manage UI under `pkg/server/ui/dist/manage/` stays served by the Report Server as a transitional fallback.

**Architecture:** New `cmd/manageserver/main.go` entrypoint + new `pkg/manageserver/` package (Chi router, JWT middleware, role middleware, setup + auth handlers) + new `pkg/managestore/` (Postgres storage with separate schema: `manage_users`, `manage_sessions`, `manage_setup`). License client is the consumer-side library already shipped in PR A (`internal/license`); Manage's startup calls `Activate(product="manage")` against License Server, runs the usage pusher.

**Tech Stack:** Go 1.25 (`go-chi/chi/v5`, `pgx/v5`), Ed25519-signed JWT (HS256 simpler but HS256 needs only a shared secret — decision in §Config below), bcrypt for password hashing, `pkg/licensestore` for Features/Limits types, `internal/license` client for activation+usage.

**Spec reference:** `docs/superpowers/specs/2026-04-19-license-v2-and-manage-portal-design.md` §4.

**Scope — this PR (B1):**
1. Migrations + Go types for `manage_users`, `manage_sessions`, `manage_setup`
2. Chi router + middleware (request ID, recoverer, timeout, security headers, CORS for dev)
3. JWT auth: login / logout / refresh / `/me`, bcrypt passwords, session table
4. Setup flow: `/setup/status`, `/setup/admin` (first admin), `/setup/license` (activate online)
5. License client integration: activates online at startup if key+server configured, runs usage pusher
6. `cmd/manageserver/main.go` binary with env-var config, signal handling, graceful shutdown
7. Report Server stub: `POST /api/v1/enrol/manage` returns `501 Not Implemented` with a TODO message (B2 populates)
8. `Containerfile.manageserver` multi-stage build; `compose.yaml` profile `manage-server` on port 8082
9. CI: unit + integration test job
10. Integration tests: setup flow happy path, auth round-trip, licence activation

**Out of scope (PR B2):**
- Scanner orchestrator goroutine pool
- mTLS scan-push to Report Server
- `/api/v1/enrol/manage` actually issuing `bundle.tar.gz` with client cert
- Re-mounting existing scan handlers (scanjobs/engine/agentpush/credentials/discovery) under the Manage router

**Out of scope (PR C):**
- Vue UI for Manage Portal
- Cutover — deletes the legacy vanilla-JS `pkg/server/ui/dist/manage/`

---

## File structure

**Created:**

```
cmd/manageserver/
  main.go

pkg/manageserver/
  server.go                     Chi router, Server struct, Run lifecycle
  config.go                     Config struct, env-var parsing
  auth.go                       JWT issue/parse + bcrypt helpers
  handlers_auth.go              /auth/login, /logout, /refresh, /me
  handlers_auth_test.go
  handlers_setup.go             /setup/status, /setup/admin, /setup/license
  handlers_setup_test.go
  handlers_health.go            /health
  middleware.go                 JWT middleware, role middleware, setup-gate middleware
  middleware_test.go
  license.go                    licence activation + usage pusher wiring
  license_test.go

pkg/managestore/
  migrations.go                 inline []string migrations (mirrors licensestore pattern)
  store.go                      Store interface + types (ManageUser, ManageSession, SetupState)
  postgres.go                   PostgresStore implementation with pgx/v5
  postgres_test.go              integration tests (build tag)

Containerfile.manageserver      multi-stage: golang build → scratch
compose.yaml                    new service under profile: [manage-server]

.github/workflows/ci.yml        new job: manage-server-test (unit + integration)

docs/plans/<existing> (no change)
```

**Modified:**

```
Makefile                        new targets: build-manageserver, container-build-manageserver,
                                              container-run-manageserver, container-stop-manageserver
pkg/server/handlers_enrol.go    NEW (actually created): stub /api/v1/enrol/manage → 501
pkg/server/server.go            mount the new route inside /api/v1/enrol subgroup
```

---

## Phase 0 — DB migration

### Task 0.1: `pkg/managestore/migrations.go`

**Files:**
- Create: `pkg/managestore/migrations.go`

Follows the `pkg/licensestore/migrations.go` inline-slice pattern.

```go
package managestore

// migrations is an ordered list of SQL schema migrations for the Manage Server.
// Each entry is applied once, in order. The index+1 is the schema version.
var migrations = []string{
	// Version 1: Initial schema — users, sessions, setup state.
	`CREATE TABLE IF NOT EXISTS manage_users (
		id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
		email           TEXT         NOT NULL UNIQUE,
		name            TEXT         NOT NULL,
		role            TEXT         NOT NULL CHECK (role IN ('admin', 'network_engineer')),
		password        TEXT         NOT NULL,
		must_change_pw  BOOLEAN      NOT NULL DEFAULT FALSE,
		created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
		updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manage_users_email ON manage_users(email);

	CREATE TABLE IF NOT EXISTS manage_sessions (
		id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id     UUID         NOT NULL REFERENCES manage_users(id) ON DELETE CASCADE,
		token_hash  TEXT         NOT NULL UNIQUE,
		expires_at  TIMESTAMPTZ  NOT NULL,
		created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manage_sessions_token_hash ON manage_sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_manage_sessions_expires_at ON manage_sessions(expires_at);

	-- Single-row setup state. We use a CHECK constraint on id=1 so only one
	-- row can exist; simpler than a separate "singleton" pattern.
	CREATE TABLE IF NOT EXISTS manage_setup (
		id                     SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
		admin_created          BOOLEAN     NOT NULL DEFAULT FALSE,
		license_activated      BOOLEAN     NOT NULL DEFAULT FALSE,
		license_server_url     TEXT        NOT NULL DEFAULT '',
		license_key            TEXT        NOT NULL DEFAULT '',
		signed_token           TEXT        NOT NULL DEFAULT '',
		instance_id            UUID,
		updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	INSERT INTO manage_setup (id) VALUES (1) ON CONFLICT DO NOTHING;`,
}
```

**Steps:**

- [ ] Write the file.
- [ ] `go build ./pkg/managestore/...` must compile (just the `migrations` var).
- [ ] Commit:

```sh
git add pkg/managestore/migrations.go
git commit -m "feat(managestore): v1 migration — manage_users, manage_sessions, manage_setup"
```

---

## Phase 1 — Store types + Postgres CRUD

### Task 1.1: Store types + interface

**Files:**
- Create: `pkg/managestore/store.go`

```go
package managestore

import (
	"context"
	"time"
)

// ManageUser is a Manage Portal user with its own auth surface separate
// from Report Server's users table.
type ManageUser struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          string    `json:"role"` // "admin" | "network_engineer"
	PasswordHash  string    `json:"-"`    // never serialised
	MustChangePW  bool      `json:"must_change_pw"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ManageSession represents an active JWT session.
type ManageSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// SetupState is the singleton row tracking Manage Server initialisation.
type SetupState struct {
	AdminCreated     bool
	LicenseActivated bool
	LicenseServerURL string
	LicenseKey       string
	SignedToken      string
	InstanceID       string
	UpdatedAt        time.Time
}

// Store is the Manage Server's storage surface.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *ManageUser) error
	GetUserByEmail(ctx context.Context, email string) (*ManageUser, error)
	GetUserByID(ctx context.Context, id string) (*ManageUser, error)
	ListUsers(ctx context.Context) ([]ManageUser, error)
	UpdateUserPassword(ctx context.Context, id, newHash string) error
	CountUsers(ctx context.Context) (int64, error)

	// Sessions
	CreateSession(ctx context.Context, sess *ManageSession) error
	GetSessionByTokenHash(ctx context.Context, hash string) (*ManageSession, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	// Setup
	GetSetup(ctx context.Context) (*SetupState, error)
	MarkAdminCreated(ctx context.Context) error
	SaveLicenseActivation(ctx context.Context, serverURL, key, signedToken, instanceID string) error

	Close() error
}

// ErrNotFound signals a resource miss; handlers return 404.
type ErrNotFound struct{ Resource, ID string }

func (e *ErrNotFound) Error() string { return e.Resource + " not found: " + e.ID }

// ErrConflict signals a uniqueness violation.
type ErrConflict struct{ Message string }

func (e *ErrConflict) Error() string { return e.Message }
```

**Steps:**

- [ ] Write.
- [ ] `go build ./pkg/managestore/...`.
- [ ] Commit: `feat(managestore): Store interface + types (ManageUser, ManageSession, SetupState)`.

### Task 1.2: Postgres implementation

**Files:**
- Create: `pkg/managestore/postgres.go`

Mirrors `pkg/licensestore/postgres.go` — `NewPostgresStore` + `NewPostgresStoreInSchema` (for tests), `migrate` helper that reads `manage_schema_version`. Implement all Store methods using pgx/v5.

Key implementation notes:
- `migrate` creates `manage_schema_version` (not `schema_version` — avoid cross-tool collision in same DB).
- Test helper `NewPostgresStoreInSchema` creates an isolated PG schema per test, identical pattern to licensestore.
- `CreateUser` uses `ON CONFLICT` → returns `&ErrConflict{Message:"email X already exists"}`.
- `GetSetup` returns the singleton row; if `SELECT` returns no rows, INSERT the default and retry.

**Steps:**

- [ ] Write `postgres.go` mirroring licensestore pattern.
- [ ] Create `pkg/managestore/postgres_test.go` with integration tests for every method — use the same `openTestStore(t)` helper pattern as licensestore, but seeding a fresh schema. Helpers: `makeUser`, `makeSession`.
- [ ] `TRITON_TEST_DB_URL=... go test -tags integration ./pkg/managestore/...` — all green.
- [ ] Commit: `feat(managestore): PostgresStore CRUD + migrate + schema isolation for tests`.

---

## Phase 2 — pkg/manageserver scaffolding

### Task 2.1: Config + Server struct

**Files:**
- Create: `pkg/manageserver/config.go`
- Create: `pkg/manageserver/server.go`

```go
// config.go
package manageserver

import (
	"crypto/ed25519"
	"time"
)

// Config wires the Manage Server runtime.
type Config struct {
	Listen         string                   // e.g. ":8082"
	DBUrl          string                   // postgres DSN
	JWTSigningKey  []byte                   // HS256 secret; 32+ bytes
	LicenseServer  string                   // License Server URL (may be empty until setup)
	LicenseKey     string                   // set after setup completes; persisted in DB
	InstanceID     string                   // UUID for this Manage instance
	ReportServer   string                   // Report Server URL (mTLS bundle source; unused in B1)
	// Future: TLSCert, TLSKey for HTTPS termination.

	SessionTTL     time.Duration            // default 24h
	PublicKey      ed25519.PublicKey        // License Server public key for parsing tokens
}
```

```go
// server.go
package manageserver

import (
	"context"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/managestore"
)

type Server struct {
	cfg     *Config
	store   managestore.Store
	router  chi.Router
	http    *http.Server

	mu               sync.RWMutex
	setupMode        bool                // true until admin created AND license activated
	licenceGuard     *license.Guard       // nil in setup mode
	licencePusher    *license.UsagePusher // nil in setup mode; started after activation
}

// New creates the Server, runs its initial setup probe (reads setup state
// from DB), and wires the router. Does not start the HTTP listener.
func New(cfg *Config, store managestore.Store) (*Server, error) {
	srv := &Server{cfg: cfg, store: store}
	if err := srv.initSetupState(context.Background()); err != nil {
		return nil, err
	}
	srv.router = srv.buildRouter()
	return srv, nil
}

// Run starts the HTTP listener and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.http = &http.Server{
		Addr:    s.cfg.Listen,
		Handler: s.router,
	}
	errCh := make(chan error, 1)
	go func() {
		err := s.http.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
```

**`initSetupState`**: reads `manage_setup` row. Sets `s.setupMode = !(AdminCreated && LicenseActivated)`. If license was previously activated, `initSetupState` re-parses `SignedToken` with the public key and sets `s.licenceGuard`. If the cached token has expired, the server transitions back to setup mode (or at least triggers re-activation) — keep simple in B1: just set `setupMode = false` when `AdminCreated && LicenseActivated`, leave revalidation to `license.go` (Task 2.5).

**`buildRouter`**: uses chi. Global middleware: `RequestID`, `RealIP`, `Recoverer`, `Timeout(60s)`, security headers, throttle. Then:

```go
r.Get("/api/v1/health", srv.handleHealth)

// Setup endpoints — always available (own middleware: only-when-in-setup for POST).
r.Route("/api/v1/setup", func(r chi.Router) {
    r.Get("/status", srv.handleSetupStatus)
    r.With(srv.setupOnly).Post("/admin", srv.handleSetupAdmin)
    r.With(srv.setupOnly).Post("/license", srv.handleSetupLicense)
})

// Auth endpoints — available only when not in setup mode.
r.Route("/api/v1/auth", func(r chi.Router) {
    r.Use(srv.requireOperational)
    r.Post("/login", srv.handleLogin)
    r.Post("/logout", srv.handleLogout)
    r.Post("/refresh", srv.handleRefresh)
})

// Authenticated endpoints — require valid JWT.
r.Route("/api/v1", func(r chi.Router) {
    r.Use(srv.requireOperational)
    r.Use(srv.jwtAuth)
    r.Get("/me", srv.handleMe)
    // B2 stacks scan-job routes here.
})
```

**Steps:**

- [ ] Write config + server.
- [ ] Compile.
- [ ] Commit: `feat(manageserver): Config + Server scaffold with chi router + setup-mode gate`.

### Task 2.2: Middleware

**Files:**
- Create: `pkg/manageserver/middleware.go`
- Create: `pkg/manageserver/middleware_test.go`

Includes:
- `setupOnly` — rejects non-setup calls once both `AdminCreated && LicenseActivated` are true (returns 409).
- `requireOperational` — rejects calls while still in setup mode (returns 503 with body `{"setup_required": true}`).
- `jwtAuth` — parses `Authorization: Bearer <token>`, validates HS256 signature, checks session exists in DB, stashes user ID in request context.
- `requireRole(roles ...string)` — checks user's role from context; 403 if not in list.
- `securityHeaders` — Content-Security-Policy, X-Frame-Options DENY, etc.

**Tests** — table-driven HTTP tests: setup-mode gates, JWT valid/invalid/expired, role admittance.

- [ ] Write + test + commit: `feat(manageserver): middleware — JWT, setup-gate, operational-gate, role`.

---

## Phase 3 — Auth handlers

### Task 3.1: bcrypt helpers + JWT issue/parse

**Files:**
- Create: `pkg/manageserver/auth.go`
- Extend: `pkg/manageserver/auth_test.go`

```go
// auth.go
package manageserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword uses bcrypt cost 12 (sensible default).
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), 12)
	return string(b), err
}

// VerifyPassword returns nil on match; bcrypt error otherwise.
func VerifyPassword(hash, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

// JWTClaims is a minimal claims set — sub + exp + role.
type JWTClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

// signJWT produces a HS256 token: base64url(header).base64url(payload).base64url(sig).
// Header is the literal string {"alg":"HS256","typ":"JWT"} to avoid runtime allocation.
func signJWT(claims JWTClaims, secret []byte) (string, error) {
	const header = `{"alg":"HS256","typ":"JWT"}`
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	p64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := h64 + "." + p64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	s64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + s64, nil
}

// parseJWT returns the claims if the signature is valid and exp is in the future.
func parseJWT(token string, secret []byte) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	expected := hmac.New(sha256.New, secret)
	expected.Write([]byte(parts[0] + "." + parts[1]))
	expectedSig := base64.RawURLEncoding.EncodeToString(expected.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, errors.New("invalid signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

// hashToken is what we store in manage_sessions.token_hash — SHA-256 of the
// token string. We never persist the raw token; the client must present it.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
```

**Tests** — sign+parse round-trip, expired token, tampered signature, password hash correctness.

- [ ] Write + test + commit: `feat(manageserver): bcrypt + HS256 JWT helpers`.

### Task 3.2: Login/logout/refresh/me handlers

**Files:**
- Create: `pkg/manageserver/handlers_auth.go`
- Create: `pkg/manageserver/handlers_auth_test.go`

Standard flow:
- `POST /api/v1/auth/login` — body `{email, password}`. Looks up user, verifies bcrypt, issues JWT with role claim, inserts hashed token into `manage_sessions`, returns `{token, user: {id, email, name, role, must_change_pw}}`. Rate-limiting (per-IP + per-email) — simple in-memory map with a per-attempt sleep to deter brute force. Cap at 5 attempts / 15 min per (email, IP) — if exceeded, 429.
- `POST /api/v1/auth/logout` — header `Authorization: Bearer ...`; deletes the session row.
- `POST /api/v1/auth/refresh` — body `{old_token}`; if old still valid and session row present, issues new token and replaces the session row.
- `GET /api/v1/me` — returns the authenticated user.

Rate limiter — can be a simpler version of what Report Server uses in `pkg/server/handlers_auth.go`. Extract the counter pattern (a `sync.Map` of `{email: time.Time}` with N attempts in the last 15 min) — keep in-memory for B1; Redis can come later.

**Tests** — happy path, wrong password → 401, expired token on /me → 401, logout idempotency.

- [ ] Write + test + commit: `feat(manageserver): /auth/login + logout + refresh + me handlers`.

---

## Phase 4 — Setup handlers

### Task 4.1: /setup/status

**Files:**
- Create: `pkg/manageserver/handlers_setup.go`

```go
// GET /api/v1/setup/status — returns current setup progress.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
    state, err := s.store.GetSetup(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to read setup state")
        return
    }
    writeJSON(w, http.StatusOK, map[string]any{
        "admin_created":     state.AdminCreated,
        "license_activated": state.LicenseActivated,
        "setup_required":    !(state.AdminCreated && state.LicenseActivated),
    })
}
```

### Task 4.2: /setup/admin (create first admin)

```go
// POST /api/v1/setup/admin — body {email, name, password}.
// Only allowed when no admin exists. Creates user with role=admin.
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
    state, _ := s.store.GetSetup(r.Context())
    if state.AdminCreated {
        writeError(w, http.StatusConflict, "admin already created")
        return
    }
    var req struct {
        Email    string `json:"email"`
        Name     string `json:"name"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
        writeError(w, http.StatusBadRequest, "email and password are required")
        return
    }
    if err := validatePassword(req.Password); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }
    hash, err := HashPassword(req.Password)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "password hashing failed")
        return
    }
    user := &managestore.ManageUser{
        Email: req.Email, Name: req.Name, Role: "admin", PasswordHash: hash,
    }
    if err := s.store.CreateUser(r.Context(), user); err != nil {
        var cf *managestore.ErrConflict
        if errors.As(err, &cf) {
            writeError(w, http.StatusConflict, cf.Message)
            return
        }
        writeError(w, http.StatusInternalServerError, "create user failed")
        return
    }
    if err := s.store.MarkAdminCreated(r.Context()); err != nil {
        writeError(w, http.StatusInternalServerError, "mark setup failed")
        return
    }
    s.refreshSetupMode(r.Context())
    writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "user_id": user.ID})
}

// validatePassword enforces min-length 12, at least one digit.
func validatePassword(p string) error {
    if len(p) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    hasDigit := false
    for _, c := range p {
        if c >= '0' && c <= '9' {
            hasDigit = true
            break
        }
    }
    if !hasDigit {
        return errors.New("password must contain a digit")
    }
    return nil
}
```

### Task 4.3: /setup/license (activate online)

```go
// POST /api/v1/setup/license — body {license_server_url, license_key}.
// Calls License Server /activate with product="manage". On success, stores
// signed token + instance ID + server URL; transitions out of setup mode.
func (s *Server) handleSetupLicense(w http.ResponseWriter, r *http.Request) {
    state, _ := s.store.GetSetup(r.Context())
    if !state.AdminCreated {
        writeError(w, http.StatusConflict, "create admin first")
        return
    }
    if state.LicenseActivated {
        writeError(w, http.StatusConflict, "license already activated")
        return
    }
    var req struct {
        LicenseServerURL string `json:"license_server_url"`
        LicenseKey       string `json:"license_key"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LicenseServerURL == "" || req.LicenseKey == "" {
        writeError(w, http.StatusBadRequest, "license_server_url and license_key required")
        return
    }

    // Use the License Server client shipped in internal/license.
    client := license.NewServerClient(req.LicenseServerURL)
    instanceID := uuid.Must(uuid.NewV7()).String()
    resp, err := client.Activate(r.Context(), license.ActivateRequest{
        LicenseKey:  req.LicenseKey,
        MachineID:   license.MachineFingerprint(),
        Product:     "manage",
    })
    if err != nil {
        writeError(w, http.StatusBadRequest, "activation failed: "+err.Error())
        return
    }
    if !resp.Features.Manage {
        writeError(w, http.StatusForbidden, "license does not grant manage product")
        return
    }
    if err := s.store.SaveLicenseActivation(r.Context(), req.LicenseServerURL, req.LicenseKey, resp.SignedToken, instanceID); err != nil {
        writeError(w, http.StatusInternalServerError, "save activation: "+err.Error())
        return
    }
    s.refreshSetupMode(r.Context())

    writeJSON(w, http.StatusOK, map[string]any{
        "ok":       true,
        "features": resp.Features,
        "limits":   resp.Limits,
    })
}
```

**NOTE on the License Server client:** The existing `internal/license/client.go` `ServerClient.Activate` has a specific request signature. Check it first — the current `ActivateRequest` may not carry a `Product` field (added in PR A's handleActivate but the client may lag). If it doesn't, add `Product` to the request struct and include in the POST body.

**NOTE on setup flow atomicity:** If `Activate` succeeds on LS but `SaveLicenseActivation` fails locally, the licence is still consumed on LS but Manage thinks it's not activated. Acceptable for B1 — admin retries setup/license and LS dedupes on `machine_fingerprint + licence_key`. Document the edge case in a comment.

**Tests** — 3 tests:
1. `TestSetupStatus_StartsAtAllFalse`
2. `TestSetupAdmin_CreatesFirstAdminAndTransitions`
3. `TestSetupLicense_PersistsAndExitsSetupMode` — uses a stub LS that the test spins up via `httptest.Server`.

- [ ] Write + test + commit: `feat(manageserver): /setup/status + /setup/admin + /setup/license handlers`.

---

## Phase 5 — License client + pusher wiring

### Task 5.1: License init on Server start

**Files:**
- Create: `pkg/manageserver/license.go`
- Create: `pkg/manageserver/license_test.go`

Flow in `Server.initLicence(ctx)` (called from `Run` or after setup completion):
1. Read setup state. If `LicenseActivated == false`, return — server stays in setup mode.
2. Parse `SignedToken` with `s.cfg.PublicKey` via `license.NewGuardFromToken`. If parse fails (expired / wrong key), revert setup to unactivated.
3. Construct `license.UsagePusher` with `LicenseServer: state.LicenseServerURL`, `LicenseKey: state.LicenseKey`, `InstanceID: state.InstanceID`, `Source: s.collectUsage`.
4. `go pusher.Run(ctx)` — canceller is the Server's lifecycle context.
5. Store `s.licenceGuard = guard`, `s.licencePusher = pusher`. Flip `s.setupMode = false`.

`collectUsage` returns `[]license.UsageMetric` — B1 reports only things we actually count locally: `CountUsers`, possibly `CountSessions`. Hosts / zones / scans come from B2. Skeleton:

```go
func (s *Server) collectUsage() []license.UsageMetric {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    var out []license.UsageMetric
    if n, err := s.store.CountUsers(ctx); err == nil {
        // No licence metric maps to "users" yet — could emit as a debug heartbeat.
    }
    _ = n
    return out
}
```

Even with zero metrics, the pusher emits a heartbeat every 60s, which is useful for License Server to detect a live instance.

**Integration test** — spin up a stub License Server, run `Server.initLicence`, assert pusher posts within 200ms.

- [ ] Write + test + commit: `feat(manageserver): licence init + usage pusher wired from setup state`.

---

## Phase 6 — Binary entrypoint

### Task 6.1: cmd/manageserver/main.go

Mirrors `cmd/licenseserver/main.go` structure — `run()` returns an error, `main` calls `log.Fatalf`. Env vars:

| Env | Required? | Default | Purpose |
|-----|-----------|---------|---------|
| `TRITON_MANAGE_LISTEN` | no | `:8082` | HTTP listen |
| `TRITON_MANAGE_DB_URL` | **yes** | — | Postgres DSN |
| `TRITON_MANAGE_JWT_SIGNING_KEY` | **yes** | — | HS256 secret, hex-encoded; min 32 bytes |
| `TRITON_MANAGE_LICENSE_SERVER_PUBKEY` | **yes** | — | License Server public key, hex-encoded; for parsing signed tokens |
| `TRITON_MANAGE_INSTANCE_ID` | no | generated | UUID for this instance |
| `TRITON_MANAGE_LICENSE_SERVER` | no | — | License Server URL (persisted on /setup/license) |
| `TRITON_MANAGE_LICENSE_KEY` | no | — | pre-configured licence key; if set, activates at startup |
| `TRITON_MANAGE_REPORT_SERVER` | no | — | Report Server URL (unused in B1; reserved for B2) |
| `TRITON_MANAGE_SESSION_TTL` | no | `24h` | JWT expiry |

Signal handling: `os.Interrupt`, `syscall.SIGTERM` → cancel context → `Server.Run` returns → `store.Close()` → exit 0.

- [ ] Write + manual smoke: `go build ./cmd/manageserver/ && ...`.
- [ ] Commit: `feat(cmd): manageserver binary with env-var config + signal handling`.

---

## Phase 7 — Report Server stub endpoint

### Task 7.1: POST /api/v1/enrol/manage stub

**Files:**
- Create: `pkg/server/handlers_enrol.go`
- Modify: `pkg/server/server.go` — mount route

```go
// handleEnrolManage is a stub for the Manage-Server → Report-Server mTLS
// enrolment handshake. B2 implements the actual cert issuance; this stub
// returns 501 with a descriptive message so B1 deployments have a stable
// endpoint to probe.
func (s *Server) handleEnrolManage(w http.ResponseWriter, r *http.Request) {
    writeError(w, http.StatusNotImplemented, "manage mTLS enrolment lands in PR B2 (triton#feat/manage-server-b2)")
}
```

Mount under the existing admin-authed `/api/v1/admin` subgroup — only a Report admin should be able to enrol a Manage instance.

- [ ] Write + test (returns 501 with authentication OK) + commit: `feat(server): stub /api/v1/admin/enrol/manage (B2 implements)`.

---

## Phase 8 — Container + compose + CI

### Task 8.1: Containerfile.manageserver

Multi-stage:

```dockerfile
FROM docker.io/library/golang:1.25 AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION}" \
    -o /triton-manageserver cmd/manageserver/main.go

FROM scratch
ENV HOME=/tmp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /triton-manageserver /triton-manageserver
EXPOSE 8082
ENTRYPOINT ["/triton-manageserver"]
```

### Task 8.2: compose.yaml profile

Add a `manageserver` service entry under `profiles: [manage-server]` depending on the existing postgres service.

### Task 8.3: Makefile + CI

Makefile targets mirror licenseserver:
- `build-manageserver`
- `container-build-manageserver`
- `container-run-manageserver`
- `container-stop-manageserver`

CI `.github/workflows/ci.yml` gains a `manage-server-test` job running unit + integration tests against the `manage` schema inside the existing Postgres service container.

- [ ] Write + commit: `build(manageserver): Containerfile + compose profile + Make targets + CI job`.

---

## Phase 9 — Integration tests + PR

### Task 9.1: End-to-end setup flow integration test

**File:** `test/integration/manage_setup_test.go`

Scenario: fresh DB → `GET /api/v1/setup/status` returns `setup_required: true` → `POST /api/v1/setup/admin` → status updates → `POST /api/v1/setup/license` against a stub License Server → status transitions to operational → `POST /api/v1/auth/login` succeeds with admin creds → `GET /api/v1/me` returns the user.

### Task 9.2: Final verification

```sh
go build ./...
go vet ./...
golangci-lint run ./...
TRITON_TEST_DB_URL="..." go test -tags integration ./pkg/managestore/... ./pkg/manageserver/... ./test/integration/...
make container-build-manageserver
```

All green.

- [ ] Commit: `test(integration): manage server full setup → auth → me flow`.
- [ ] Push branch + open draft PR.

---

## Acceptance checklist

- [ ] `cmd/manageserver/main.go` binary compiles; env-var contract documented.
- [ ] `make container-build-manageserver` produces an image.
- [ ] Empty DB → setup_required: true. `/setup/admin` creates the first user. `/setup/license` activates online against License Server. Transitions to operational.
- [ ] `/auth/login` returns JWT; `/me` returns the user; `/logout` invalidates the session.
- [ ] Role middleware returns 403 for mismatched roles (no non-test callers yet; just the test).
- [ ] License usage pusher starts after successful activation; posts heartbeats to License Server.
- [ ] Report Server's `/api/v1/admin/enrol/manage` returns 501 with a pointer to B2.
- [ ] Legacy vanilla JS manage UI at `pkg/server/ui/dist/manage/` still served by Report Server (untouched).
- [ ] All tests green; lint clean.

---

## Follow-on: PR B2 (Manage scanner + mTLS push)

After B1 lands:
1. Scanner orchestrator goroutine pool — queue scan jobs, worker pool, result queue.
2. mTLS Report-push — Report Server's `/api/v1/admin/enrol/manage` starts issuing `bundle.tar.gz` with a client cert; Manage uses the cert to POST results to Report's `/api/v1/scans`.
3. Re-mount existing scan-related handlers (`scanjobs`, `engine`, `agentpush`, `credentials`, `discovery`) under Manage's Chi router, gated by JWT + role middleware.
4. Scan-result queue table + drain goroutine.
5. Container image upgrade with scanner tools (nmap, arp-scan) if Manage runs native scans (or remote via orchestrator — TBD in B2 plan).

PR C then ships the Vue UI on top of B2.
