# Manage ↔ License Portal Cross-Service Licence Lifecycle Tests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four integration tests that wire a real `pkg/licenseserver` against a real `pkg/manageserver` (running via `RunOnListener`) over real TCP, validating the full licence lifecycle without stubs.

**Architecture:** Three minimal production-code changes enable real-port testing (`RunOnListener` split, `WatcherTickInterval` config field, configurable watcher ticker). A single new test file `test/integration/manage_licence_crossservice_test.go` boots both servers, drives the complete setup flow against the real License Portal, then exercises the four lifecycle paths. The manage server runs via the real `Run()` path so `runCtx` is set and boot-time watcher resume works.

**Tech Stack:** Go `//go:build integration`, `pkg/licenseserver`, `pkg/manageserver`, `pkg/managestore`, `pkg/licensestore`, `net`, `net/http/httptest`, `github.com/stretchr/testify`

---

## File Map

| File | Change |
|------|--------|
| `pkg/manageserver/config.go` | Add `WatcherTickInterval time.Duration` field |
| `pkg/manageserver/licence_watcher.go` | Use config interval instead of hardcoded 10s |
| `pkg/manageserver/server.go` | Split `Run()` → `Run()` + `RunOnListener()` |
| `test/integration/manage_licence_crossservice_test.go` | New file: fixture + 4 tests |

---

## Task 1: Add `WatcherTickInterval` to Config and wire it in `licence_watcher.go`

**Files:**
- Modify: `pkg/manageserver/config.go`
- Modify: `pkg/manageserver/licence_watcher.go`

- [ ] **Step 1: Add field to Config**

Open `pkg/manageserver/config.go`. After the `ReportServiceKey` field (line 50), add:

```go
// WatcherTickInterval is the polling interval for the pending-deactivation
// watcher goroutine. Zero defaults to 10s. Tests set this to ~100ms for
// deterministic fast-path coverage.
WatcherTickInterval time.Duration
```

The full Config struct after the edit:

```go
// Config wires the Manage Server runtime.
type Config struct {
	Listen        string            // admin HTTP listener; e.g. ":8082"
	DBUrl         string            // postgres DSN
	JWTSigningKey []byte            // HS256 secret; ≥32 bytes
	PublicKey     ed25519.PublicKey // License Server public key (for parsing signed tokens)
	InstanceID    string            // UUID for this Manage instance
	SessionTTL    time.Duration     // default 24h

	// Parallelism is the scan-orchestrator worker count (Batch E).
	// Zero defaults to 10 inside NewOrchestrator; negative is clamped
	// there too. Capped at 50 to bound Postgres connection usage.
	Parallelism int

	// GatewayListen is the :8443 mTLS listener address for agent
	// phone-home + scan ingestion (Batch F). Default ":8443".
	GatewayListen string

	// GatewayHostname is the DNS name or IP that admins publish to
	// agents — becomes the CN + SAN of the gateway's server leaf. For
	// local tests this is typically "127.0.0.1" or "localhost".
	GatewayHostname string

	// ManageGatewayURL is the URL enrolled agents dial (baked into the
	// bundle's config.yaml). If empty, Server.Run derives it from
	// GatewayHostname + GatewayListen.
	ManageGatewayURL string

	// GatewayRetryInterval is how often gatewayRetryLoop polls caStore.Load
	// when CA is not yet bootstrapped. Default 5s; tests override to shorter
	// for deterministic fast-path coverage.
	GatewayRetryInterval time.Duration

	// ReportServer is the base URL Manage calls to auto-enrol via
	// /api/v1/admin/enrol/manage during /setup/license. Empty = skip
	// auto-enrol (best-effort; admin can re-trigger later). Batch G.
	ReportServer string

	// ReportServiceKey is the shared secret sent as the
	// X-Triton-Service-Key header on the auto-enrol POST. Must match the
	// ServiceKey configured on the Report server's admin API. Empty skips
	// auto-enrol even when ReportServer is set. Batch G.
	ReportServiceKey string

	// WatcherTickInterval is the polling interval for the pending-deactivation
	// watcher goroutine. Zero defaults to 10s. Tests set this to ~100ms for
	// deterministic fast-path coverage.
	WatcherTickInterval time.Duration
}
```

- [ ] **Step 2: Wire interval in `licence_watcher.go`**

Replace line 16 in `pkg/manageserver/licence_watcher.go`:

```go
// Before:
ticker := time.NewTicker(10 * time.Second)

// After:
interval := s.cfg.WatcherTickInterval
if interval == 0 {
	interval = 10 * time.Second
}
ticker := time.NewTicker(interval)
```

Full file after edit:

```go
package manageserver

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
)

// runDeactivationWatcher polls while pending_deactivation is set.
// It fires deactivateNow once CountActive returns 0.
// Exits when ctx is cancelled, when the flag is cleared (cancel case),
// or after firing deactivation.
func (s *Server) runDeactivationWatcher(ctx context.Context) {
	interval := s.cfg.WatcherTickInterval
	if interval == 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state, err := s.store.GetSetup(ctx)
			if err != nil {
				log.Printf("deactivation watcher: read setup: %v", err)
				continue
			}
			if !state.PendingDeactivation {
				// Flag was cleared (admin cancelled). Exit watcher.
				return
			}

			var active int64
			if state.InstanceID != "" {
				if tenantID, err := uuid.Parse(state.InstanceID); err == nil {
					active, _ = s.scanjobsStore.CountActive(ctx, tenantID)
				}
			}
			if active > 0 {
				continue
			}

			if err := s.deactivateNow(ctx); err != nil {
				log.Printf("deactivation watcher: deactivateNow: %v", err)
			}
			return
		}
	}
}
```

- [ ] **Step 3: Verify it compiles**

```bash
go build ./pkg/manageserver/...
```

Expected: no output (clean build).

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/config.go pkg/manageserver/licence_watcher.go
git commit -m "feat(manageserver): configurable WatcherTickInterval for testability"
```

---

## Task 2: Split `Run()` into `Run()` + `RunOnListener()`

**Files:**
- Modify: `pkg/manageserver/server.go`

The current `Run()` calls `s.http.ListenAndServe()` inside a goroutine, which makes it impossible to know the bound port when using `:0`. We split it so tests can pre-create the listener and know the URL before calling `RunOnListener`.

- [ ] **Step 1: Add `net` import to server.go**

In `pkg/manageserver/server.go`, add `"net"` to the import block. The import block currently starts at line 4 — add it after `"fmt"`:

```go
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/manageserver/zones"
	"github.com/amiryahaya/triton/pkg/managestore"
)
```

- [ ] **Step 2: Replace `Run()` with `Run()` + `RunOnListener()`**

Find the `Run(ctx context.Context) error` function (starts at line 340). Replace the entire function with two functions:

```go
// Run creates a TCP listener on cfg.Listen then calls RunOnListener.
// This is the production entry point; cmd/manageserver calls this.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("manage server: listen %s: %w", s.cfg.Listen, err)
	}
	return s.RunOnListener(ctx, ln)
}

// RunOnListener runs the server on an already-bound listener. Tests call
// this after pre-creating a :0 listener to know the URL before the server
// starts accepting connections.
func (s *Server) RunOnListener(ctx context.Context, ln net.Listener) error {
	// Store the server context so handler-spawned goroutines (e.g. the
	// deactivation watcher) can respect server shutdown without holding
	// a stale request context.
	s.runCtx = ctx

	// Spawn the Batch E scanner pipeline before the HTTP listener comes
	// up so we never serve /scan-jobs while the orchestrator is offline.
	// startScannerPipeline derives a cancellable child context from ctx;
	// stopScannerPipeline waits for graceful exit. CA bootstrap rides
	// on the same instance_id resolution.
	pipelineWG := s.startScannerPipeline(ctx)

	// Resume pending deactivation watcher if server was restarted mid-deactivation.
	if setup, err := s.store.GetSetup(ctx); err == nil && setup.PendingDeactivation {
		if s.watcherRunning.CompareAndSwap(false, true) {
			go func() {
				defer s.watcherRunning.Store(false)
				s.runDeactivationWatcher(ctx)
			}()
		}
	}

	// Gateway listener runs concurrently with admin. Spawn it AFTER
	// startScannerPipeline (which bootstraps the CA) so the retry loop
	// sees a populated CA row on first-boot scenarios. When the CA is
	// not yet bootstrapped (e.g. /setup/license hasn't been called),
	// gatewayRetryLoop polls caStore.Load and brings the listener up
	// as soon as the CA lands, so the gateway self-recovers without a
	// server restart.
	gatewayWG := sync.WaitGroup{}
	gatewayWG.Add(1)
	go func() {
		defer gatewayWG.Done()
		s.gatewayRetryLoop(ctx)
	}()

	s.http = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := s.http.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		// Stop the usage pusher BEFORE waiting on HTTP shutdown so it
		// doesn't keep trying to reach the Licence Server while shutdown
		// is in progress (and so its goroutine exits cleanly).
		s.stopLicence()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr := s.http.Shutdown(shutdownCtx)
		// Wait for orchestrator + drain goroutines. The parent ctx is
		// already cancelled; they'll exit after their current poll tick.
		pipelineWG.Wait()
		gatewayWG.Wait()
		return shutdownErr
	case err := <-errCh:
		s.stopLicence()
		pipelineWG.Wait()
		gatewayWG.Wait()
		return err
	}
}
```

- [ ] **Step 3: Build to verify**

```bash
go build ./pkg/manageserver/... ./cmd/manageserver/...
```

Expected: no output.

- [ ] **Step 4: Run existing manage integration tests to confirm no regression**

```bash
go test -v -tags integration -race -p 1 -run 'TestManageLicence' \
  -count=1 ./test/integration/... 2>&1 | tail -20
```

Expected: all 5 `TestManageLicence_*` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/server.go
git commit -m "feat(manageserver): RunOnListener for pre-bound listener; Run delegates to it"
```

---

## Task 3: Cross-service test fixture

**Files:**
- Create: `test/integration/manage_licence_crossservice_test.go`

This task creates the file with build tag, imports, fixture struct, `newCSFixture`, and all helper functions. No test functions yet — those are Tasks 4–7.

- [ ] **Step 1: Create the file with fixture infrastructure**

```go
//go:build integration

// Cross-service licence lifecycle tests.
//
// These tests boot a real pkg/licenseserver (httptest) and a real
// pkg/manageserver (via RunOnListener) over TCP. The Manage Server calls the
// real License Portal for every lifecycle operation — no stubs.
//
// Tests:
//  1. TestCSLicence_Refresh          — refresh re-activates via real License Portal
//  2. TestCSLicence_ReplaceKey       — replace activates new key via real License Portal
//  3. TestCSLicence_Deactivate_Immediate — immediate deactivation calls real Deactivate
//  4. TestCSLicence_Deactivate_Queued   — queued deactivation watcher calls real Deactivate

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// csSchemaSeq allocates unique PG schemas across cross-service tests.
var csSchemaSeq atomic.Int64

// csJWTKey is a fixed 32-byte HS256 secret for cross-service tests.
var csJWTKey = []byte("manage-cs-test-jwt-key-32bytess!")

// csAdminKey is the License Portal admin key used in cross-service tests.
const csAdminKey = "cs-test-admin-key"

// csFixture holds the test rig for cross-service lifecycle tests.
type csFixture struct {
	// License Portal
	LSServer *httptest.Server
	LSPub    ed25519.PublicKey
	OrgID    string
	LicIDA   string // initial license (Pro, 5 seats) — used by Refresh + Deactivate tests
	LicIDB   string // second license (Enterprise, 2 seats) — used by ReplaceKey test

	// Manage Server
	ManageSrv   *manageserver.Server
	ManageURL   string
	ManageStore *managestore.PostgresStore
	AdminJWT    string
	InstanceID  string // from manage_setup after /setup/license completes
}

// newCSFixture boots a real License Portal (httptest) and a real Manage Server
// (via RunOnListener), drives the full setup flow, and returns the fixture.
// t.Cleanup handles teardown.
func newCSFixture(t *testing.T) *csFixture {
	t.Helper()
	// Allow http (not just https) for the license server URL in tests.
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")

	ctx := context.Background()
	f := &csFixture{}

	// -------------------------------------------------------------------------
	// License Portal side
	// -------------------------------------------------------------------------

	lsStore, err := licensestore.NewPostgresStore(ctx, testDBURL())
	if err != nil {
		t.Skipf("PostgreSQL unavailable (license store): %v", err)
	}
	require.NoError(t, lsStore.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = lsStore.TruncateAll(ctx)
		lsStore.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.LSPub = pub

	lsCfg := &licenseserver.Config{
		ListenAddr: ":0",
		AdminKeys:  []string{csAdminKey},
		SigningKey:  priv,
		PublicKey:   pub,
	}
	lsSrv := licenseserver.New(lsCfg, lsStore)
	f.LSServer = httptest.NewServer(lsSrv.Router())
	t.Cleanup(f.LSServer.Close)

	// Create org.
	resp := csLSAdminReq(t, f, "POST", "/api/v1/admin/orgs", map[string]string{"name": "CS-Test-Org"})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create org")
	var orgOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgOut))
	resp.Body.Close()
	f.OrgID = orgOut["id"].(string)

	// Create License A — Pro, 5 seats (initial activation + refresh + deactivate tests).
	resp = csLSAdminReq(t, f, "POST", "/api/v1/admin/licenses", map[string]any{
		"orgID": f.OrgID, "tier": "pro", "seats": 5, "days": 365,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create license A")
	var licAOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licAOut))
	resp.Body.Close()
	f.LicIDA = licAOut["id"].(string)

	// Create License B — Enterprise, 2 seats (replace-key test).
	resp = csLSAdminReq(t, f, "POST", "/api/v1/admin/licenses", map[string]any{
		"orgID": f.OrgID, "tier": "enterprise", "seats": 2, "days": 365,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create license B")
	var licBOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licBOut))
	resp.Body.Close()
	f.LicIDB = licBOut["id"].(string)

	// -------------------------------------------------------------------------
	// Manage Server side
	// -------------------------------------------------------------------------

	schema := fmt.Sprintf("test_manage_cs_%d", csSchemaSeq.Add(1))
	msStore, err := managestore.NewPostgresStoreInSchema(ctx, getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable (manage store): %v", err)
	}
	t.Cleanup(func() {
		_ = msStore.DropSchema(ctx)
		_ = msStore.Close()
	})
	f.ManageStore = msStore

	msCfg := &manageserver.Config{
		JWTSigningKey:       csJWTKey,
		PublicKey:           pub, // same key as License Portal signs tokens with
		SessionTTL:          time.Hour,
		GatewayListen:       "127.0.0.1:0",
		GatewayHostname:     "127.0.0.1",
		WatcherTickInterval: 100 * time.Millisecond,
	}
	msSrv, err := manageserver.New(msCfg, msStore, msStore.Pool())
	require.NoError(t, err)
	f.ManageSrv = msSrv

	// Pre-create the listener so we know the URL before Run starts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.ManageURL = "http://" + ln.Addr().String()

	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = msSrv.RunOnListener(runCtx, ln) }()

	// Wait for the manage server to be ready (polls /api/v1/health).
	csWaitReady(t, f.ManageURL)

	// Drive full setup: admin → license → login.
	csSetup(t, f)

	return f
}

// csSetup drives /setup/admin → /setup/license (against real LS) → /auth/login.
func csSetup(t *testing.T, f *csFixture) {
	t.Helper()
	const adminEmail = "admin@cstest.local"
	const adminPassword = "CS-test-password-1"

	resp := postJSON(t, f.ManageURL+"/api/v1/setup/admin", map[string]any{
		"email":    adminEmail,
		"name":     "CS Admin",
		"password": adminPassword,
	})
	body := csReadBody(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin: %s", body)

	// This is the first real cross-service call: Manage → real License Portal.
	resp = postJSON(t, f.ManageURL+"/api/v1/setup/license", map[string]any{
		"license_server_url": f.LSServer.URL,
		"license_key":        f.LicIDA,
	})
	body = csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license: %s", body)

	loginResp := postJSON(t, f.ManageURL+"/api/v1/auth/login", map[string]any{
		"email":    adminEmail,
		"password": adminPassword,
	})
	loginBytes, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login: %s", string(loginBytes))

	var loginOut map[string]any
	require.NoError(t, json.Unmarshal(loginBytes, &loginOut))
	tok, ok := loginOut["token"].(string)
	require.True(t, ok, "login must return token, got %+v", loginOut)
	f.AdminJWT = tok

	// Capture instance_id for direct DB operations in queued-deactivation test.
	ctx := context.Background()
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, state.InstanceID, "instance_id must be set after setup")
	f.InstanceID = state.InstanceID
}

// csWaitReady polls the manage server until it returns HTTP or times out at 5s.
func csWaitReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/v1/health")
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("manage server not ready within 5s")
}

// csManageReq sends an authenticated request to the Manage Server admin plane.
func csManageReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, f.ManageURL+path, bodyReader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+f.AdminJWT)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// csLSAdminReq sends an admin-keyed request to the License Portal.
func csLSAdminReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response {
	t.Helper()
	return licAdminReqWithKey(t, method, f.LSServer.URL+path, csAdminKey, body)
}

// csActivationsForLicense calls GET /api/v1/admin/activations?license={licID}
// on the License Portal and returns the decoded activation list.
func csActivationsForLicense(t *testing.T, f *csFixture, licID string) []map[string]any {
	t.Helper()
	resp := csLSAdminReq(t, f, "GET",
		fmt.Sprintf("/api/v1/admin/activations?license=%s", licID), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "list activations for %s", licID)
	var acts []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&acts))
	return acts
}

// csReadBody reads and closes the response body, returning it as a string.
func csReadBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

// csDeactivatedAt extracts the deactivated_at field from an activation map.
// Returns empty string if absent or null.
func csDeactivatedAt(act map[string]any) string {
	if v, ok := act["deactivated_at"]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
```

- [ ] **Step 2: Verify the file compiles (no test functions yet)**

```bash
go build -tags integration ./test/integration/
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add test/integration/manage_licence_crossservice_test.go
git commit -m "test(cs-licence): fixture + helpers for cross-service lifecycle tests"
```

---

## Task 4: `TestCSLicence_Refresh`

**Files:**
- Modify: `test/integration/manage_licence_crossservice_test.go`

- [ ] **Step 1: Write the failing test**

Append to `test/integration/manage_licence_crossservice_test.go`:

```go
// TestCSLicence_Refresh verifies that POST /admin/licence/refresh calls the
// real License Portal Activate endpoint, stores a new signed token, and keeps
// the guard live.
func TestCSLicence_Refresh(t *testing.T) {
	f := newCSFixture(t)

	// Capture the signed token currently stored after setup.
	ctx := context.Background()
	stateBefore, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	tokenBefore := stateBefore.SignedToken
	require.NotEmpty(t, tokenBefore, "setup must have stored a signed token")

	// POST /api/v1/admin/licence/refresh
	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/refresh", nil)
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "refresh must return ok:true, got %v", out)

	// Store: signed_token must have changed (License Portal issued a fresh token).
	stateAfter, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.NotEqual(t, tokenBefore, stateAfter.SignedToken,
		"signed_token must change after refresh")

	// Guard is still live — GET /admin/licence must return 200.
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"GET /admin/licence must return 200 after refresh: %s", licBody)

	// License Portal: at least one active activation exists for LicIDA.
	acts := csActivationsForLicense(t, f, f.LicIDA)
	require.NotEmpty(t, acts, "License Portal must have at least one activation for LicIDA")
	active := 0
	for _, a := range acts {
		if csDeactivatedAt(a) == "" {
			active++
		}
	}
	require.Greater(t, active, 0,
		"License Portal must have at least one non-deactivated activation for LicIDA")
}
```

- [ ] **Step 2: Run the test to verify it passes**

```bash
go test -v -tags integration -race -run TestCSLicence_Refresh \
  -count=1 -p 1 ./test/integration/... 2>&1 | tail -30
```

Expected:
```
--- PASS: TestCSLicence_Refresh (...)
PASS
```

- [ ] **Step 3: Commit**

```bash
git add test/integration/manage_licence_crossservice_test.go
git commit -m "test(cs-licence): TestCSLicence_Refresh — refresh calls real License Portal"
```

---

## Task 5: `TestCSLicence_ReplaceKey`

**Files:**
- Modify: `test/integration/manage_licence_crossservice_test.go`

- [ ] **Step 1: Append the test**

```go
// TestCSLicence_ReplaceKey verifies that POST /admin/licence/replace activates
// a new key against the real License Portal and stores the new key in the DB.
// The old key's activation is intentionally NOT deactivated by replace (per spec —
// the orphaned seat is admin-managed via the License Portal).
func TestCSLicence_ReplaceKey(t *testing.T) {
	f := newCSFixture(t)

	// POST /api/v1/admin/licence/replace with LicIDB.
	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/replace",
		map[string]string{"license_key": f.LicIDB})
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "replace: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "replace must return ok:true, got %v", out)

	// Store: license_key must now be LicIDB.
	ctx := context.Background()
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.Equal(t, f.LicIDB, state.LicenseKey,
		"license_key in DB must be LicIDB after replace")

	// License Portal: LicIDB must have an active activation.
	actsB := csActivationsForLicense(t, f, f.LicIDB)
	require.NotEmpty(t, actsB, "License Portal must have an activation for LicIDB")
	activeB := 0
	for _, a := range actsB {
		if csDeactivatedAt(a) == "" {
			activeB++
		}
	}
	require.Greater(t, activeB, 0, "LicIDB must have a non-deactivated activation")

	// License Portal: LicIDA activation is still active (replace does NOT
	// deactivate the old key — per spec, that seat is orphaned until admin acts).
	actsA := csActivationsForLicense(t, f, f.LicIDA)
	require.NotEmpty(t, actsA, "LicIDA must still have activations after replace")
	activeA := 0
	for _, a := range actsA {
		if csDeactivatedAt(a) == "" {
			activeA++
		}
	}
	require.Greater(t, activeA, 0, "LicIDA activation must remain active after replace")

	// Guard is still live.
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"GET /admin/licence must return 200 after replace: %s", licBody)
}
```

- [ ] **Step 2: Run the test**

```bash
go test -v -tags integration -race -run TestCSLicence_ReplaceKey \
  -count=1 -p 1 ./test/integration/... 2>&1 | tail -30
```

Expected: `--- PASS: TestCSLicence_ReplaceKey (...)`

- [ ] **Step 3: Commit**

```bash
git add test/integration/manage_licence_crossservice_test.go
git commit -m "test(cs-licence): TestCSLicence_ReplaceKey — replace calls real License Portal"
```

---

## Task 6: `TestCSLicence_Deactivate_Immediate`

**Files:**
- Modify: `test/integration/manage_licence_crossservice_test.go`

- [ ] **Step 1: Append the test**

```go
// TestCSLicence_Deactivate_Immediate verifies that POST /admin/licence/deactivate
// with no active scan jobs calls the real License Portal Deactivate endpoint,
// clears local activation state, and puts the Manage Server into setup mode.
func TestCSLicence_Deactivate_Immediate(t *testing.T) {
	f := newCSFixture(t)

	// No scan jobs seeded — deactivation must be immediate (200, not 202).
	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/deactivate", nil)
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"immediate deactivate must return 200: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "immediate deactivate: ok must be true, got %v", out)

	// License Portal: the activation for LicIDA must now have deactivated_at set.
	acts := csActivationsForLicense(t, f, f.LicIDA)
	require.NotEmpty(t, acts, "License Portal must have an activation for LicIDA")
	deactivated := 0
	for _, a := range acts {
		if csDeactivatedAt(a) != "" {
			deactivated++
		}
	}
	require.Greater(t, deactivated, 0,
		"License Portal: at least one activation for LicIDA must have deactivated_at set")

	// Manage Server: GET /admin/licence must return 503 (setup mode).
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusServiceUnavailable, licResp.StatusCode,
		"GET /admin/licence after deactivation must return 503: %s", licBody)

	// Manage Store: license activation must be cleared.
	ctx := context.Background()
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.False(t, state.LicenseActivated, "LicenseActivated must be false after deactivation")
	require.Empty(t, state.LicenseKey, "LicenseKey must be empty after deactivation")
	require.Empty(t, state.SignedToken, "SignedToken must be empty after deactivation")
}
```

- [ ] **Step 2: Run the test**

```bash
go test -v -tags integration -race -run TestCSLicence_Deactivate_Immediate \
  -count=1 -p 1 ./test/integration/... 2>&1 | tail -30
```

Expected: `--- PASS: TestCSLicence_Deactivate_Immediate (...)`

- [ ] **Step 3: Commit**

```bash
git add test/integration/manage_licence_crossservice_test.go
git commit -m "test(cs-licence): TestCSLicence_Deactivate_Immediate — calls real Deactivate"
```

---

## Task 7: `TestCSLicence_Deactivate_Queued`

**Files:**
- Modify: `test/integration/manage_licence_crossservice_test.go`

- [ ] **Step 1: Append the test**

```go
// TestCSLicence_Deactivate_Queued verifies the queued deactivation path:
// deactivate returns 202 while a scan job is running, then the watcher
// goroutine (100ms tick, set via WatcherTickInterval) fires deactivateNow
// against the real License Portal once the scan job completes.
func TestCSLicence_Deactivate_Queued(t *testing.T) {
	f := newCSFixture(t)
	ctx := context.Background()

	tenantID, err := uuid.Parse(f.InstanceID)
	require.NoError(t, err)

	// Seed a running scan job directly so CountActive returns 1.
	// zone_id and host_id are nullable, so no FK rows are required.
	var jobID uuid.UUID
	require.NoError(t, f.ManageStore.Pool().QueryRow(ctx,
		`INSERT INTO manage_scan_jobs (tenant_id, profile, status, running_heartbeat_at)
		 VALUES ($1, 'quick', 'running', NOW())
		 RETURNING id`,
		tenantID,
	).Scan(&jobID))

	// POST /admin/licence/deactivate — must return 202 (queued) because
	// active scan count is 1.
	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/deactivate", nil)
	body := csReadBody(resp)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"deactivate with active scan must return 202: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["pending"], "pending must be true: %v", out)

	// Manage Server: licence still live while deactivation is pending.
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"licence must be live while pending: %s", licBody)

	// License Portal: activation still active (watcher has not fired yet).
	actsBefore := csActivationsForLicense(t, f, f.LicIDA)
	require.NotEmpty(t, actsBefore)
	for _, a := range actsBefore {
		require.Empty(t, csDeactivatedAt(a),
			"activation must not be deactivated yet: %v", a)
	}

	// Complete the running scan job so CountActive drops to 0.
	_, err = f.ManageStore.Pool().Exec(ctx,
		`UPDATE manage_scan_jobs SET status = 'completed', finished_at = NOW() WHERE id = $1`,
		jobID,
	)
	require.NoError(t, err)

	// Wait for the watcher (100ms tick) to fire deactivateNow.
	// Allow up to 2s: 20× the tick interval.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		licResp2 := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
		io.Copy(io.Discard, licResp2.Body) //nolint:errcheck
		licResp2.Body.Close()
		if licResp2.StatusCode == http.StatusServiceUnavailable {
			// Watcher fired — verify the License Portal shows the deactivation.
			actsAfter := csActivationsForLicense(t, f, f.LicIDA)
			require.NotEmpty(t, actsAfter)
			deactivated := 0
			for _, a := range actsAfter {
				if csDeactivatedAt(a) != "" {
					deactivated++
				}
			}
			require.Greater(t, deactivated, 0,
				"License Portal must show deactivated_at after watcher fires")
			return // test passes
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("deactivation watcher did not fire within 2s after scan job completed")
}
```

- [ ] **Step 2: Run the test**

```bash
go test -v -tags integration -race -run TestCSLicence_Deactivate_Queued \
  -count=1 -p 1 ./test/integration/... 2>&1 | tail -30
```

Expected: `--- PASS: TestCSLicence_Deactivate_Queued (...)` — should complete in under 3s.

- [ ] **Step 3: Run all four cross-service tests together**

```bash
go test -v -tags integration -race -run 'TestCSLicence' \
  -count=1 -p 1 ./test/integration/... 2>&1 | tail -30
```

Expected: all 4 `TestCSLicence_*` tests PASS.

- [ ] **Step 4: Run full integration suite to confirm no regression**

```bash
go test -tags integration -race -p 1 -count=1 ./test/integration/... 2>&1 | tail -10
```

Expected: `ok  	github.com/amiryahaya/triton/test/integration`

- [ ] **Step 5: Commit**

```bash
git add test/integration/manage_licence_crossservice_test.go
git commit -m "test(cs-licence): TestCSLicence_Deactivate_Queued — watcher calls real Deactivate"
```

---

## Summary

| Task | What ships |
|------|-----------|
| 1 | `WatcherTickInterval` config field + watcher wired to use it |
| 2 | `RunOnListener` split; `Run()` delegates |
| 3 | Test file with fixture, helpers, 0 test functions |
| 4 | `TestCSLicence_Refresh` |
| 5 | `TestCSLicence_ReplaceKey` |
| 6 | `TestCSLicence_Deactivate_Immediate` |
| 7 | `TestCSLicence_Deactivate_Queued` |
