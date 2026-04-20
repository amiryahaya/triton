# Manage Server Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship 6 small Manage Server hardening items in one bundled PR: HTTPS enforcement on license_server_url, `/api/v1/admin/gateway-health` endpoint + topbar pill, gateway listener self-recovery retry loop, zone/host delete cascade warnings, real `/api/v1/admin/licence` endpoint + view rewire, real `/api/v1/admin/settings` endpoint + view rewire.

**Architecture:** Six independent items grouped into six batches (A–F). Backend items use existing Guard + managestore + scanresults helpers. Frontend items extend existing Pinia stores + views. No new packages; no migrations; no breaking changes. Branch `feat/manage-hardening` based on `feat/manage-password-change` (PR #87).

**Tech Stack:** Go 1.25 + chi/v5 + existing `internal/license.Guard` (HasFeature/LimitCap/CurrentUsage/SoftBufferCeiling/Tier) + existing `scanresults.LoadLicenseState`. Vue 3 + Pinia + Vitest. No new dependencies.

---

## File structure

### New files (backend)

- `pkg/manageserver/handlers_gateway_health.go` — `handleGatewayHealth` + `GatewayHealthResponse` struct.
- `pkg/manageserver/handlers_gateway_health_test.go` — build-tagged integration tests.
- `pkg/manageserver/handlers_admin_licence.go` — `handleLicenceSummary` + response struct.
- `pkg/manageserver/handlers_admin_licence_test.go` — integration tests.
- `pkg/manageserver/handlers_admin_settings.go` — `handleSettings` + response struct.
- `pkg/manageserver/handlers_admin_settings_test.go` — integration tests.
- `pkg/manageserver/server_gateway_retry_test.go` — retry-loop integration tests.

### New files (frontend)

- `web/apps/manage-portal/src/stores/gatewayHealth.ts` — polling store.
- `web/apps/manage-portal/tests/stores/gatewayHealth.spec.ts` — store lifecycle test.

### Modified files (backend)

- `pkg/manageserver/handlers_setup.go::handleSetupLicense` — HTTPS validation.
- `pkg/manageserver/handlers_setup_test.go` — append HTTPS tests.
- `pkg/manageserver/server.go` — new `gatewayState` field, new `serverLeaf` field, refactored `runGateway` → `gatewayRetryLoop`, new `GatewayRetryInterval` config default.
- `pkg/manageserver/config.go` — optional new `GatewayRetryInterval time.Duration` field.

### Modified files (frontend)

- `web/packages/api-client/src/manageServer.ts` — three new methods (`getGatewayHealth`, `getLicence`, `getSettings`).
- `web/packages/api-client/src/manageServer.types.ts` — `GatewayHealthResponse`, `LicenceSummary`, `LimitPair`, `SettingsSummary` types.
- `web/packages/api-client/src/index.ts` — re-export new types.
- `web/packages/api-client/tests/manageServer.test.ts` — three new request-shape tests.
- `web/apps/manage-portal/src/stores/licence.ts` — replace placeholder `fetch()` with real call.
- `web/apps/manage-portal/src/stores/settings.ts` — replace placeholder `fetch()` with real call.
- `web/apps/manage-portal/src/views/Licence.vue` — rewire to real store shape.
- `web/apps/manage-portal/src/views/Settings.vue` — remove placeholder note, wire real fields.
- `web/apps/manage-portal/src/views/Zones.vue` — updated TConfirmDialog message.
- `web/apps/manage-portal/src/views/Hosts.vue` — updated TConfirmDialog message.
- `web/apps/manage-portal/src/App.vue` — gateway-cert warning pill next to existing change-password button.
- `web/apps/manage-portal/tests/views/Licence.spec.ts` — rewrite for new render.
- `web/apps/manage-portal/tests/views/Settings.spec.ts` — rewrite for new render.
- `web/apps/manage-portal/tests/views/Zones.spec.ts` — assert new warning text.
- `web/apps/manage-portal/tests/views/Hosts.spec.ts` — assert new warning text.

---

## Batch A — HTTPS enforcement on `/setup/license`

### Task A1: Reject plaintext License Server URLs

**Files:**
- Modify: `pkg/manageserver/handlers_setup.go::handleSetupLicense`
- Modify: `pkg/manageserver/handlers_setup_test.go`

- [ ] **Step 1: Write failing tests** in `pkg/manageserver/handlers_setup_test.go` (append to the existing integration test file — it already has `//go:build integration`):

```go
func TestSetupLicense_RejectsHTTP(t *testing.T) {
    t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "")
    srv, _, cleanup := openSetupServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    // First create admin
    _, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
        "email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
    }`))

    resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(`{
        "license_server_url":"http://insecure.example.com","license_key":"abc"
    }`))
    require.NoError(t, err)
    defer resp.Body.Close()
    require.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var body map[string]any
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
    assert.Contains(t, fmt.Sprintf("%v", body["error"]), "https://")
}

func TestSetupLicense_AllowsHTTPWhenEnvSet(t *testing.T) {
    t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
    srv, _, cleanup := openSetupServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    // Stub LS accepting activation
    ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte(`{"token":"stub","features":{"manage":true}}`))
    }))
    defer ls.Close()

    _, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
        "email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
    }`))

    resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(fmt.Sprintf(`{
        "license_server_url":%q,"license_key":"abc"
    }`, ls.URL)))
    require.NoError(t, err)
    defer resp.Body.Close()
    // With the env set, we no longer reject at the HTTPS gate. Downstream
    // activation may still fail if the stub doesn't sign a valid token —
    // a 200 or a 400 with a different error message both prove we passed
    // the gate. Assert: body does NOT contain the https:// rejection msg.
    body, _ := io.ReadAll(resp.Body)
    assert.NotContains(t, string(body), "must use https://")
}

func TestSetupLicense_RejectsMissingScheme(t *testing.T) {
    t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "")
    srv, _, cleanup := openSetupServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    _, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
        "email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
    }`))

    resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(`{
        "license_server_url":"example.com","license_key":"abc"
    }`))
    require.NoError(t, err)
    defer resp.Body.Close()
    require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
```

Add imports if missing: `"os"`, `"strings"`, `"io"`.

- [ ] **Step 2: Run tests, verify they fail**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-hardening
go test -tags integration -run 'TestSetupLicense_Rejects|TestSetupLicense_Allows' ./pkg/manageserver/...
```

Expected: FAIL (HTTPS check not yet implemented).

- [ ] **Step 3: Add HTTPS validation** in `pkg/manageserver/handlers_setup.go::handleSetupLicense`, just after the body-decode block (around line 123 — where `req.LicenseServerURL` is first validated for non-empty), before the existing `client := license.NewServerClient(req.LicenseServerURL)` line:

```go
// Reject plaintext License Server URLs unless dev opts out explicitly.
// Production must use HTTPS so the license key isn't exposed on the wire.
if !strings.HasPrefix(req.LicenseServerURL, "https://") {
    if os.Getenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER") != "true" {
        writeError(w, http.StatusBadRequest,
            "license_server_url must use https:// (set TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER=true to override in dev)")
        return
    }
}
```

Add imports: `"os"`, `"strings"`.

- [ ] **Step 4: Run tests, verify pass**

```bash
go test -tags integration -run 'TestSetupLicense_Rejects|TestSetupLicense_Allows' ./pkg/manageserver/...
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/handlers_setup.go pkg/manageserver/handlers_setup_test.go
git commit -m "feat(manageserver): reject plaintext license_server_url with dev-mode opt-out"
```

---

## Batch B — `/api/v1/admin/gateway-health` endpoint

### Task B1: Add `gatewayState` + `serverLeaf` state fields to Server

**Files:**
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Define constants + fields at the top of server.go**, near the existing `Server` struct definition:

```go
// Gateway listener lifecycle states. Read by /admin/gateway-health, written
// by gatewayRetryLoop.
const (
    gatewayStatePendingSetup int32 = 0 // CA not yet minted; retry loop polling
    gatewayStateRetryLoop    int32 = 1 // Retry loop running, listener not yet up
    gatewayStateUp           int32 = 2 // Listener bound, cert minted, healthy
    gatewayStateFailed       int32 = 3 // Listener exited with error
)
```

Add to the `Server` struct (next to existing `mu sync.RWMutex` and related fields):

```go
    gatewayState atomic.Int32 // see gatewayState* constants
    serverLeaf   atomic.Value // stores tls.Certificate when listener is up
```

(No need to initialise — both default to zero values, which match `gatewayStatePendingSetup` + nil `tls.Certificate`.)

Add import: `"sync/atomic"` if not already present.

- [ ] **Step 2: Run build to verify compiles**

```bash
go build ./...
```

Expected: clean. No behaviour change yet.

- [ ] **Step 3: Commit**

```bash
git add pkg/manageserver/server.go
git commit -m "feat(manageserver): add gatewayState + serverLeaf atomic fields"
```

### Task B2: Gateway-health handler + route + types

**Files:**
- Create: `pkg/manageserver/handlers_gateway_health.go`
- Modify: `pkg/manageserver/server.go` (add route)

- [ ] **Step 1: Write the handler file**:

```go
package manageserver

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "net/http"
    "time"

    "github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// GatewayHealthResponse is the JSON body returned by
// GET /api/v1/admin/gateway-health.
type GatewayHealthResponse struct {
    CABootstrapped    bool       `json:"ca_bootstrapped"`
    ListenerState     string     `json:"listener_state"`
    CertExpiresAt     *time.Time `json:"cert_expires_at"`
    CertDaysRemaining int        `json:"cert_days_remaining"`
}

var listenerStateNames = map[int32]string{
    gatewayStatePendingSetup: "pending_setup",
    gatewayStateRetryLoop:    "retry_loop",
    gatewayStateUp:           "up",
    gatewayStateFailed:       "failed",
}

// handleGatewayHealth reports gateway listener + CA + cert state.
//
// Always returns 200 with best-effort data: a DB error on the CA-load
// path returns ca_bootstrapped=false + logs a warning; this endpoint
// must never panic or block even when the gateway is in a bad state.
//
// GET /api/v1/admin/gateway-health
func (s *Server) handleGatewayHealth(w http.ResponseWriter, r *http.Request) {
    state := s.gatewayState.Load()
    resp := GatewayHealthResponse{
        ListenerState: listenerStateNames[state],
    }

    // CA bootstrap flag — one cheap row read.
    if s.caStore != nil {
        _, err := s.caStore.Load(r.Context())
        resp.CABootstrapped = err == nil || !errors.Is(err, ca.ErrNotFound)
        // Note: ErrNotFound means "CA not bootstrapped"; any OTHER error is
        // a transient DB failure, in which case we still report CABootstrapped
        // conservatively as false but the listener_state reflects the truth.
        if err != nil && errors.Is(err, ca.ErrNotFound) {
            resp.CABootstrapped = false
        } else if err == nil {
            resp.CABootstrapped = true
        }
    }

    // Cert expiry — only when listener is up and we have a cached leaf.
    if state == gatewayStateUp {
        if leafAny := s.serverLeaf.Load(); leafAny != nil {
            if leaf, ok := leafAny.(tls.Certificate); ok && len(leaf.Certificate) > 0 {
                if cert, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
                    expiresAt := cert.NotAfter
                    resp.CertExpiresAt = &expiresAt
                    resp.CertDaysRemaining = int(time.Until(expiresAt) / (24 * time.Hour))
                }
            }
        }
    }

    writeJSON(w, http.StatusOK, resp)
    _ = context.Background() // silence unused import during intermediate steps
}
```

**Note on `ca.ErrNotFound`:** this sentinel is defined in `pkg/manageserver/ca/postgres.go` (check: `grep ErrNotFound pkg/manageserver/ca/*.go`). If the exported name differs (e.g. `ca.ErrCANotFound`), adjust the import.

- [ ] **Step 2: Mount the route** in `pkg/manageserver/server.go::buildRouter`, inside the `/api/v1/admin` subtree after the existing zones/hosts/scan-jobs mounts:

```go
        r.Get("/gateway-health", s.handleGatewayHealth)
```

- [ ] **Step 3: Build + manual smoke**

```bash
go build ./...
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/handlers_gateway_health.go pkg/manageserver/server.go
git commit -m "feat(manageserver): /admin/gateway-health endpoint"
```

### Task B3: Gateway-health integration tests

**Files:**
- Create: `pkg/manageserver/handlers_gateway_health_test.go`

- [ ] **Step 1: Write tests**:

```go
//go:build integration

package manageserver_test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/pkg/manageserver"
)

func TestGatewayHealth_PendingSetup(t *testing.T) {
    // Fresh DB, no CA bootstrapped.
    srv, _, cleanup := openOperationalServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    token := loginAsAdmin(t, ts.URL)
    req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/gateway-health", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    require.Equal(t, http.StatusOK, resp.StatusCode)
    var body manageserver.GatewayHealthResponse
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
    assert.False(t, body.CABootstrapped)
    assert.Equal(t, "pending_setup", body.ListenerState)
    assert.Nil(t, body.CertExpiresAt)
    assert.Equal(t, 0, body.CertDaysRemaining)
}

func TestGatewayHealth_Up(t *testing.T) {
    // openOperationalServerWithGateway is a new helper (see step 2) that
    // boots a Server with the gateway retry loop having already flipped
    // to "up" — easiest implementation: manually bootstrap the CA +
    // mint a cert + set s.gatewayState + s.serverLeaf before the test
    // HTTP server starts.
    srv, _, cleanup := openOperationalServerWithGateway(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    token := loginAsAdmin(t, ts.URL)
    req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/gateway-health", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    require.Equal(t, http.StatusOK, resp.StatusCode)
    var body manageserver.GatewayHealthResponse
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
    assert.True(t, body.CABootstrapped)
    assert.Equal(t, "up", body.ListenerState)
    require.NotNil(t, body.CertExpiresAt)
    // Server leaf is minted for ~90 days at issue time.
    assert.Greater(t, body.CertDaysRemaining, 80)
    assert.LessOrEqual(t, body.CertDaysRemaining, 91)
}
```

The helpers `openOperationalServer`, `loginAsAdmin`, and `openOperationalServerWithGateway` must exist in the test helper file. The first two already exist (see `pkg/manageserver/middleware_test.go` or `handlers_setup_test.go`). `openOperationalServerWithGateway` is new — add it to a helpers file:

```go
// openOperationalServerWithGateway boots an operational server AND
// bootstraps the CA + mints a server leaf + sets gatewayState=up so
// /gateway-health reports the "up" path. Used by gateway-health tests
// that want to exercise the happy path without waiting for the retry
// loop to converge.
func openOperationalServerWithGateway(t *testing.T) (*manageserver.Server, managestore.Store, func()) {
    t.Helper()
    srv, store, cleanup := openOperationalServer(t)

    // Bootstrap CA + server leaf manually via the exported test helper on Server.
    require.NoError(t, srv.BootstrapGatewayForTest(context.Background()))

    return srv, store, cleanup
}
```

This requires adding a `BootstrapGatewayForTest` test-only method on Server (not exported in normal builds — use a build tag `_test.go` file, or just export it with clear naming). Simpler path: add the method in a new file `pkg/manageserver/testing_gateway.go`:

```go
//go:build integration

package manageserver

import (
    "context"

    "github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// BootstrapGatewayForTest triggers one synchronous pass of CA bootstrap +
// leaf mint + gatewayState transition to "up". Used by integration tests
// that need the gateway-health endpoint to report "up" without racing
// the retry-loop goroutine.
//
// Exported only under the integration build tag.
func (s *Server) BootstrapGatewayForTest(ctx context.Context) error {
    instance, err := s.store.GetSetup(ctx)
    if err != nil {
        return err
    }
    if _, err := s.caStore.Bootstrap(ctx, instance.InstanceID); err != nil {
        return err
    }
    return s.bootstrapGatewayListener(ctx)
}
```

`bootstrapGatewayListener` is a new method added in Task C1 (retry loop refactor). If the tests run before C1 lands, this test is deferred to after C1. Simpler: order the commits so C1 precedes B3 — see note at top of Batch C.

**Ordering note:** Task B3 depends on Task C1's `bootstrapGatewayListener` helper. Run C1 FIRST if you follow subagent-driven execution, then come back for B3. Alternatively, skip B3's `TestGatewayHealth_Up` initially (only run `TestGatewayHealth_PendingSetup`) and add it after C1.

- [ ] **Step 2: Run the pending-setup test** (which doesn't need the gateway up):

```bash
go test -tags integration -run TestGatewayHealth_PendingSetup ./pkg/manageserver/...
```

Expected: PASS.

- [ ] **Step 3: Commit the pending-setup test + helper infrastructure**

```bash
git add pkg/manageserver/handlers_gateway_health_test.go pkg/manageserver/testing_gateway.go
git commit -m "test(manageserver): gateway-health pending-setup path"
```

The `_Up` test's commit happens after C1 lands — see Batch C.

---

## Batch C — Gateway listener self-recovery

### Task C1: Refactor runGateway → gatewayRetryLoop + bootstrapGatewayListener

**Files:**
- Modify: `pkg/manageserver/server.go`
- Modify: `pkg/manageserver/config.go` (add `GatewayRetryInterval`)

- [ ] **Step 1: Add `GatewayRetryInterval` to Config**

In `pkg/manageserver/config.go`, after the existing `GatewayHostname` field:

```go
    // GatewayRetryInterval is how often gatewayRetryLoop polls caStore.Load
    // when CA is not yet bootstrapped. Default 5s; tests override to shorter.
    GatewayRetryInterval time.Duration
```

Add `"time"` import if not already present.

Default it inside `Server.New` (or wherever config defaults are applied today — search for existing defaults like `if cfg.Parallelism == 0 { cfg.Parallelism = 10 }`):

```go
    if cfg.GatewayRetryInterval == 0 {
        cfg.GatewayRetryInterval = 5 * time.Second
    }
```

- [ ] **Step 2: Find the existing `runGateway` method** in `pkg/manageserver/server.go`. Read it carefully — it currently does the one-shot CA-load + listener-start flow. Refactor as follows:

Extract the "mint leaf + start listener + block on ctx" logic into a new method `bootstrapGatewayListener(ctx)`:

```go
// bootstrapGatewayListener mints the server leaf, starts the TLS listener,
// and blocks until ctx.Done() or listener error. Updates s.gatewayState +
// s.serverLeaf on success. Idempotent is NOT a requirement — called at
// most once per Server lifetime by gatewayRetryLoop.
func (s *Server) bootstrapGatewayListener(ctx context.Context) error {
    // ... move the existing leaf-mint + http.Server-start code here ...
    // Set s.serverLeaf before server.ListenAndServeTLS begins.
    // s.gatewayState.Store(gatewayStateUp) AFTER ListenAndServeTLS begins (i.e.,
    // after the listener is bound — handled by the net.Listen path, not
    // ListenAndServeTLS which blocks).
    // On server.Serve error: s.gatewayState.Store(gatewayStateFailed).
}
```

Then replace `runGateway` with `gatewayRetryLoop`:

```go
// gatewayRetryLoop polls caStore.Load every cfg.GatewayRetryInterval until
// the CA is bootstrapped, then calls bootstrapGatewayListener. Meant to be
// spawned as a goroutine from Server.Run.
//
// Cancellation: ctx cancel stops both the poll loop AND (via
// bootstrapGatewayListener) the listener itself.
func (s *Server) gatewayRetryLoop(ctx context.Context) {
    s.gatewayState.Store(gatewayStatePendingSetup)

    ticker := time.NewTicker(s.cfg.GatewayRetryInterval)
    defer ticker.Stop()

    for {
        // Try to load the CA.
        if _, err := s.caStore.Load(ctx); err == nil {
            // CA exists — advance to retry_loop and start the listener.
            s.gatewayState.Store(gatewayStateRetryLoop)
            if err := s.bootstrapGatewayListener(ctx); err != nil {
                log.Printf("manageserver: gateway listener exited: %v", err)
                s.gatewayState.Store(gatewayStateFailed)
            }
            return
        }

        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            // loop
        }
    }
}
```

Update `Server.Run` to spawn `gatewayRetryLoop` as a goroutine (replacing the previous `runGateway` call):

```go
    go s.gatewayRetryLoop(ctx)
```

Search for any other callers of `runGateway` — typically only `Server.Run`. Remove the old method.

- [ ] **Step 3: Build + confirm compiles**

```bash
go build ./...
```

If build fails on `log.Printf`, add `"log"` import. If `time.NewTicker` unavailable, `"time"` import.

- [ ] **Step 4: Run existing gateway tests** to ensure no regression:

```bash
go test -tags integration -run TestGateway ./pkg/manageserver/...
```

Expected: all PASS (existing gateway tests should still work — the listener startup flow is unchanged, just wrapped).

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/server.go pkg/manageserver/config.go
git commit -m "feat(manageserver): gateway listener self-recovery via retry loop"
```

### Task C2: Retry-loop integration tests

**Files:**
- Create: `pkg/manageserver/server_gateway_retry_test.go`

- [ ] **Step 1: Write tests**:

```go
//go:build integration

package manageserver_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestGatewayRetry_BootstrapsMidRun: start Server.Run with CA absent,
// verify gatewayState=pending_setup/retry_loop, bootstrap CA via API,
// within a few retry intervals verify gatewayState=up.
func TestGatewayRetry_BootstrapsMidRun(t *testing.T) {
    // Use a short retry interval so the test completes quickly.
    srv, _, cleanup := openOperationalServerWithRetryInterval(t, 100*time.Millisecond)
    defer cleanup()

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    // Spawn Server.Run in the background.
    done := make(chan error, 1)
    go func() { done <- srv.Run(ctx) }()

    // Initially: pending_setup or retry_loop (race between state writes).
    time.Sleep(150 * time.Millisecond)
    assert.Equal(t, int32(0), srv.GatewayStateForTest(), "initial state should be pending_setup")

    // Bootstrap the CA via the test helper.
    setup, err := srv.Store().GetSetup(ctx)
    require.NoError(t, err)
    _, err = srv.CAStore().Bootstrap(ctx, setup.InstanceID)
    require.NoError(t, err)

    // Wait up to 2s for gatewayState to flip to up.
    assert.Eventually(t, func() bool {
        return srv.GatewayStateForTest() == 2 // gatewayStateUp
    }, 2*time.Second, 50*time.Millisecond)

    // Cancel + wait for goroutine exit.
    cancel()
    select {
    case <-done:
    case <-time.After(2 * time.Second):
        t.Fatal("Server.Run did not exit within 2s of cancel")
    }
}

func TestGatewayRetry_CancelStopsRetryLoop(t *testing.T) {
    srv, _, cleanup := openOperationalServerWithRetryInterval(t, 100*time.Millisecond)
    defer cleanup()

    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan error, 1)
    go func() { done <- srv.Run(ctx) }()

    time.Sleep(200 * time.Millisecond)
    cancel()

    select {
    case <-done:
    case <-time.After(1 * time.Second):
        t.Fatal("Server.Run did not exit within 1s of cancel (retry loop stuck)")
    }
}
```

New helpers needed on Server:
- `GatewayStateForTest() int32` — returns `s.gatewayState.Load()`
- `Store() managestore.Store` — exposes `s.store`
- `CAStore() *ca.PostgresStore` — exposes `s.caStore`

Add these to `pkg/manageserver/testing_gateway.go` (the integration-build-tagged file from Task B3):

```go
func (s *Server) GatewayStateForTest() int32 { return s.gatewayState.Load() }
func (s *Server) Store() managestore.Store   { return s.store }
func (s *Server) CAStore() *ca.PostgresStore { return s.caStore }
```

(Adjust types if `caStore` is a different concrete type.)

Add helper `openOperationalServerWithRetryInterval(t, interval)` to the same file or the shared helpers file:

```go
func openOperationalServerWithRetryInterval(t *testing.T, interval time.Duration) (*manageserver.Server, managestore.Store, func()) {
    t.Helper()
    // Mirror openOperationalServer but set cfg.GatewayRetryInterval first.
    // ... see existing helper for the pattern ...
}
```

The exact shape depends on how `openOperationalServer` is structured today — read that helper before writing this one.

- [ ] **Step 2: Run tests, verify pass**

```bash
go test -tags integration -run TestGatewayRetry ./pkg/manageserver/...
```

Expected: 2 PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/manageserver/server_gateway_retry_test.go pkg/manageserver/testing_gateway.go
git commit -m "test(manageserver): gateway retry loop bootstrap + cancel"
```

### Task C3: Add deferred `TestGatewayHealth_Up` test from Batch B3

- [ ] **Step 1: Append `TestGatewayHealth_Up`** (see Batch B3 Task B3 Step 1 for the test code) to `pkg/manageserver/handlers_gateway_health_test.go`.

- [ ] **Step 2: Run**

```bash
go test -tags integration -run TestGatewayHealth ./pkg/manageserver/...
```

Expected: 2 PASS (pending_setup + Up).

- [ ] **Step 3: Commit**

```bash
git add pkg/manageserver/handlers_gateway_health_test.go
git commit -m "test(manageserver): gateway-health up path"
```

---

## Batch D — Zone/host delete cascade warnings

### Task D1: Update Zones.vue confirm dialog

**Files:**
- Modify: `web/apps/manage-portal/src/views/Zones.vue`
- Modify: `web/apps/manage-portal/tests/views/Zones.spec.ts`

- [ ] **Step 1: Write failing test** — append to `Zones.spec.ts`:

```ts
it('renders cascade-aware delete confirmation', async () => {
  const pinia = createTestingPinia({
    createSpy: vi.fn,
    initialState: {
      zones: { items: [{ id: 'z1', name: 'dmz', description: '', created_at: '', updated_at: '' }] },
    },
  });
  const w = mount(Zones, { global: { plugins: [pinia], stubs: { TDataTable: false } } });
  // Click the Delete action on the row.
  await w.find('[data-test="zone-delete-z1"]').trigger('click');
  await w.vm.$nextTick();
  const modalText = w.find('[data-test="confirm-dialog"]').text();
  expect(modalText).toContain("dmz");
  expect(modalText).toContain("set zone_id to NULL");
  expect(modalText).toContain("cannot be undone");
});
```

Note: this test assumes the view adds `data-test="zone-delete-<id>"` + `data-test="confirm-dialog"` hooks. If the view uses TConfirmDialog differently, query by slot content.

- [ ] **Step 2: Run, verify fails**

```bash
cd web && pnpm --filter manage-portal test
```

- [ ] **Step 3: Update `Zones.vue`** — find the existing `<TConfirmDialog>` that fires on zone delete. Replace its `message` / `description` prop (whichever the component uses) with:

```
Deleting zone '{{ zoneToDelete?.name }}' will set zone_id to NULL on any
hosts in it (they become unassigned) and on any scan jobs referencing
this zone (audit trail preserved). Zone memberships are cascaded-deleted.
This cannot be undone.
```

Add the `data-test="confirm-dialog"` attribute to the dialog + `data-test="zone-delete-{id}"` to the delete button on each row so the test can find them.

- [ ] **Step 4: Run test, verify passes**

```bash
cd web && pnpm --filter manage-portal test
```

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/views/Zones.vue web/apps/manage-portal/tests/views/Zones.spec.ts
git commit -m "feat(manage-portal): zone delete confirmation spells out cascade"
```

### Task D2: Update Hosts.vue confirm dialog

**Files:**
- Modify: `web/apps/manage-portal/src/views/Hosts.vue`
- Modify: `web/apps/manage-portal/tests/views/Hosts.spec.ts`

Mirror Task D1 structure. The message becomes:

```
Deleting host '{{ hostToDelete?.hostname }}' will set host_id to NULL
on scan jobs referencing it. Historical scan results remain in the
queue / Report Server. This cannot be undone.
```

- [ ] **Step 1: Write failing test** — append to `Hosts.spec.ts`:

```ts
it('renders cascade-aware delete confirmation', async () => {
  const pinia = createTestingPinia({
    createSpy: vi.fn,
    initialState: {
      hosts: { items: [{ id: 'h1', hostname: 'db-01', os: 'linux', created_at: '', updated_at: '' }] },
    },
  });
  const w = mount(Hosts, { global: { plugins: [pinia], stubs: { TDataTable: false } } });
  await w.find('[data-test="host-delete-h1"]').trigger('click');
  await w.vm.$nextTick();
  const modalText = w.find('[data-test="confirm-dialog"]').text();
  expect(modalText).toContain('db-01');
  expect(modalText).toContain('set host_id to NULL');
  expect(modalText).toContain('cannot be undone');
});
```

- [ ] **Step 2: Run, fail.**

- [ ] **Step 3: Update `Hosts.vue`** — change the confirm dialog message + add the two `data-test` hooks.

- [ ] **Step 4: Run, pass.**

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/views/Hosts.vue web/apps/manage-portal/tests/views/Hosts.spec.ts
git commit -m "feat(manage-portal): host delete confirmation spells out cascade"
```

---

## Batch E — `/api/v1/admin/licence` endpoint + view rewire

### Task E1: Backend handler + types

**Files:**
- Create: `pkg/manageserver/handlers_admin_licence.go`
- Create: `pkg/manageserver/handlers_admin_licence_test.go`
- Modify: `pkg/manageserver/server.go` (route)

- [ ] **Step 1: Write failing test** in `handlers_admin_licence_test.go`:

```go
//go:build integration

package manageserver_test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/pkg/manageserver"
)

func TestLicence_Active(t *testing.T) {
    srv, _, cleanup := openOperationalServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    token := loginAsAdmin(t, ts.URL)
    req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/licence", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    require.Equal(t, http.StatusOK, resp.StatusCode)
    var body manageserver.LicenceSummary
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
    assert.NotEmpty(t, body.Tier)
    assert.NotEmpty(t, body.InstanceID)
    // openOperationalServer activates a licence with manage=true
    assert.True(t, body.Features["manage"])
    // limits struct always present (cap may be -1 meaning unlimited)
    assert.NotNil(t, body.Limits.Seats)
    assert.NotNil(t, body.Limits.Hosts)
}

func TestLicence_Inactive(t *testing.T) {
    // openSetupServer returns a server where setup is complete but
    // licenceGuard is nil (for some reason) — OR alternatively we
    // inject a server state where guard is nil after setup.
    // Easiest: inject nil guard via an exported test setter.
    srv, _, cleanup := openOperationalServer(t)
    defer cleanup()
    srv.SetLicenceGuardForTest(nil) // new helper (see step 3)
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    token := loginAsAdmin(t, ts.URL)
    req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/licence", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
```

- [ ] **Step 2: Run, fail.**

- [ ] **Step 3: Write the handler**:

```go
// pkg/manageserver/handlers_admin_licence.go
package manageserver

import (
    "net/http"
    "time"
)

// LicenceSummary is the JSON body of GET /api/v1/admin/licence.
type LicenceSummary struct {
    Tier               string            `json:"tier"`
    Features           map[string]bool   `json:"features"`
    Limits             LicenceLimits     `json:"limits"`
    LicenseServerURL   string            `json:"license_server_url"`
    InstanceID         string            `json:"instance_id"`
    LastPushedAt       *time.Time        `json:"last_pushed_at"`
    LastPushError      string            `json:"last_push_error"`
    ConsecutiveFailures int              `json:"consecutive_failures"`
}

type LicenceLimits struct {
    Seats  LimitPair           `json:"seats"`
    Hosts  LimitPair           `json:"hosts"`
    Agents LimitPair           `json:"agents"`
    Scans  ScansLimitPair      `json:"scans"`
}

type LimitPair struct {
    Cap  int64 `json:"cap"`
    Used int64 `json:"used"`
}

type ScansLimitPair struct {
    LimitPair
    SoftBufferCeiling int64 `json:"soft_buffer_ceiling"`
}

// handleLicenceSummary aggregates licence state from the Guard + setup
// state + scanresults license state for the /admin/licence endpoint.
//
// GET /api/v1/admin/licence
func (s *Server) handleLicenceSummary(w http.ResponseWriter, r *http.Request) {
    guard := s.guardSnapshot()
    if guard == nil {
        writeError(w, http.StatusServiceUnavailable, "licence inactive")
        return
    }

    setup, err := s.store.GetSetup(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, "read setup state")
        return
    }

    state, _ := s.scanResultsStore.LoadLicenseState(r.Context()) // nil-store OK

    resp := LicenceSummary{
        Tier:               string(guard.Tier()),
        Features:           map[string]bool{"manage": guard.HasFeature("manage")},
        LicenseServerURL:   setup.LicenseServerURL,
        InstanceID:         setup.InstanceID,
        LastPushError:      state.LastPushError,
        ConsecutiveFailures: state.ConsecutiveFailures,
    }
    if state.LastPushedAt != nil {
        resp.LastPushedAt = state.LastPushedAt
    }

    resp.Limits.Seats = LimitPair{
        Cap:  guard.LimitCap("seats", "total"),
        Used: guard.CurrentUsage("seats", "total"),
    }
    resp.Limits.Hosts = LimitPair{
        Cap:  guard.LimitCap("hosts", "total"),
        Used: guard.CurrentUsage("hosts", "total"),
    }
    resp.Limits.Agents = LimitPair{
        Cap:  guard.LimitCap("agents", "total"),
        Used: guard.CurrentUsage("agents", "total"),
    }
    resp.Limits.Scans = ScansLimitPair{
        LimitPair: LimitPair{
            Cap:  guard.LimitCap("scans", "monthly"),
            Used: guard.CurrentUsage("scans", "monthly"),
        },
        SoftBufferCeiling: guard.SoftBufferCeiling("scans", "monthly"),
    }

    writeJSON(w, http.StatusOK, resp)
}
```

**Note:** `s.scanResultsStore` is the existing scanresults store field on Server; if the field name differs (`s.pushStore`, `s.scanresults`, etc.), adjust the reference. Also note `state.LastPushedAt` type — the existing `scanresults.Status` struct uses `*time.Time` or `time.Time`; adjust accordingly.

- [ ] **Step 4: Add the test-only setter** in `pkg/manageserver/testing_gateway.go` (or a new `testing_licence.go` if you prefer):

```go
// SetLicenceGuardForTest overrides the licence guard for integration
// tests that need to exercise the "inactive guard" path.
func (s *Server) SetLicenceGuardForTest(g *license.Guard) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.licenceGuard = g
}
```

Add `"github.com/amiryahaya/triton/internal/license"` import.

- [ ] **Step 5: Mount the route** in `server.go::buildRouter`:

```go
        r.Get("/licence", s.handleLicenceSummary)
```

- [ ] **Step 6: Run tests, verify pass**

```bash
go test -tags integration -run TestLicence ./pkg/manageserver/...
```

Expected: 2 PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/handlers_admin_licence.go pkg/manageserver/handlers_admin_licence_test.go pkg/manageserver/server.go pkg/manageserver/testing_gateway.go
git commit -m "feat(manageserver): /admin/licence endpoint"
```

### Task E2: Frontend api-client + types

**Files:**
- Modify: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/index.ts`
- Modify: `web/packages/api-client/tests/manageServer.test.ts`

- [ ] **Step 1: Append types** to `manageServer.types.ts`:

```ts
export interface LimitPair {
  cap: number;
  used: number;
}

export interface ScansLimitPair extends LimitPair {
  soft_buffer_ceiling: number;
}

export interface LicenceSummary {
  tier: string;
  features: Record<string, boolean>;
  limits: {
    seats: LimitPair;
    hosts: LimitPair;
    agents: LimitPair;
    scans: ScansLimitPair;
  };
  license_server_url: string;
  instance_id: string;
  last_pushed_at: string | null;
  last_push_error: string;
  consecutive_failures: number;
}
```

- [ ] **Step 2: Append method** to `createManageApi` in `manageServer.ts`:

```ts
    getLicence: () => http.get<LicenceSummary>('/v1/admin/licence'),
```

Also make sure `LicenceSummary` is imported at the top.

- [ ] **Step 3: Re-export the types** in `index.ts`:

```ts
export type { LimitPair, ScansLimitPair, LicenceSummary } from './manageServer.types';
```

- [ ] **Step 4: Write failing test** — append to `tests/manageServer.test.ts`:

```ts
it('getLicence GETs /v1/admin/licence', async () => {
  await api.getLicence();
  expect(fake.calls[0]).toEqual({ method: 'GET', path: '/v1/admin/licence' });
});
```

- [ ] **Step 5: Run tests, verify pass**

```bash
cd web && pnpm --filter @triton/api-client test
```

- [ ] **Step 6: Commit**

```bash
git add web/packages/api-client/
git commit -m "feat(api-client): manageServer.getLicence + types"
```

### Task E3: Licence store + view rewire

**Files:**
- Modify: `web/apps/manage-portal/src/stores/licence.ts`
- Modify: `web/apps/manage-portal/src/views/Licence.vue`
- Modify: `web/apps/manage-portal/tests/views/Licence.spec.ts`

- [ ] **Step 1: Rewrite `stores/licence.ts`**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { LicenceSummary } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useLicenceStore = defineStore('licence', () => {
  const summary = ref<LicenceSummary | null>(null);
  const loading = ref(false);
  const error = ref('');

  async function fetch() {
    loading.value = true;
    error.value = '';
    try {
      summary.value = await useApiClient().get().getLicence();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'failed to load licence';
    } finally {
      loading.value = false;
    }
  }

  return { summary, loading, error, fetch };
});
```

- [ ] **Step 2: Rewrite `views/Licence.vue`**:

```vue
<script setup lang="ts">
import { onMounted, computed } from 'vue';
import { useRouter } from 'vue-router';
import { TPanel, TButton, TStatCard } from '@triton/ui';
import { useLicenceStore } from '../stores/licence';

const licence = useLicenceStore();
const router = useRouter();

onMounted(() => licence.fetch());

function fmtCap(cap: number): string {
  if (cap < 0) return 'unlimited';
  return cap.toLocaleString();
}

function pctUsed(pair: { cap: number; used: number }): string {
  if (pair.cap < 0 || pair.cap === 0) return '—';
  return `${Math.round((pair.used / pair.cap) * 100)}%`;
}

const showErrorPanel = computed(() => {
  const s = licence.summary;
  return !!s && (s.last_push_error !== '' || s.consecutive_failures > 0);
});

const shortURL = computed(() => {
  const u = licence.summary?.license_server_url ?? '';
  if (u.length <= 40) return u;
  return u.slice(0, 37) + '…';
});
</script>

<template>
  <section class="view">
    <h1>Licence</h1>

    <div v-if="licence.loading">Loading…</div>
    <div v-else-if="licence.error" class="err">{{ licence.error }}</div>
    <template v-else-if="licence.summary">
      <div class="grid">
        <TStatCard label="Tier" :value="licence.summary.tier" />
        <TStatCard label="Manage feature" :value="licence.summary.features.manage ? 'enabled' : 'disabled'" />
      </div>

      <TPanel title="Limits">
        <table class="limits">
          <thead>
            <tr><th>Metric</th><th>Cap</th><th>Used</th><th>% utilised</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>Seats</td>
              <td>{{ fmtCap(licence.summary.limits.seats.cap) }}</td>
              <td>{{ licence.summary.limits.seats.used.toLocaleString() }}</td>
              <td>{{ pctUsed(licence.summary.limits.seats) }}</td>
            </tr>
            <tr>
              <td>Hosts</td>
              <td>{{ fmtCap(licence.summary.limits.hosts.cap) }}</td>
              <td>{{ licence.summary.limits.hosts.used.toLocaleString() }}</td>
              <td>{{ pctUsed(licence.summary.limits.hosts) }}</td>
            </tr>
            <tr>
              <td>Agents</td>
              <td>{{ fmtCap(licence.summary.limits.agents.cap) }}</td>
              <td>{{ licence.summary.limits.agents.used.toLocaleString() }}</td>
              <td>{{ pctUsed(licence.summary.limits.agents) }}</td>
            </tr>
            <tr>
              <td>Scans (monthly)</td>
              <td>
                {{ fmtCap(licence.summary.limits.scans.cap) }}
                <span v-if="licence.summary.limits.scans.cap >= 0" class="subtext">
                  (soft ceiling {{ fmtCap(licence.summary.limits.scans.soft_buffer_ceiling) }})
                </span>
              </td>
              <td>{{ licence.summary.limits.scans.used.toLocaleString() }}</td>
              <td>{{ pctUsed(licence.summary.limits.scans) }}</td>
            </tr>
          </tbody>
        </table>
      </TPanel>

      <TPanel title="Heartbeat">
        <dl>
          <dt>Last successful push</dt>
          <dd>{{ licence.summary.last_pushed_at ?? 'never' }}</dd>
          <dt>Licence Server URL</dt>
          <dd :title="licence.summary.license_server_url">{{ shortURL }}</dd>
          <dt>Instance ID</dt>
          <dd class="mono">{{ licence.summary.instance_id }}</dd>
        </dl>
      </TPanel>

      <TPanel v-if="showErrorPanel" title="Push failures" variant="danger">
        <p v-if="licence.summary.consecutive_failures > 0" class="err">
          <strong>{{ licence.summary.consecutive_failures }}</strong> consecutive failures.
        </p>
        <pre v-if="licence.summary.last_push_error" class="err-text">{{ licence.summary.last_push_error.slice(0, 400) }}</pre>
      </TPanel>

      <TPanel title="Actions">
        <TButton variant="ghost" @click="router.push('/setup/license')">Re-activate</TButton>
      </TPanel>
    </template>
  </section>
</template>

<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: var(--space-3); }
.limits { width: 100%; border-collapse: collapse; }
.limits th, .limits td { text-align: left; padding: var(--space-2); border-bottom: 1px solid var(--border); }
.subtext { color: var(--text-muted); font-size: 0.8rem; }
.mono { font-family: var(--font-mono); }
.err { color: var(--danger); }
.err-text { font-family: var(--font-mono); font-size: 0.8rem; white-space: pre-wrap; }
</style>
```

- [ ] **Step 3: Rewrite `tests/views/Licence.spec.ts`**:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Licence from '../../src/views/Licence.vue';

describe('Licence view', () => {
  it('renders tier + limits + heartbeat when summary loads', () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        licence: {
          summary: {
            tier: 'enterprise',
            features: { manage: true },
            limits: {
              seats: { cap: 100, used: 7 },
              hosts: { cap: 1000, used: 42 },
              agents: { cap: 50, used: 3 },
              scans: { cap: 100000, used: 12345, soft_buffer_ceiling: 110000 },
            },
            license_server_url: 'https://license.example.com',
            instance_id: 'abc-123',
            last_pushed_at: '2026-04-21T12:00:00Z',
            last_push_error: '',
            consecutive_failures: 0,
          },
          loading: false,
          error: '',
        },
      },
    });
    const w = mount(Licence, { global: { plugins: [pinia], stubs: ['TStatCard', 'TPanel', 'TButton'] } });
    expect(w.html()).toContain('enterprise');
    expect(w.html()).toContain('Seats');
    expect(w.html()).toContain('Hosts');
    expect(w.html()).toContain('Agents');
    expect(w.html()).toContain('Scans');
    expect(w.html()).toContain('abc-123');
  });

  it('hides error panel when push state is healthy', () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        licence: {
          summary: {
            tier: 'free', features: {}, limits: {
              seats: { cap: -1, used: 0 }, hosts: { cap: -1, used: 0 },
              agents: { cap: -1, used: 0 }, scans: { cap: -1, used: 0, soft_buffer_ceiling: -1 },
            },
            license_server_url: '', instance_id: '',
            last_pushed_at: null, last_push_error: '', consecutive_failures: 0,
          },
          loading: false, error: '',
        },
      },
    });
    const w = mount(Licence, { global: { plugins: [pinia], stubs: ['TStatCard', 'TPanel', 'TButton'] } });
    expect(w.html()).not.toContain('consecutive failures');
  });

  it('shows error panel when consecutive_failures > 0', () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        licence: {
          summary: {
            tier: 'enterprise', features: { manage: true }, limits: {
              seats: { cap: 100, used: 0 }, hosts: { cap: 100, used: 0 },
              agents: { cap: 100, used: 0 }, scans: { cap: 100, used: 0, soft_buffer_ceiling: 100 },
            },
            license_server_url: '', instance_id: '',
            last_pushed_at: null,
            last_push_error: 'connection refused',
            consecutive_failures: 3,
          },
          loading: false, error: '',
        },
      },
    });
    const w = mount(Licence, { global: { plugins: [pinia], stubs: ['TStatCard', 'TPanel', 'TButton'] } });
    expect(w.html()).toContain('3');
    expect(w.html()).toContain('connection refused');
  });
});
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd web && pnpm --filter manage-portal test
```

- [ ] **Step 5: Build, verify clean**

```bash
cd web && pnpm --filter manage-portal build
```

- [ ] **Step 6: Commit**

```bash
git add web/apps/manage-portal/src/stores/licence.ts web/apps/manage-portal/src/views/Licence.vue web/apps/manage-portal/tests/views/Licence.spec.ts
git commit -m "feat(manage-portal): Licence view wired to real /admin/licence endpoint"
```

---

## Batch F — `/api/v1/admin/settings` endpoint + view rewire

### Task F1: Backend handler + test

**Files:**
- Create: `pkg/manageserver/handlers_admin_settings.go`
- Create: `pkg/manageserver/handlers_admin_settings_test.go`
- Modify: `pkg/manageserver/server.go` (route)

- [ ] **Step 1: Write failing test**:

```go
//go:build integration

package manageserver_test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/pkg/manageserver"
)

func TestSettings_ReturnsAllFields(t *testing.T) {
    srv, _, cleanup := openOperationalServer(t)
    defer cleanup()
    ts := httptest.NewServer(srv.Router())
    defer ts.Close()

    token := loginAsAdmin(t, ts.URL)
    req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/settings", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    require.Equal(t, http.StatusOK, resp.StatusCode)
    var body manageserver.SettingsSummary
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
    assert.Greater(t, body.Parallelism, 0)
    assert.NotEmpty(t, body.GatewayListen)
    assert.NotEmpty(t, body.ManageListen)
    assert.NotEmpty(t, body.InstanceID)
    assert.NotEmpty(t, body.Version)
}
```

- [ ] **Step 2: Run, fail.**

- [ ] **Step 3: Write handler**:

```go
// pkg/manageserver/handlers_admin_settings.go
package manageserver

import (
    "net/http"

    "github.com/amiryahaya/triton/internal/version"
)

type SettingsSummary struct {
    Parallelism      int    `json:"parallelism"`
    GatewayListen    string `json:"gateway_listen"`
    GatewayHostname  string `json:"gateway_hostname"`
    ReportServerURL  string `json:"report_server_url"`
    ManageListen     string `json:"manage_listen"`
    InstanceID       string `json:"instance_id"`
    Version          string `json:"version"`
}

// handleSettings returns the live runtime configuration for operator
// visibility. Read-only; no POST/PUT.
//
// GET /api/v1/admin/settings
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
    setup, err := s.store.GetSetup(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, "read setup state")
        return
    }

    writeJSON(w, http.StatusOK, SettingsSummary{
        Parallelism:     s.cfg.Parallelism,
        GatewayListen:   s.cfg.GatewayListen,
        GatewayHostname: s.cfg.GatewayHostname,
        ReportServerURL: s.cfg.ReportServer,
        ManageListen:    s.cfg.Listen,
        InstanceID:      setup.InstanceID,
        Version:         version.Version,
    })
}
```

- [ ] **Step 4: Mount the route** in `server.go::buildRouter`:

```go
        r.Get("/settings", s.handleSettings)
```

- [ ] **Step 5: Run test, verify pass**

```bash
go test -tags integration -run TestSettings_ReturnsAllFields ./pkg/manageserver/...
```

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/handlers_admin_settings.go pkg/manageserver/handlers_admin_settings_test.go pkg/manageserver/server.go
git commit -m "feat(manageserver): /admin/settings endpoint"
```

### Task F2: Frontend api-client + types

**Files:**
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/src/index.ts`
- Modify: `web/packages/api-client/tests/manageServer.test.ts`

- [ ] **Step 1: Append type** to `manageServer.types.ts`:

```ts
export interface SettingsSummary {
  parallelism: number;
  gateway_listen: string;
  gateway_hostname: string;
  report_server_url: string;
  manage_listen: string;
  instance_id: string;
  version: string;
}
```

- [ ] **Step 2: Append method** to `createManageApi`:

```ts
    getSettings: () => http.get<SettingsSummary>('/v1/admin/settings'),
```

(Import `SettingsSummary` at the top.)

- [ ] **Step 3: Re-export** in `index.ts`:

```ts
export type { SettingsSummary } from './manageServer.types';
```

- [ ] **Step 4: Append test**:

```ts
it('getSettings GETs /v1/admin/settings', async () => {
  await api.getSettings();
  expect(fake.calls[0]).toEqual({ method: 'GET', path: '/v1/admin/settings' });
});
```

- [ ] **Step 5: Run + commit**

```bash
cd web && pnpm --filter @triton/api-client test
cd ..
git add web/packages/api-client/
git commit -m "feat(api-client): manageServer.getSettings + type"
```

### Task F3: Settings store + view rewire

**Files:**
- Modify: `web/apps/manage-portal/src/stores/settings.ts`
- Modify: `web/apps/manage-portal/src/views/Settings.vue`
- Modify: `web/apps/manage-portal/tests/views/Settings.spec.ts`

- [ ] **Step 1: Rewrite store**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { SettingsSummary } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<SettingsSummary | null>(null);
  const loading = ref(false);
  const error = ref('');

  async function fetch() {
    loading.value = true;
    error.value = '';
    try {
      settings.value = await useApiClient().get().getSettings();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'failed to load settings';
    } finally {
      loading.value = false;
    }
  }

  return { settings, loading, error, fetch };
});
```

- [ ] **Step 2: Rewrite `views/Settings.vue`**:

```vue
<script setup lang="ts">
import { onMounted } from 'vue';
import { TPanel } from '@triton/ui';
import { useSettingsStore } from '../stores/settings';

const settings = useSettingsStore();
onMounted(() => settings.fetch());
</script>

<template>
  <section class="view">
    <h1>Settings</h1>
    <div v-if="settings.loading">Loading…</div>
    <div v-else-if="settings.error" class="err">{{ settings.error }}</div>
    <TPanel v-else-if="settings.settings" title="Runtime config">
      <dl>
        <dt>Manage listen</dt><dd class="mono">{{ settings.settings.manage_listen }}</dd>
        <dt>Gateway listen</dt><dd class="mono">{{ settings.settings.gateway_listen }}</dd>
        <dt>Gateway hostname</dt><dd class="mono">{{ settings.settings.gateway_hostname || '—' }}</dd>
        <dt>Report Server URL</dt><dd class="mono">{{ settings.settings.report_server_url || '—' }}</dd>
        <dt>Parallelism</dt><dd>{{ settings.settings.parallelism }}</dd>
        <dt>Instance ID</dt><dd class="mono">{{ settings.settings.instance_id }}</dd>
        <dt>Version</dt><dd class="mono">{{ settings.settings.version }}</dd>
      </dl>
    </TPanel>
  </section>
</template>

<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
dl { display: grid; grid-template-columns: 160px 1fr; gap: var(--space-1) var(--space-3); }
dt { color: var(--text-muted); }
dd { font-family: var(--font-mono); }
.mono { font-family: var(--font-mono); }
.err { color: var(--danger); }
</style>
```

Note: the "Note" paragraph from the placeholder view is removed — no follow-up disclaimer needed now that the endpoint is real.

- [ ] **Step 3: Rewrite Settings spec**:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Settings from '../../src/views/Settings.vue';

describe('Settings view', () => {
  it('renders all runtime config fields', () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        settings: {
          settings: {
            parallelism: 10,
            gateway_listen: ':8443',
            gateway_hostname: 'manage.example.com',
            report_server_url: 'https://report.example.com',
            manage_listen: ':8082',
            instance_id: 'abc-123',
            version: '0.1.0',
          },
          loading: false, error: '',
        },
      },
    });
    const w = mount(Settings, { global: { plugins: [pinia], stubs: ['TPanel'] } });
    expect(w.html()).toContain(':8443');
    expect(w.html()).toContain(':8082');
    expect(w.html()).toContain('manage.example.com');
    expect(w.html()).toContain('https://report.example.com');
    expect(w.html()).toContain('10');
    expect(w.html()).toContain('abc-123');
    expect(w.html()).toContain('0.1.0');
  });
});
```

- [ ] **Step 4: Run + commit**

```bash
cd web && pnpm --filter manage-portal test && pnpm --filter manage-portal build
cd ..
git add web/apps/manage-portal/src/stores/settings.ts web/apps/manage-portal/src/views/Settings.vue web/apps/manage-portal/tests/views/Settings.spec.ts
git commit -m "feat(manage-portal): Settings view wired to real /admin/settings endpoint"
```

---

## Batch G — Gateway cert warning pill (frontend side of Item 2)

### Task G1: gatewayHealth store + api-client method

**Files:**
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/src/index.ts`
- Modify: `web/packages/api-client/tests/manageServer.test.ts`
- Create: `web/apps/manage-portal/src/stores/gatewayHealth.ts`

- [ ] **Step 1: Append type**:

```ts
export interface GatewayHealthResponse {
  ca_bootstrapped: boolean;
  listener_state: 'pending_setup' | 'retry_loop' | 'up' | 'failed';
  cert_expires_at: string | null;
  cert_days_remaining: number;
}
```

- [ ] **Step 2: Append method**:

```ts
    getGatewayHealth: () => http.get<GatewayHealthResponse>('/v1/admin/gateway-health'),
```

- [ ] **Step 3: Re-export + test** mirroring the pattern from E2/F2.

- [ ] **Step 4: Create store**:

```ts
// web/apps/manage-portal/src/stores/gatewayHealth.ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { GatewayHealthResponse } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useGatewayHealthStore = defineStore('gatewayHealth', () => {
  const state = ref<GatewayHealthResponse | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    loading.value = true;
    try {
      state.value = await useApiClient().get().getGatewayHealth();
    } catch {
      // Non-fatal — the pill just hides.
    } finally {
      loading.value = false;
    }
  }

  function startPolling() {
    if (pollHandle !== null) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 60_000);
  }

  function stopPolling() {
    if (pollHandle !== null) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  }

  return { state, loading, fetch, startPolling, stopPolling };
});
```

- [ ] **Step 5: Run tests + commit**

```bash
cd web && pnpm --filter @triton/api-client test && pnpm --filter manage-portal build
cd ..
git add web/packages/api-client/ web/apps/manage-portal/src/stores/gatewayHealth.ts
git commit -m "feat(manage-portal): gatewayHealth store + api-client method"
```

### Task G2: Wire cert warning pill in App.vue

**Files:**
- Modify: `web/apps/manage-portal/src/App.vue`
- Modify: `web/apps/manage-portal/tests/views/` (or a new `tests/app.spec.ts`)

- [ ] **Step 1: Inside App.vue's `<script setup>`**, after the existing store imports:

```ts
import { useGatewayHealthStore } from './stores/gatewayHealth';

const gatewayHealth = useGatewayHealthStore();

// Start polling when mounted. Since App.vue mounts once per session,
// this lives as long as the tab is open.
onMounted(() => gatewayHealth.startPolling());
onBeforeUnmount(() => gatewayHealth.stopPolling());

const gatewayCertWarn = computed(() => {
  const s = gatewayHealth.state;
  return !!s && s.cert_days_remaining > 0 && s.cert_days_remaining < 14;
});
```

Add missing imports (`computed`, `onMounted`, `onBeforeUnmount`).

- [ ] **Step 2: Add pill to the topbar** — find the `<div class="top-right">` block. Before the Change-password button, add:

```vue
<TPill
  v-if="gatewayCertWarn"
  variant="warn"
  :title="'Restart triton-manageserver within this window to mint a fresh 90-day cert.'"
>
  Gateway cert expires in {{ gatewayHealth.state?.cert_days_remaining }}d
</TPill>
```

Add `TPill` to the `@triton/ui` import at the top if not already imported.

- [ ] **Step 3: Write a test for the pill** in `tests/views/AppGatewayPill.spec.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import App from '../../src/App.vue';
import { createRouter, createMemoryHistory } from 'vue-router';

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/dashboard', component: { template: '<div>d</div>' } }],
  });
}

// Stub TAuthGate so the test bypasses auth rendering.
const authGateStub = { template: '<slot />' };

describe('App.vue gateway cert pill', () => {
  it('hides when cert_days_remaining >= 14', () => {
    const pinia = createTestingPinia({ createSpy: vi.fn, initialState: {
      auth: { token: 'valid' }, // mocked — real behaviour via TAuthGate stub
      gatewayHealth: { state: { ca_bootstrapped: true, listener_state: 'up', cert_expires_at: '', cert_days_remaining: 45 } },
    }});
    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: { TAuthGate: authGateStub, TAppShell: true, TSidebar: true, TCrumbBar: true, TAppSwitcher: true, TThemeToggle: true, TUserMenu: true, TToastHost: true, TButton: true, TPill: { template: '<span class="pill-stub">{{ $slots.default?.()?.[0]?.children }}</span>' } },
      },
    });
    expect(w.html()).not.toContain('pill-stub');
  });

  it('shows when cert_days_remaining < 14', () => {
    const pinia = createTestingPinia({ createSpy: vi.fn, initialState: {
      auth: { token: 'valid' },
      gatewayHealth: { state: { ca_bootstrapped: true, listener_state: 'up', cert_expires_at: '', cert_days_remaining: 7 } },
    }});
    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: { TAuthGate: authGateStub, TAppShell: true, TSidebar: true, TCrumbBar: true, TAppSwitcher: true, TThemeToggle: true, TUserMenu: true, TToastHost: true, TButton: true, TPill: { template: '<span class="pill-stub">7d</span>' } },
      },
    });
    expect(w.html()).toContain('pill-stub');
  });
});
```

If the TPill stub rendering turns out to be too fragile, fall back to asserting the computed `gatewayCertWarn` value via `exposed` refs on App.vue. Keep it simple.

- [ ] **Step 4: Run + commit**

```bash
cd web && pnpm --filter manage-portal test && pnpm --filter manage-portal build
cd ..
git add web/apps/manage-portal/src/App.vue web/apps/manage-portal/tests/views/AppGatewayPill.spec.ts
git commit -m "feat(manage-portal): topbar pill warns when gateway cert <14 days"
```

---

## Batch H — Sanity + PR

### Task H1: Full sanity sweep

- [ ] **Step 1: Backend**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-hardening
go build ./...
go vet -tags integration ./...
go test -tags integration ./pkg/manageserver/... 2>&1 | tail -10
```

Expected: all clean.

- [ ] **Step 2: Frontend**

```bash
cd web && pnpm install
cd web && pnpm --filter manage-portal test
cd web && pnpm --filter manage-portal build
cd web && pnpm --filter @triton/api-client test
```

Expected: all pass.

- [ ] **Step 3: Lint**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-hardening
golangci-lint run ./... 2>&1 | tail -10
```

Expected: 0 issues.

- [ ] **Step 4: Commit anything found.**

### Task H2: Push + open PR

- [ ] **Step 1: Rebase onto main** (once PR #87 is merged):

```bash
git fetch origin
git rebase origin/main
```

Resolve any trivial conflicts (likely in `App.vue` topbar if #87 touched the same region).

- [ ] **Step 2: Push**

```bash
git push -u origin feat/manage-hardening
```

- [ ] **Step 3: Open PR**

```bash
gh pr create --title "feat(manage): hardening sprint — 6 XS/S items" --body "$(cat <<'EOF'
## Summary

Six small Manage Server hardening items bundled as one cohesive PR (per brainstorm decision 2026-04-21):

1. **HTTPS enforcement on `/setup/license`** — reject `http://` URLs unless `TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER=true`.
2. **`GET /api/v1/admin/gateway-health`** endpoint — reports CA bootstrap state, listener state, cert expiry, days remaining.
3. **Gateway listener self-recovery** — 5s retry loop polls `caStore.Load` until CA exists, then starts listener. No more "restart after setup" footgun.
4. **Zone/host delete cascade warnings** — confirm modals spell out `ON DELETE SET NULL` side effects. Static text (no live-count query).
5. **`GET /api/v1/admin/licence`** endpoint + Licence.vue rewire — real tier, features, limits, last-heartbeat, push failures.
6. **`GET /api/v1/admin/settings`** endpoint + Settings.vue rewire — real runtime config.

Plus topbar cert-warning pill (14-day threshold, 60s poll).

Implements `docs/superpowers/specs/2026-04-21-manage-hardening-design.md`.

## Test plan

- [ ] CI Lint green.
- [ ] CI Unit Test green.
- [ ] CI Integration Test green — new `TestSetupLicense_Rejects*`, `TestGatewayHealth_*`, `TestGatewayRetry_*`, `TestLicence_*`, `TestSettings_*`.
- [ ] CI Web build + test green — new Licence.spec, Settings.spec rewrites + Zones/Hosts warning tests + gateway-health store test + api-client additions.
- [ ] CI Build green.
- [ ] Manual: complete setup → land on operational app → Licence view shows real guard state → Settings view shows live config.
- [ ] Manual: delete a zone that has hosts → confirm modal text references "set zone_id to NULL".
- [ ] Manual: gateway cert pill hidden today (cert minted fresh) — verifiable by forcing a short cert lifetime in a dev build.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Verify CI.** If failures surface, fix in follow-up commits; don't amend merged ancestors.

---

## Self-review

**Spec coverage:**
- §4.1 HTTPS enforcement → Batch A (Task A1).
- §4.2 gateway-health endpoint → Batch B (Tasks B1–B3) + Batch G (frontend pill).
- §4.3 gateway self-recovery → Batch C (Tasks C1–C3).
- §4.4 licence endpoint → Batch E (Tasks E1–E3).
- §4.5 settings endpoint → Batch F (Tasks F1–F3).
- §5.1 cert-warning pill → Batch G.
- §5.2 cascade warnings → Batch D (Tasks D1–D2).
- §5.3 Licence view rewire → Batch E Task E3.
- §5.4 Settings view rewire → Batch F Task F3.
- §7 tests list → covered across all batches.

**Placeholder scan:** no "TBD" / "similar to above" / vague. Every step shows code or exact commands.

**Type consistency:**
- `GatewayHealthResponse` / `LicenceSummary` / `SettingsSummary` names match between Go struct tags and TS types.
- `LimitPair` + `ScansLimitPair` used consistently in backend struct + frontend type + Licence.vue render.
- `gatewayState*` constants defined in server.go, accessed by handler via `listenerStateNames[state]` map.
- `s.scanResultsStore.LoadLicenseState` — if the field name differs in the existing Server struct, the implementer will discover + adapt (flagged in Task E1 Step 3).

**Cross-batch dependencies:**
- B3 `TestGatewayHealth_Up` depends on C1's `bootstrapGatewayListener` helper. Order: B1 → B2 → B3-partial (pending-setup only) → C1 → C2 → C3 → back to B3-remaining (the Up test). Plan notes this explicitly.
- E1 `TestLicence_Inactive` uses `SetLicenceGuardForTest` which lives in the `testing_gateway.go` file created in Task B3.

**PR size:** ~7 backend tasks + ~7 frontend tasks = 14 commits + 2 sanity/PR tasks = 16 total. Each task ≤ 1 commit. Bundle ships as one PR.
