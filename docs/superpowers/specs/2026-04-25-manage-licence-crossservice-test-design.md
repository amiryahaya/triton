# Manage ↔ License Portal Cross-Service Licence Lifecycle Tests

## Goal

Add integration tests that wire a real `pkg/licenseserver` against a real `pkg/manageserver` (running via `Run()`) over real TCP, validating all four licence lifecycle paths: refresh, replace-key, deactivate-immediate, and deactivate-queued. These tests replace the stub-backed cross-service paths in `manage_licence_lifecycle_test.go` where `lcStubLicenseServer` always returns success regardless of the License Portal's actual state.

**Tech Stack:** Go integration tests (`//go:build integration`), `pkg/licenseserver`, `pkg/manageserver`, `pkg/managestore`, `pkg/licensestore`, `net/http/httptest`

---

## Section 1: Infrastructure Changes

Three small changes to production code to enable real-port testing and configurable watcher timing.

### 1.1 `pkg/manageserver/server.go` — split `Run()` into `Run()` + `RunOnListener()`

```go
// Run creates a TCP listener on cfg.Listen then delegates to RunOnListener.
func (s *Server) Run(ctx context.Context) error {
    ln, err := net.Listen("tcp", s.cfg.Listen)
    if err != nil {
        return fmt.Errorf("manage server: listen %s: %w", s.cfg.Listen, err)
    }
    return s.RunOnListener(ctx, ln)
}

// RunOnListener runs the server on an already-bound listener.
// Tests call this after pre-creating a :0 listener to know the URL upfront.
func (s *Server) RunOnListener(ctx context.Context, ln net.Listener) error {
    s.runCtx = ctx
    // ... all existing Run() body, but s.http.Serve(ln) instead of ListenAndServe()
}
```

All existing callers (`cmd/manageserver/main.go`) continue to call `Run()` unchanged. `RunOnListener` is the new entry point for tests.

### 1.2 `pkg/manageserver/config.go` — add `WatcherTickInterval`

```go
// WatcherTickInterval is the polling interval for the deactivation watcher.
// Zero defaults to 10s. Tests set this to a short value (e.g. 100ms) so the
// queued-deactivation scenario completes quickly.
WatcherTickInterval time.Duration
```

### 1.3 `pkg/manageserver/licence_watcher.go` — use config interval

Replace hardcoded `time.NewTicker(10 * time.Second)` with:

```go
interval := s.cfg.WatcherTickInterval
if interval == 0 {
    interval = 10 * time.Second
}
ticker := time.NewTicker(interval)
```

---

## Section 2: Test File

**File:** `test/integration/manage_licence_crossservice_test.go`
**Build tag:** `//go:build integration`

### 2.1 Fixture struct

```go
type csFixture struct {
    // License Portal
    LSServer   *httptest.Server
    LSAdminURL string
    LSAdminKey string
    LSPub      ed25519.PublicKey
    OrgID      string
    LicIDA     string // initial license (Pro, 5 seats)
    LicIDB     string // second license (Enterprise, 2 seats) — for replace-key test

    // Manage Server
    ManageSrv   *manageserver.Server
    ManageURL   string
    ManageStore *managestore.PostgresStore
    AdminJWT    string
    InstanceID  string // from manage_setup after setup completes
}
```

### 2.2 `newCSFixture(t *testing.T) *csFixture`

**License Portal side:**

1. `licensestore.NewPostgresStore(ctx, testDBURL())` then `store.TruncateAll(ctx)`
2. `pub, priv, _ := ed25519.GenerateKey(rand.Reader)`
3. `licenseserver.New(licenseserver.Config{AdminKeys: []string{"cs-test-key"}, SigningKey: priv, PublicKey: pub, ListenAddr: ":0"}, lsStore)`
4. `httptest.NewServer(lsSrv.Router())` → `lsURL`; `t.Cleanup(lsSrv.Close)`
5. `POST {lsURL}/api/v1/admin/orgs {"name": "CS Test Org"}` → `orgID`
6. `POST {lsURL}/api/v1/admin/licenses {"orgID": orgID, "tier": "pro", "seats": 5, "days": 365}` → `licIDA`
7. `POST {lsURL}/api/v1/admin/licenses {"orgID": orgID, "tier": "enterprise", "seats": 2, "days": 365}` → `licIDB`

**Manage Server side:**

8. Schema name: `fmt.Sprintf("cs_%s", strings.ReplaceAll(uuid.NewString(), "-", "")[:12])`
9. `managestore.NewPostgresStoreInSchema(ctx, testDBURL(), schema)` → `store`
10. `manageserver.Config{PublicKey: lsPub, WatcherTickInterval: 100 * time.Millisecond, GatewayListen: "127.0.0.1:0", GatewayHostname: "127.0.0.1", JWTSigningKey: csJWTKey, SessionTTL: time.Hour}`
11. `manageserver.New(cfg, store, store.Pool())` → `srv`
12. `ln, _ := net.Listen("tcp", "127.0.0.1:0")` → `manageURL = "http://" + ln.Addr().String()`
13. `ctx, cancel := context.WithCancel(context.Background())`; `t.Cleanup(cancel)`
14. `go srv.RunOnListener(ctx, ln)` — `runCtx` is set, boot-time goroutines start (scanner pipeline, gateway retry loop, watcher resume if needed)
15. `csWaitReady(t, manageURL)` — polls `GET {manageURL}/api/v1/health` until 200 or 5s timeout
16. `csAdminReq(t, f, "POST", "/api/v1/setup/admin", map[string]string{"username": "admin", "password": "Test1234!"})` → 201
17. `csAdminReq(t, f, "POST", "/api/v1/setup/license", map[string]string{"license_server_url": lsURL, "license_key": licIDA})` → 200; **this is the first real cross-service call**
18. `csAdminReq(t, f, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "Test1234!"})` → adminJWT
19. `store.GetSetup(ctx)` → `instanceID`

### 2.3 Helper functions

```go
// csAdminReq sends a JSON request to the Manage Server; uses adminJWT when set.
func csAdminReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response

// csLSAdminReq sends an admin-keyed request to the License Portal.
func csLSAdminReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response

// csWaitReady polls until the manage server responds or times out.
func csWaitReady(t *testing.T, baseURL string)

// csActivationsForLicense calls GET {lsURL}/api/v1/admin/activations?license={licID}
// with the admin key and returns the decoded activation list.
func csActivationsForLicense(t *testing.T, f *csFixture, licID string) []map[string]any
```

---

## Section 3: Test Scenarios

### `TestCSLicence_Refresh`

```
1. Note current signed_token via store.GetSetup()
2. POST /api/v1/admin/licence/refresh → assert 200, body {"ok": true}
3. store.GetSetup() → new signed_token differs from step 1
4. GET /api/v1/admin/licence → 200 (guard live)
5. csActivationsForLicense(licIDA) → at least 1 activation with deactivated_at null
```

Verifies: the Manage Server calls the real License Portal `Activate` endpoint on refresh, stores the new token, and keeps the guard live.

---

### `TestCSLicence_ReplaceKey`

```
1. POST /api/v1/admin/licence/replace {"license_key": licIDB} → assert 200, body {"ok": true}
2. store.GetSetup() → LicenseKey == licIDB
3. csActivationsForLicense(licIDB) → has active activation (deactivated_at null)
4. csActivationsForLicense(licIDA) → still active (replace does NOT deactivate old key per spec)
5. GET /api/v1/admin/licence → 200
```

Verifies: the real License Portal records the new activation for License B; the old License A seat is intentionally left active (orphan, admin cleans up via License Portal).

---

### `TestCSLicence_Deactivate_Immediate`

```
1. (No scan jobs in DB)
2. POST /api/v1/admin/licence/deactivate → assert 200 (immediate path)
3. csActivationsForLicense(licIDA) → activation has deactivated_at non-null
4. GET /api/v1/admin/licence → 503 {"setup_required": true}
5. store.GetSetup() → LicenseActivated == false, LicenseKey == "", SignedToken == ""
```

Verifies: `deactivateNow` calls the real License Portal `Deactivate` endpoint; local state is cleared; server re-enters setup mode.

---

### `TestCSLicence_Deactivate_Queued`

```
1. Direct INSERT into manage_scan_jobs: status='running', tenant_id=instanceID
   pool.Exec(ctx, "INSERT INTO manage_scan_jobs (id, tenant_id, status, created_at, updated_at)
                    VALUES ($1, $2, 'running', now(), now())", uuid.New(), instanceID)
2. POST /api/v1/admin/licence/deactivate → assert 202 {"pending": true, "active_scans": 1}
3. GET /api/v1/admin/licence → 200, pending_deactivation: true (watcher not fired yet)
4. csActivationsForLicense(licIDA) → still active (watcher hasn't fired)
5. Direct UPDATE: SET status='done' WHERE id=...
6. time.Sleep(400ms) // 4× WatcherTickInterval of 100ms
7. csActivationsForLicense(licIDA) → deactivated_at non-null (watcher called real Deactivate)
8. GET /api/v1/admin/licence → 503 {"setup_required": true}
```

Verifies: the deactivation watcher (running under real `runCtx`) fires against the real License Portal once active scan count drops to zero.

---

## Section 4: What This Does NOT Cover

- **Boot-time watcher resume** (server restarts with `pending_deactivation=true` already in DB) — the `RunOnListener` path calls `Run()`'s goroutine-start sequence including the resume check, but a dedicated test for crash-restart would require stopping and re-creating the server. Out of scope here; covered by existing unit test `TestDeactivationWatcher_FiresOnZeroScans`.
- **Usage pusher calls** to License Portal — the pusher starts during fixture setup but its calls are not asserted in these tests.
- **License Portal returning 422** on a bad key — covered by the existing stub-based `TestHandleLicenceRefresh_RemoteError`.
- **Replace-key tier change reflected in guard** — covered by stub-based `TestManageLicence_ReplaceKey`.

---

## Section 5: Database Isolation

- License Portal uses `licensestore.TruncateAll(ctx)` at fixture start — clears `organizations`, `licenses`, `activations`, `audit_log`.
- Manage Server uses `managestore.NewPostgresStoreInSchema` with a random schema name — fully isolated from other manage tests running in parallel.
- Both use `testDBURL()` (same `triton_test` DB) — the table name spaces don't overlap (`manage_*` tables live in the schema, license tables live in `public`).
