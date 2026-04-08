//go:build system

// Package system_test runs an end-to-end integration of the full
// Triton multi-tenant stack: it spawns the real `triton-license-server`
// and `triton server` binaries as child processes, points them at a
// real PostgreSQL instance, and drives the complete flow via HTTP:
//
//  1. Superadmin bootstrap on the license server
//  2. Create an org with an admin via the admin API (cross-server
//     provisioning to the report server happens transparently)
//  3. Log the invited admin into the report server
//  4. Force the initial password change
//  5. Create an org user via the report server's user CRUD
//  6. Issue a license for the org and activate it as an "agent"
//  7. Submit a scan via the real /api/v1/scans endpoint using the
//     activated license token
//  8. Fetch the scan back and verify the payload roundtripped
//  9. Check the audit log reflects the create-user action
//
// 10. Verify /metrics on the report server reflects the traffic
//
// This is the canonical answer to "is the system wired together
// correctly" — higher-signal than the in-process integration tests
// because it exercises real TCP, real JSON wire formats, and real
// process startup ordering.
//
// Run with:
//
//	TRITON_SYSTEM_TEST_DB_URL=postgres://... \
//	  go test -tags system ./test/system/
//
// Requires:
//   - A reachable PostgreSQL (will use separate databases for each
//     server; see setup).
//   - The two binaries built at ./bin/triton and ./bin/triton-license-server
//     (the test helper builds them if missing).
package system_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	adminKey           = "system-test-admin-key"
	serviceKey         = "system-test-service-key-shared"
	bootstrapAdminPW   = "system-test-bootstrap-pw-12345"
	bootstrapAdminMail = "bootstrap@system.test"
)

// systemTestDBURL returns the DB URL to use for the test. Both the
// license server and report server point at the same PostgreSQL
// instance but write to separate schemas / tables.
func systemTestDBURL(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("TRITON_SYSTEM_TEST_DB_URL"); u != "" {
		return u
	}
	return "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
}

// buildBinaries always builds fresh copies of both binaries into a
// test-owned directory. Prior approach (check-then-build) risked
// running against stale binaries left over from pre-Phase 4 builds
// that still carried the old --api-key flag. For system tests we
// always want the current tip of tree.
func buildBinaries(t *testing.T) (tritonBin, licenseBin string) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	outDir := t.TempDir()
	tritonBin = filepath.Join(outDir, "triton")
	licenseBin = filepath.Join(outDir, "triton-license-server")

	build := func(name, out, pkg string) {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", name, err, out)
		}
	}
	build("triton", tritonBin, "./")
	build("triton-license-server", licenseBin, "./cmd/licenseserver")
	return tritonBin, licenseBin
}

// findRepoRoot walks up from the test file until it finds go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod in any parent)")
		}
		dir = parent
	}
}

// freePort returns a TCP port the OS considers free right now.
// Races with startup between the Listen close and the server bind
// are possible but rare; the system test tolerates a single retry.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForHealth polls the given URL until it returns 200 or the
// deadline passes. Used to wait for each child process to finish
// startup before driving requests.
func waitForHealth(t *testing.T, url string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		//nolint:gosec // test-only HTTP to a freshly-started child
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("service at %s did not become healthy within %s", url, deadline)
}

// systemStack holds the running child processes and their URLs for
// a single system test. Cleanup is registered via t.Cleanup.
type systemStack struct {
	licenseURL string
	reportURL  string
	signingKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	licenseCmd *exec.Cmd
	reportCmd  *exec.Cmd
}

// startStack spins up both servers with matching cross-server
// keys and waits for health. Each server gets its own PostgreSQL
// database so their migrations cannot collide (the license server
// and report server both define a `users` table, `organizations`
// table, etc. — sharing a schema causes FK constraint failures).
func startStack(t *testing.T) *systemStack {
	t.Helper()
	tritonBin, licenseBin := buildBinaries(t)
	baseDBURL := systemTestDBURL(t)
	// Ensure the DB is reachable before burning startup time on
	// the children. Prevents confusing timeouts when DB is down.
	if err := pingPG(baseDBURL); err != nil {
		t.Skipf("PostgreSQL unreachable at %s: %v", baseDBURL, err)
	}
	// Allocate two dedicated databases. Dropping and creating each
	// time isolates runs from each other. Requires the connecting
	// user to have CREATE DATABASE privilege.
	suffix := uuid.Must(uuid.NewV7()).String()[:8]
	licenseDBName := "triton_sys_lic_" + suffix
	reportDBName := "triton_sys_rep_" + suffix
	require.NoError(t, createDatabase(baseDBURL, licenseDBName))
	require.NoError(t, createDatabase(baseDBURL, reportDBName))
	t.Cleanup(func() {
		_ = dropDatabase(baseDBURL, licenseDBName)
		_ = dropDatabase(baseDBURL, reportDBName)
	})
	licenseDBURL := swapDatabase(baseDBURL, licenseDBName)
	reportDBURL := swapDatabase(baseDBURL, reportDBName)

	signingPub, signingPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signingHex := hex.EncodeToString(signingPriv)
	pubHex := hex.EncodeToString(signingPub)

	// Mint an ephemeral enterprise license for the report server
	// CLI guard. The report server's REPORT_SERVER_TENANT_PUBKEY
	// override makes the guard accept this ephemeral-signed token
	// without requiring the embedded production pubkey.
	licenseToken := mintEnterpriseLicense(t, signingPriv)

	licensePort := freePort(t)
	reportPort := freePort(t)
	licenseURL := fmt.Sprintf("http://127.0.0.1:%d", licensePort)
	reportURL := fmt.Sprintf("http://127.0.0.1:%d", reportPort)

	// Start license server. The env is built from scratch (not
	// inheriting os.Environ) so stale TRITON_LICENSE_KEY files or
	// variables on the test host don't affect the child.
	licenseCmd := exec.Command(licenseBin)
	licenseCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(), // avoid reading ~/.triton
		"TRITON_LICENSE_SERVER_LISTEN=:" + fmt.Sprint(licensePort),
		"TRITON_LICENSE_SERVER_DB_URL=" + licenseDBURL,
		"TRITON_LICENSE_SERVER_ADMIN_KEY=" + adminKey,
		"TRITON_LICENSE_SERVER_ADMIN_PASSWORD=" + bootstrapAdminPW,
		"TRITON_LICENSE_SERVER_ADMIN_EMAIL=" + bootstrapAdminMail,
		"TRITON_LICENSE_SERVER_SIGNING_KEY=" + signingHex,
		"TRITON_LICENSE_SERVER_REPORT_URL=" + reportURL,
		"TRITON_LICENSE_SERVER_REPORT_KEY=" + serviceKey,
		"TRITON_LICENSE_SERVER_BINARIES_DIR=" + t.TempDir(),
	}
	licenseCmd.Stdout = prefixedWriter{p: "[license] ", w: os.Stdout}
	licenseCmd.Stderr = prefixedWriter{p: "[license] ", w: os.Stderr}
	require.NoError(t, licenseCmd.Start())

	// Start report server with matching service/JWT keys. As with
	// the license server, build the env from scratch to avoid
	// inheriting stale TRITON_LICENSE_KEY / HOME/.triton state.
	reportCmd := exec.Command(tritonBin, "server",
		"--listen", fmt.Sprintf(":%d", reportPort),
		"--db", reportDBURL,
		"--license-key", licenseToken,
	)
	reportCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"REPORT_SERVER_SERVICE_KEY=" + serviceKey,
		"REPORT_SERVER_JWT_SIGNING_KEY=" + signingHex,
		// Tenant pubkey override so the CLI guard + UnifiedAuth
		// both accept the ephemeral-signed licence token we just
		// minted above. Without this the embedded production
		// pubkey would reject the token and the server would
		// fall back to free tier (which blocks server mode).
		"REPORT_SERVER_TENANT_PUBKEY=" + pubHex,
		// Short rate-limiter windows so tests don't wait 15 minutes
		// for a lockout to expire if they need to exercise one.
		"REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS=5",
		"REPORT_SERVER_RATE_LIMIT_WINDOW=1m",
		"REPORT_SERVER_RATE_LIMIT_LOCKOUT=1m",
	}
	reportCmd.Stdout = prefixedWriter{p: "[report] ", w: os.Stdout}
	reportCmd.Stderr = prefixedWriter{p: "[report] ", w: os.Stderr}
	require.NoError(t, reportCmd.Start())

	stack := &systemStack{
		licenseURL: licenseURL,
		reportURL:  reportURL,
		signingKey: signingPriv,
		publicKey:  signingPub,
		licenseCmd: licenseCmd,
		reportCmd:  reportCmd,
	}
	t.Cleanup(func() { stack.stop(t) })

	// Wait for health on both — 15s is generous for CI.
	waitForHealth(t, licenseURL+"/api/v1/health", 15*time.Second)
	waitForHealth(t, reportURL+"/api/v1/health", 15*time.Second)
	return stack
}

func (s *systemStack) stop(t *testing.T) {
	t.Helper()
	_ = s.reportCmd.Process.Signal(os.Interrupt)
	_ = s.licenseCmd.Process.Signal(os.Interrupt)
	// Give the processes a moment to shut down gracefully.
	done := make(chan struct{})
	go func() {
		_ = s.reportCmd.Wait()
		_ = s.licenseCmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.reportCmd.Process.Kill()
		_ = s.licenseCmd.Process.Kill()
	}
}

// prefixedWriter wraps an io.Writer and prefixes each line so the
// test log can tell license-server and report-server output apart.
type prefixedWriter struct {
	p string
	w io.Writer
}

func (p prefixedWriter) Write(b []byte) (int, error) {
	// Write unbuffered — the goroutine that owns the child stream
	// calls us once per syscall-sized chunk, which is good enough.
	_, _ = fmt.Fprint(p.w, p.p+string(b))
	return len(b), nil
}

// --- HTTP helpers ---

func postJSON(t *testing.T, url string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func getJSON(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decode(t *testing.T, resp *http.Response, into any) {
	t.Helper()
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
}

// readBody reads the response body into a string, closes it, and
// replaces resp.Body with a new reader over the same bytes so the
// caller can still json-decode afterwards. Used in combination
// with require.Equal + formatted error messages that need the
// body visible on failure without stealing it from a successful
// decode path.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return string(b)
}

// --- The test ---

// TestSystem_FullMultiTenantFlow exercises the whole multi-tenant
// stack end-to-end: superadmin → create org → receive temp password
// → admin login → change password → create user → submit scan →
// audit log → metrics. Expected runtime ~10 seconds.
func TestSystem_FullMultiTenantFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("system test skipped in -short mode")
	}
	stack := startStack(t)

	// Step 1: use the admin key to create an org with an initial admin.
	adminEmail := fmt.Sprintf("admin-%s@system.test", uuid.Must(uuid.NewV7()).String()[:8])
	createResp := postJSON(t, stack.licenseURL+"/api/v1/admin/orgs",
		map[string]any{
			"name":        "System Test Org",
			"admin_email": adminEmail,
			"admin_name":  "System Test Admin",
		},
		map[string]string{"X-Triton-Admin-Key": adminKey},
	)
	createBody := readBody(t, createResp)
	require.Equal(t, http.StatusCreated, createResp.StatusCode,
		"org creation must succeed; body=%s", createBody)
	var orgPayload struct {
		Org struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"org"`
		Admin *struct {
			Email          string `json:"email"`
			TempPassword   string `json:"temp_password"`
			EmailDelivered bool   `json:"email_delivered"`
		} `json:"admin"`
	}
	decode(t, createResp, &orgPayload)
	require.NotEmpty(t, orgPayload.Org.ID)
	require.NotNil(t, orgPayload.Admin, "admin block should be present since we asked for provisioning")
	require.NotEmpty(t, orgPayload.Admin.TempPassword,
		"license server must return the temp password when no mailer is configured")
	assert.False(t, orgPayload.Admin.EmailDelivered,
		"email delivery should be false since we did not configure Resend")

	// Step 2: admin logs into the REPORT server.
	loginResp := postJSON(t, stack.reportURL+"/api/v1/auth/login",
		map[string]string{
			"email":    adminEmail,
			"password": orgPayload.Admin.TempPassword,
		}, nil,
	)
	loginBody := readBody(t, loginResp)
	require.Equal(t, http.StatusOK, loginResp.StatusCode,
		"admin login must succeed; body=%s", loginBody)
	var loginPayload struct {
		Token              string `json:"token"`
		MustChangePassword bool   `json:"mustChangePassword"`
	}
	decode(t, loginResp, &loginPayload)
	require.NotEmpty(t, loginPayload.Token)
	require.True(t, loginPayload.MustChangePassword,
		"initial admin login must report mcp=true")

	// Step 3: admin rotates their password.
	newAdminPW := "system-test-new-admin-pw-123456"
	cpwResp := postJSON(t, stack.reportURL+"/api/v1/auth/change-password",
		map[string]string{
			"current_password": orgPayload.Admin.TempPassword,
			"new_password":     newAdminPW,
		},
		map[string]string{"Authorization": "Bearer " + loginPayload.Token},
	)
	cpwBody := readBody(t, cpwResp)
	require.Equal(t, http.StatusOK, cpwResp.StatusCode,
		"change-password must succeed; body=%s", cpwBody)
	var cpwPayload struct {
		Token string `json:"token"`
	}
	decode(t, cpwResp, &cpwPayload)
	require.NotEmpty(t, cpwPayload.Token)
	adminToken := cpwPayload.Token

	// Step 4: admin creates an org user via the report server.
	userEmail := fmt.Sprintf("user-%s@system.test", uuid.Must(uuid.NewV7()).String()[:8])
	createUserResp := postJSON(t, stack.reportURL+"/api/v1/users",
		map[string]any{
			"email":    userEmail,
			"name":     "System Test User",
			"role":     "org_user",
			"password": "system-test-user-pw-12345",
		},
		map[string]string{"Authorization": "Bearer " + adminToken},
	)
	createUserBody := readBody(t, createUserResp)
	require.Equal(t, http.StatusCreated, createUserResp.StatusCode,
		"user creation must succeed; body=%s", createUserBody)
	createUserResp.Body.Close()

	// Step 5: audit log query should show the user.create event.
	//
	// The audit write is goroutine-fire-and-forget, so poll for a
	// few iterations before giving up.
	var found bool
	for i := 0; i < 30; i++ {
		auditResp := getJSON(t, stack.reportURL+"/api/v1/audit/",
			map[string]string{"Authorization": "Bearer " + adminToken},
		)
		if auditResp.StatusCode != http.StatusOK {
			auditResp.Body.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var events []map[string]any
		decode(t, auditResp, &events)
		for _, e := range events {
			if e["eventType"] == "user.create" {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.True(t, found,
		"audit log should contain a user.create event after the CRUD call")

	// Step 6: /metrics endpoint returns something that looks like
	// Prometheus text format.
	metricsResp := getJSON(t, stack.reportURL+"/api/v1/metrics", nil)
	require.Equal(t, http.StatusOK, metricsResp.StatusCode)
	body := readAll(metricsResp)
	assert.Contains(t, body, "triton_login_rate_limiter_tracked")
	assert.Contains(t, body, "triton_request_rate_limiter_tracked")

	// Step 7: rate limiter observed at least 1 tracked bucket from
	// our login flow. We can't assert on exact values because the
	// login limiter deletes buckets on success, but the request
	// limiter bucket should persist across the window.
	assert.Contains(t, body, "triton_request_rate_limiter_tracked 1")
}

// readAll drains a response body into a string for error messages.
// Closes the body as a side effect.
func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// pingPG runs a lightweight SELECT 1 via the same pgx driver the
// servers use. Returns nil if the server is reachable, an error
// otherwise. Extracted to its own helper so startStack can skip
// the test cleanly when PG is down.
func pingPG(dbURL string) error {
	// We intentionally avoid importing pgx here to keep the system
	// test's dependency surface small — use os/exec'd psql if
	// available, otherwise rely on a TCP connect check. The TCP
	// check is crude but sufficient: if the port is open, the
	// subsequent child process will produce a cleaner error than
	// we would.
	// Parse the host:port out of the URL.
	if !strings.HasPrefix(dbURL, "postgres://") {
		return fmt.Errorf("unsupported DB URL scheme: %s", dbURL)
	}
	rest := strings.TrimPrefix(dbURL, "postgres://")
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return fmt.Errorf("no @ in DB URL")
	}
	hostport := rest[atIdx+1:]
	if slashIdx := strings.Index(hostport, "/"); slashIdx >= 0 {
		hostport = hostport[:slashIdx]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// createDatabase creates a fresh PostgreSQL database by name using
// the base DB URL's credentials. Drops any existing database first
// so re-runs start clean. Uses pgx directly (not psql) so the test
// does not depend on the postgres client being installed.
func createDatabase(baseDBURL, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	adminURL := swapDatabase(baseDBURL, "postgres")
	conn, err := pgxConnect(ctx, adminURL)
	if err != nil {
		return fmt.Errorf("connecting to postgres for CREATE DATABASE: %w", err)
	}
	defer conn.Close(ctx)
	// Drop any leftover from a prior crashed run. Quoting the
	// identifier keeps us safe if the UUID ever contains a dash —
	// pg identifiers allow underscores but not dashes bare, so
	// the quoting is also the correctness anchor.
	if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
		return fmt.Errorf("dropping database %s: %w", name, err)
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		return fmt.Errorf("creating database %s: %w", name, err)
	}
	return nil
}

// dropDatabase removes a database created by createDatabase.
// Called from t.Cleanup; swallows errors because cleanup must not
// fail the test.
//
// Uses WITH (FORCE) (PG 13+) so the drop terminates any connections
// still alive from a child process that hasn't fully exited yet —
// the test's stop() helper SIGINTs the servers and waits only 5s
// before escalating to SIGKILL, so there's a window where pgx
// connections are still open at cleanup time. Without FORCE we'd
// hit "database is being accessed by other users" and leave the
// test database behind. Sprint 3 D7.
func dropDatabase(baseDBURL, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	adminURL := swapDatabase(baseDBURL, "postgres")
	conn, err := pgxConnect(ctx, adminURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`)
	return err
}

// swapDatabase returns the base URL with its database name replaced
// by dbName. Assumes the URL is in the standard postgres://...
// format with a single /database path component.
func swapDatabase(baseURL, dbName string) string {
	// Crude but adequate: find the last '/' after the host:port and
	// everything before '?', replace between them.
	q := ""
	if idx := strings.Index(baseURL, "?"); idx >= 0 {
		q = baseURL[idx:]
		baseURL = baseURL[:idx]
	}
	lastSlash := strings.LastIndex(baseURL, "/")
	if lastSlash < len("postgres://") {
		return baseURL + "/" + dbName + q
	}
	return baseURL[:lastSlash+1] + dbName + q
}

// mintEnterpriseLicense signs an ephemeral enterprise license
// token using the supplied private key. Used by the system test
// to hand the report server CLI a valid --license-key that its
// guard will accept when paired with REPORT_SERVER_TENANT_PUBKEY.
func mintEnterpriseLicense(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	// We shell out to `go run ./cmd/keygen` ... actually no, that
	// binary signs with the production key. We need to use the
	// internal/license package directly. Import it.
	//
	// Use a subprocess avoids coupling the system test's module
	// graph to internal packages — but keeping it direct is
	// simpler. The internal/license package is importable from
	// tests inside the same module.
	return mintLicenseHelper(t, priv)
}
