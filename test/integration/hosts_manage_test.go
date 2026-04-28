//go:build integration

// Hosts — Manage Server integration tests.
//
// Covers the hardening changes introduced in the hosts-hardening feature:
//
//  1. Hostname is now mandatory — omitting it returns 400.
//  2. ssh_port defaults to 22 when not supplied.
//  3. ssh_port is persisted when supplied explicitly.
//  4. Migration v19 seeds 13 built-in tags into manage_tags.
//  5. BulkCreate also enforces hostname-required.

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// hostsSchemaSeq allocates unique PG schemas for hosts integration tests.
var hostsSchemaSeq atomic.Int64

// hostsManageServer holds everything needed by a hosts integration test.
type hostsManageServer struct {
	url string // http://127.0.0.1:PORT of httptest.Server
	jwt string // admin Bearer token (already past setup + login)
}

// requireHostsManageServer spins up a Manage Server, completes setup
// (admin + license), logs in, and returns the test harness.
// The server is cleaned up via t.Cleanup.
func requireHostsManageServer(t *testing.T) hostsManageServer {
	t.Helper()

	// Ed25519 keypair for license tokens — same pattern as manage_setup_test.go.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "hosts-int-test-lic",
		Tier:      license.TierPro,
		Org:       "HostsIntegrationTest",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	ls := newManageStubLicenseServer(t, stubLicenseServerConfig{
		signedToken:  signed,
		activationID: fmt.Sprintf("hosts-int-test-activation-%d", hostsSchemaSeq.Load()),
		tier:         "pro",
		features:     licensestore.Features{Manage: true},
	})
	t.Cleanup(ls.Close)

	// Isolated DB schema.
	schema := fmt.Sprintf("test_hosts_int_%d", hostsSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	})

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: manageJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")

	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// Complete setup via API (same pattern as TestManageServerSetupFlow).
	const adminEmail = "hosts-admin@example.com"
	const adminPassword = "testpassword-hosts-42"

	resp := postJSON(t, ts.URL+"/api/v1/setup/admin", map[string]any{
		"email": adminEmail, "name": "Hosts Test Admin", "password": adminPassword,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin failed")

	resp = postJSON(t, ts.URL+"/api/v1/setup/license", map[string]any{
		"license_server_url": ls.URL,
		"license_key":        "hosts-int-test-lic",
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license failed")

	loginResp := postJSON(t, ts.URL+"/api/v1/auth/login", map[string]any{
		"email": adminEmail, "password": adminPassword,
	})
	loginBodyBytes, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login failed: %s", loginBodyBytes)

	var loginBody map[string]any
	require.NoError(t, json.Unmarshal(loginBodyBytes, &loginBody))
	token, _ := loginBody["token"].(string)
	require.NotEmpty(t, token, "login returned no token")

	return hostsManageServer{url: ts.URL, jwt: token}
}

// hostsDo performs an authenticated HTTP request to the manage server.
func hostsDo(t *testing.T, method, url, jwt string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestHosts_HostnameMandatory verifies that creating a host without a hostname
// returns 400. Migration v19 made hostname NOT NULL at the DB level and the
// handler now validates it before reaching the store.
func TestHosts_HostnameMandatory(t *testing.T) {
	h := requireHostsManageServer(t)

	resp := hostsDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts", h.jwt, map[string]any{
		"ip": "10.99.0.1",
		// hostname intentionally omitted
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"missing hostname must return 400, got body: %s", body)
}

// TestHosts_SSHPort_Default verifies that ssh_port is set to 22 when the field
// is omitted from the create request. Migration v19 renamed access_port→ssh_port
// and the handler's toHost() defaults it to 22.
func TestHosts_SSHPort_Default(t *testing.T) {
	h := requireHostsManageServer(t)

	resp := hostsDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts", h.jwt, map[string]any{
		"hostname": "test-host.local",
		"ip":       "10.99.0.2",
		// ssh_port intentionally omitted — should default to 22
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"create host without ssh_port must return 201, got body: %s", body)

	var created map[string]any
	require.NoError(t, json.Unmarshal(body, &created))
	sshPort, _ := created["ssh_port"].(float64) // JSON numbers decode as float64
	assert.Equal(t, float64(22), sshPort, "ssh_port must default to 22 when omitted")
}

// TestHosts_SSHPort_Custom verifies that an explicitly supplied ssh_port is
// persisted and returned in the response. Migration v19 renamed access_port→ssh_port;
// this test confirms the wire field name matches the new column name.
func TestHosts_SSHPort_Custom(t *testing.T) {
	h := requireHostsManageServer(t)

	resp := hostsDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts", h.jwt, map[string]any{
		"hostname": "win-host.local",
		"ip":       "10.99.0.3",
		"ssh_port": 5985,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"create host with custom ssh_port must return 201, got body: %s", body)

	var created map[string]any
	require.NoError(t, json.Unmarshal(body, &created))
	sshPort, _ := created["ssh_port"].(float64)
	assert.Equal(t, float64(5985), sshPort, "ssh_port must be persisted as supplied")
}

// TestHosts_BuiltinTags_Seeded verifies that migration v19 inserted all 13
// built-in tags into manage_tags. Queries the DB directly via store.Pool()
// to confirm each tag exists exactly once.
func TestHosts_BuiltinTags_Seeded(t *testing.T) {
	// Isolated schema + store — no HTTP server needed for this DB-layer test.
	schema := fmt.Sprintf("test_hosts_tags_%d", hostsSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	})

	builtinTags := []string{
		"production", "staging", "development",
		"web", "database",
		"windows", "linux", "unix",
		"server", "laptop", "workstation",
		"critical", "pqc-scope",
	}

	pool := store.Pool()
	for _, tagName := range builtinTags {
		tagName := tagName // capture loop variable
		t.Run(tagName, func(t *testing.T) {
			var count int
			err := pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM manage_tags WHERE name = $1`, tagName,
			).Scan(&count)
			require.NoError(t, err, "query manage_tags for tag %q", tagName)
			assert.Equal(t, 1, count, "built-in tag %q must exist exactly once in manage_tags", tagName)
		})
	}
}

// TestHosts_BulkCreate_HostnameRequired verifies that the bulk-create endpoint
// also enforces hostname-required. A batch containing a host without a hostname
// must return 400.
func TestHosts_BulkCreate_HostnameRequired(t *testing.T) {
	h := requireHostsManageServer(t)

	resp := hostsDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts/bulk", h.jwt, map[string]any{
		"hosts": []map[string]any{
			{"ip": "10.99.0.50"}, // hostname intentionally omitted
		},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"bulk create with missing hostname must return 400, got body: %s", body)
}
