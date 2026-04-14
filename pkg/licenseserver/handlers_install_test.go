//go:build integration

package licenseserver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// --- Install Token Generation ---

func TestHandleInstallToken_Success(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)

	// Create org + license.
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "InstallOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5, "days": 365,
	})
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	// Generate install token.
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/install-token", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.NotEmpty(t, result["token"])
	assert.Equal(t, float64(86400), result["expires_in"])
	assert.Contains(t, result["curl_command"].(string), "curl")
	assert.Contains(t, result["curl_command"].(string), "sudo bash")
	assert.Contains(t, result["ps1_command"].(string), "irm")
	assert.Contains(t, result["ps1_command"].(string), "iex")
}

func TestHandleInstallToken_NoPublicURL(t *testing.T) {
	// setupTestServer does NOT set PublicURL.
	ts, _ := setupTestServer(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "NoURLOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 1, "days": 30,
	})
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/install-token", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleInstallToken_RevokedLicense(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "RevokedOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 1, "days": 30,
	})
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	// Revoke
	revokeResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	revokeResp.Body.Close()

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/install-token", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleInstallToken_NotFound(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)

	// Use a valid UUID format that doesn't exist in the database.
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/00000000-0000-0000-0000-000000000000/install-token", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Install Script ---

func TestHandleInstallScript_Bash(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)
	token := generateInstallToken(t, ts)

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")

	body := readBodyStr(t, resp)
	assert.Contains(t, body, "#!/usr/bin/env bash")
	assert.Contains(t, body, token)
}

func TestHandleInstallScript_Ps1(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)
	token := generateInstallToken(t, ts)

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token + "?shell=ps1")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := readBodyStr(t, resp)
	assert.Contains(t, body, "#Requires -Version 5.1")
	assert.Contains(t, body, token)
}

func TestHandleInstallScript_InvalidToken(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)

	resp, err := http.Get(ts.URL + "/api/v1/install/invalid-token")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Install Binary ---

func TestHandleInstallBinary_Success(t *testing.T) {
	ts, binDir := setupTestServerWithPublicURL(t)
	token := generateInstallToken(t, ts)

	// Seed a fake binary.
	seedBinary(t, binDir, "1.0.0", "linux", "amd64", "fake-triton-binary")

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token + "/binary/linux/amd64")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := readBodyStr(t, resp)
	assert.Equal(t, "fake-triton-binary", body)
}

func TestHandleInstallBinary_NotFound(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)
	token := generateInstallToken(t, ts)

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token + "/binary/linux/arm64")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleInstallBinary_InvalidToken(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)

	resp, err := http.Get(ts.URL + "/api/v1/install/bad-token/binary/linux/amd64")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Install Agent YAML ---

func TestHandleInstallAgentYAML_Success(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)
	token := generateInstallToken(t, ts)

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token + "/agent-yaml")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/x-yaml")

	body := readBodyStr(t, resp)
	assert.Contains(t, body, "license_key:")
	assert.Contains(t, body, "profile:")
}

func TestHandleInstallAgentYAML_RevokedLicense(t *testing.T) {
	ts, _ := setupTestServerWithPublicURL(t)
	token := generateInstallTokenForRevoked(t, ts)

	resp, err := http.Get(ts.URL + "/api/v1/install/" + token + "/agent-yaml")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Helpers ---

// setupTestServerWithPublicURL creates a test server with PublicURL set.
// Returns (ts, binariesDir).
func setupTestServerWithPublicURL(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_install_%d", serverTestSeq.Add(1))

	store, err := licensestore.NewPostgresStoreInSchema(ctx, dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	binDir := t.TempDir()
	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		AdminKeys:   []string{"test-admin-key"},
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: binDir,
		PublicURL:   "https://license.example.com",
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	t.Cleanup(func() {
		ts.Close()
		_ = store.DropSchema(ctx)
		store.Close()
	})
	return ts, binDir
}

// generateInstallToken creates an org+license and generates an install token.
func generateInstallToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "InstallTestOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5, "days": 365,
	})
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	tokenResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/install-token", nil)
	tokenResult := decodeJSON(t, tokenResp)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "expected 200 for install-token generation")
	return tokenResult["token"].(string)
}

// generateInstallTokenForRevoked creates an org+license, generates an
// install token, then revokes the license. The HMAC token is still valid
// but the license is revoked so agent-yaml should fail.
func generateInstallTokenForRevoked(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "RevokeTestOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5, "days": 365,
	})
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	tokenResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/install-token", nil)
	tokenResult := decodeJSON(t, tokenResp)
	token := tokenResult["token"].(string)

	// Now revoke.
	revokeResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	revokeResp.Body.Close()

	return token
}

func readBodyStr(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// seedBinary creates a fake binary with meta.json in the binaries directory.
func seedBinary(t *testing.T, binDir, version, goos, goarch, content string) {
	t.Helper()
	dir := filepath.Join(binDir, version, goos+"-"+goarch)
	require.NoError(t, os.MkdirAll(dir, 0o755))

	filename := "triton"
	if goos == "windows" {
		filename = "triton.exe"
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644))

	meta := fmt.Sprintf(`{"version":%q,"os":%q,"arch":%q,"sha3":"deadbeef","size":%d,"filename":%q,"uploadedAt":"2026-01-01T00:00:00Z"}`,
		version, goos, goarch, len(content), filename)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644))
}
