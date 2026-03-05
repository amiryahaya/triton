//go:build integration

package licenseserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

var serverTestSeq atomic.Int64

func setupTestServer(t *testing.T) (*httptest.Server, *licensestore.PostgresStore) {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_server_%d", serverTestSeq.Add(1))
	store, err := licensestore.NewPostgresStoreInSchema(ctx, dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		AdminKeys:   []string{"test-admin-key"},
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: t.TempDir(),
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	t.Cleanup(func() {
		ts.Close()
		_ = store.DropSchema(ctx)
		store.Close()
	})
	return ts, store
}

func adminReq(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-Admin-Key", "test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func clientReq(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// --- Health ---

func TestHealth(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Admin Auth ---

func TestAdminAuth_MissingKey(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/admin/orgs")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAdminAuth_InvalidKey(t *testing.T) {
	ts, _ := setupTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/orgs", nil)
	req.Header.Set("X-Triton-Admin-Key", "wrong-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// --- Org CRUD ---

func TestCreateOrg(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "Acme Corp", "contact": "admin@acme.com",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "Acme Corp", result["name"])
	assert.NotEmpty(t, result["id"])
}

func TestCreateOrg_MissingName(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestListOrgs(t *testing.T) {
	ts, _ := setupTestServer(t)
	adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "Org1"}).Body.Close()
	adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "Org2"}).Body.Close()

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var orgs []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgs))
	assert.Len(t, orgs, 2)
}

func TestDeleteOrg_WithLicenses(t *testing.T) {
	ts, _ := setupTestServer(t)

	// Create org
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "CantDelete"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)
	orgID := orgResult["id"].(string)

	// Create license
	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 5,
	}).Body.Close()

	// Delete should fail
	resp := adminReq(t, "DELETE", ts.URL+"/api/v1/admin/orgs/"+orgID, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// --- License CRUD ---

func TestCreateLicense(t *testing.T) {
	ts, _ := setupTestServer(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "TestOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)
	orgID := orgResult["id"].(string)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 10, "days": 90,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "enterprise", result["tier"])
	assert.Equal(t, float64(10), result["seats"])
}

func TestCreateLicense_InvalidTier(t *testing.T) {
	ts, _ := setupTestServer(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "BadTierOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "invalid", "seats": 5,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRevokeLicense(t *testing.T) {
	ts, _ := setupTestServer(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "RevokeOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 5,
	})
	defer licResp.Body.Close()
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", map[string]string{
		"reason": "testing",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Activation Flow ---

func createOrgAndLicense(t *testing.T, tsURL string) (orgID, licID string) {
	t.Helper()
	orgResp := adminReq(t, "POST", tsURL+"/api/v1/admin/orgs", map[string]string{"name": "ActivOrg" + t.Name()})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)
	orgID = orgResult["id"].(string)

	licResp := adminReq(t, "POST", tsURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 3,
	})
	defer licResp.Body.Close()
	licResult := decodeJSON(t, licResp)
	licID = licResult["id"].(string)
	return
}

func TestActivate(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-abc", "hostname": "host1", "os": "linux", "arch": "amd64",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.NotEmpty(t, result["token"])
	assert.Equal(t, "pro", result["tier"])
	assert.Equal(t, float64(3), result["seats"])
	assert.Equal(t, float64(1), result["seatsUsed"])
}

func TestActivate_SeatsFull(t *testing.T) {
	ts, _ := setupTestServer(t)

	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "SmallOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)

	licResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 1,
	})
	defer licResp.Body.Close()
	licResult := decodeJSON(t, licResp)
	licID := licResult["id"].(string)

	// First activation OK
	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	// Second should fail
	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m2",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestActivate_RevokedLicense(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDeactivate(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/deactivate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestValidate_Active(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer actResp.Body.Close()
	actResult := decodeJSON(t, actResp)
	token := actResult["token"].(string)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1", "token": token,
	})
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, true, result["valid"])
	assert.Equal(t, "pro", result["tier"])
}

func TestValidate_AfterRevoke(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer actResp.Body.Close()
	actResult := decodeJSON(t, actResp)
	token := actResult["token"].(string)

	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1", "token": token,
	})
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "validation failed", result["reason"])
}

func TestValidate_WrongToken(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1", "token": "wrong-token-value",
	})
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "validation failed", result["reason"])
}

func TestValidate_MissingToken(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "validation failed", result["reason"])
}

// --- Audit ---

func TestAuditEntries(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/audit?limit=10", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var entries []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&entries))
	// Should have at least: org_create, license_create, activate
	assert.GreaterOrEqual(t, len(entries), 3)
}

// --- Stats ---

func TestDashboardStats(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/stats", nil)
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, float64(1), result["totalOrgs"])
	assert.Equal(t, float64(1), result["totalLicenses"])
	assert.Equal(t, float64(1), result["activeSeats"])
}

// --- License Detail ---

func TestGetLicenseDetail(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1", "hostname": "h1",
	}).Body.Close()

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/licenses/"+licID, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	acts := result["activations"].([]any)
	assert.Len(t, acts, 1)
}

// --- Reactivation ---

func TestReactivation(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	// Activate
	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	// Deactivate
	clientReq(t, "POST", ts.URL+"/api/v1/license/deactivate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	// Re-activate
	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.NotEmpty(t, result["token"])
}

// --- Org CRUD (additional) ---

func TestGetOrg(t *testing.T) {
	ts, _ := setupTestServer(t)
	createResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "GetMeOrg", "contact": "get@me.org",
	})
	defer createResp.Body.Close()
	orgResult := decodeJSON(t, createResp)
	orgID := orgResult["id"].(string)

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs/"+orgID, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "GetMeOrg", result["name"])
	assert.Equal(t, "get@me.org", result["contact"])
}

func TestGetOrg_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs/nonexistent-id", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestCreateOrg_DuplicateName(t *testing.T) {
	ts, _ := setupTestServer(t)
	adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "UniqueOrg",
	}).Body.Close()

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "UniqueOrg",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestUpdateOrg(t *testing.T) {
	ts, _ := setupTestServer(t)
	createResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "OriginalName",
	})
	defer createResp.Body.Close()
	orgResult := decodeJSON(t, createResp)
	orgID := orgResult["id"].(string)

	resp := adminReq(t, "PUT", ts.URL+"/api/v1/admin/orgs/"+orgID, map[string]string{
		"name": "UpdatedName", "contact": "new@contact.com",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "UpdatedName", result["name"])
	assert.NotEmpty(t, result["createdAt"])
}

// --- License CRUD (additional) ---

func TestCreateLicense_NegativeDays(t *testing.T) {
	ts, _ := setupTestServer(t)
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "NegDayOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 5, "days": -30,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateLicense_PastExpiresAt(t *testing.T) {
	ts, _ := setupTestServer(t)
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "PastExpOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 5,
		"expiresAt": "2020-01-01T00:00:00Z",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRevokeLicense_AlreadyRevoked(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	// First revoke
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Second revoke should return conflict
	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// --- Admin Deactivation ---

func TestAdminDeactivate(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	// Activate
	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "admin-deact-m1",
	})
	defer actResp.Body.Close()
	actResult := decodeJSON(t, actResp)
	actID := actResult["activationID"].(string)

	// Admin deactivate
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/activations/"+actID+"/deactivate", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "deactivated", result["status"])
}

func TestAdminDeactivate_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/activations/nonexistent/deactivate", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Auth edge case ---

func TestAdminAuth_EmptyKeys(t *testing.T) {
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_server_%d", serverTestSeq.Add(1))
	store, err := licensestore.NewPostgresStoreInSchema(ctx, dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(ctx)
		store.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Empty AdminKeys — should deny all admin requests
	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		AdminKeys:   []string{},
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: t.TempDir(),
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Even with a key header, should be denied when server has empty keys
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/orgs", nil)
	req.Header.Set("X-Triton-Admin-Key", "any-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// --- Binary Management ---

func uploadBinary(t *testing.T, tsURL, version, goos, goarch string, content []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("version", version)
	_ = w.WriteField("os", goos)
	_ = w.WriteField("arch", goarch)
	fw, err := w.CreateFormFile("file", "triton")
	require.NoError(t, err)
	_, err = fw.Write(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	req, err := http.NewRequest("POST", tsURL+"/api/v1/admin/binaries", &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Triton-Admin-Key", "test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestUploadBinary(t *testing.T) {
	ts, _ := setupTestServer(t)
	content := []byte("fake-binary-content")
	resp := uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", content)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "1.0.0", result["version"])
	assert.Equal(t, "linux", result["os"])
	assert.Equal(t, "amd64", result["arch"])
	assert.NotEmpty(t, result["sha3"])
	assert.Equal(t, float64(len(content)), result["size"])
}

func TestUploadBinary_MissingFields(t *testing.T) {
	ts, _ := setupTestServer(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("version", "1.0.0")
	// Missing os, arch, file
	require.NoError(t, w.Close())

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/admin/binaries", &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Triton-Admin-Key", "test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUploadBinary_NoAuth(t *testing.T) {
	ts, _ := setupTestServer(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	require.NoError(t, w.Close())

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/admin/binaries", &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestListBinaries(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin1")).Body.Close()
	uploadBinary(t, ts.URL, "1.0.0", "darwin", "arm64", []byte("bin2")).Body.Close()

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/binaries", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var binaries []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&binaries))
	assert.Len(t, binaries, 2)
}

func TestDeleteBinary(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()

	resp := adminReq(t, "DELETE", ts.URL+"/api/v1/admin/binaries/1.0.0/linux/amd64", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify deleted
	listResp := adminReq(t, "GET", ts.URL+"/api/v1/admin/binaries", nil)
	defer listResp.Body.Close()
	var binaries []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&binaries))
	assert.Len(t, binaries, 0)
}

func TestDeleteBinary_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "DELETE", ts.URL+"/api/v1/admin/binaries/9.9.9/linux/amd64", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestLatestVersion(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("v1")).Body.Close()
	uploadBinary(t, ts.URL, "2.0.0", "linux", "amd64", []byte("v2")).Body.Close()
	uploadBinary(t, ts.URL, "2.0.0", "darwin", "arm64", []byte("v2d")).Body.Close()

	resp, err := http.Get(ts.URL + "/api/v1/license/download/latest-version")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "2.0.0", result["version"])
	platforms := result["platforms"].([]any)
	assert.Len(t, platforms, 2)
}

func TestLatestVersion_Empty(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/license/download/latest-version")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDownloadBinary_ValidLicense(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)
	binaryContent := []byte("\x7fELF\x02\x01\x01\x00binary-content") // ELF-like header to avoid text sniffing
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", binaryContent).Body.Close()

	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/1.0.0/linux/amd64?license_id=%s", ts.URL, licID))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Content-Disposition"), "triton")
	assert.NotEmpty(t, resp.Header.Get("X-Checksum-SHA3-256"))
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, binaryContent, body)
}

func TestDownloadBinary_MissingLicense(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()

	resp, err := http.Get(ts.URL + "/api/v1/license/download/1.0.0/linux/amd64")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDownloadBinary_InvalidLicense(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()

	resp, err := http.Get(ts.URL + "/api/v1/license/download/1.0.0/linux/amd64?license_id=nonexistent")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDownloadBinary_RevokedLicense(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()

	// Revoke the license
	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil).Body.Close()

	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/1.0.0/linux/amd64?license_id=%s", ts.URL, licID))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDownloadBinary_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)

	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/9.9.9/linux/amd64?license_id=%s", ts.URL, licID))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDownloadBinary_AuditTrail(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()

	// Download
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/1.0.0/linux/amd64?license_id=%s", ts.URL, licID))
	require.NoError(t, err)
	resp.Body.Close()

	// Check audit trail
	auditResp := adminReq(t, "GET", ts.URL+"/api/v1/admin/audit?event=binary_download&limit=10", nil)
	defer auditResp.Body.Close()
	var entries []map[string]any
	require.NoError(t, json.NewDecoder(auditResp.Body).Decode(&entries))
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestUploadBinary_PathTraversal(t *testing.T) {
	ts, _ := setupTestServer(t)
	tests := []struct {
		version, os, arch string
	}{
		{"../evil", "linux", "amd64"},
		{"1.0.0", "../../etc", "amd64"},
		{"1.0.0", "linux", ".."},
		{"v1/../../etc", "linux", "amd64"},
	}
	for _, tc := range tests {
		resp := uploadBinary(t, ts.URL, tc.version, tc.os, tc.arch, []byte("x"))
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected 400 for %s/%s/%s", tc.version, tc.os, tc.arch)
	}
}

func TestUploadBinary_InvalidOS(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := uploadBinary(t, ts.URL, "1.0.0", "freebsd", "amd64", []byte("x"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUploadBinary_InvalidArch(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := uploadBinary(t, ts.URL, "1.0.0", "linux", "mips", []byte("x"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUploadBinary_Overwrite(t *testing.T) {
	ts, _ := setupTestServer(t)
	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("original")).Body.Close()

	// Upload same version/os/arch with different content — should succeed (overwrite).
	resp := uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("updated"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, float64(len("updated")), result["size"])
}

func TestUploadBinary_WindowsFilename(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := uploadBinary(t, ts.URL, "1.0.0", "windows", "amd64", []byte("winbin"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "triton.exe", result["filename"])
}

func TestDownloadBinary_ExpiredLicense(t *testing.T) {
	ts, store := setupTestServer(t)
	ctx := context.Background()

	// Create org via API.
	orgResp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "ExpiredOrg"})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)
	orgID := orgResult["id"].(string)

	// Create an already-expired license directly via store (bypasses API validation).
	expiredLic := &licensestore.LicenseRecord{
		ID:        "expired-lic-id",
		OrgID:     orgID,
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // expired yesterday
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	require.NoError(t, store.CreateLicense(ctx, expiredLic))

	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/1.0.0/linux/amd64?license_id=expired-lic-id", ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "license has expired")
}

func TestLatestVersion_SemverOrdering(t *testing.T) {
	ts, _ := setupTestServer(t)
	// Upload versions where lexicographic sort gives wrong answer.
	uploadBinary(t, ts.URL, "1.9.0", "linux", "amd64", []byte("v190")).Body.Close()
	uploadBinary(t, ts.URL, "1.10.0", "linux", "amd64", []byte("v1100")).Body.Close()
	uploadBinary(t, ts.URL, "2.0.0", "linux", "amd64", []byte("v200")).Body.Close()

	resp, err := http.Get(ts.URL + "/api/v1/license/download/latest-version")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "2.0.0", result["version"])
}

func TestLatestVersion_SemverMultiDigit(t *testing.T) {
	ts, _ := setupTestServer(t)
	// 1.10.0 should be later than 1.9.0 (numeric, not lexicographic).
	uploadBinary(t, ts.URL, "1.9.0", "linux", "amd64", []byte("v190")).Body.Close()
	uploadBinary(t, ts.URL, "1.10.0", "linux", "amd64", []byte("v1100")).Body.Close()

	resp, err := http.Get(ts.URL + "/api/v1/license/download/latest-version")
	require.NoError(t, err)
	defer resp.Body.Close()
	result := decodeJSON(t, resp)
	assert.Equal(t, "1.10.0", result["version"])
}

func TestListBinaries_Empty(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/binaries", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var binaries []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&binaries))
	assert.Len(t, binaries, 0)
}

func TestDownloadPage_Serves(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/download/index.html")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestDownloadPage_Redirect(t *testing.T) {
	ts, _ := setupTestServer(t)
	// Disable redirect following to check the 302.
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/download")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/download/index.html")
}
