package licenseserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

func setupTestServer(t *testing.T) (*httptest.Server, *licensestore.PostgresStore) {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, store.TruncateAll(ctx))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cfg := &licenseserver.Config{
		ListenAddr: ":0",
		AdminKeys:  []string{"test-admin-key"},
		SigningKey:  priv,
		PublicKey:   pub,
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	t.Cleanup(func() {
		ts.Close()
		_ = store.TruncateAll(ctx)
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
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "CantDelete"})
	orgResult := decodeJSON(t, resp)
	orgID := orgResult["id"].(string)

	// Create license
	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 5,
	}).Body.Close()

	// Delete should fail
	resp = adminReq(t, "DELETE", ts.URL+"/api/v1/admin/orgs/"+orgID, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// --- License CRUD ---

func TestCreateLicense(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "TestOrg"})
	orgResult := decodeJSON(t, resp)
	orgID := orgResult["id"].(string)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
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

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "BadTierOrg"})
	orgResult := decodeJSON(t, resp)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "invalid", "seats": 5,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRevokeLicense(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "RevokeOrg"})
	orgResult := decodeJSON(t, resp)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 5,
	})
	licResult := decodeJSON(t, resp)
	licID := licResult["id"].(string)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", map[string]string{
		"reason": "testing",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Activation Flow ---

func createOrgAndLicense(t *testing.T, tsURL string) (orgID, licID string) {
	t.Helper()
	resp := adminReq(t, "POST", tsURL+"/api/v1/admin/orgs", map[string]string{"name": "ActivOrg" + t.Name()})
	orgResult := decodeJSON(t, resp)
	orgID = orgResult["id"].(string)

	resp = adminReq(t, "POST", tsURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 3,
	})
	licResult := decodeJSON(t, resp)
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

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "SmallOrg"})
	orgResult := decodeJSON(t, resp)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 1,
	})
	licResult := decodeJSON(t, resp)
	licID := licResult["id"].(string)

	// First activation OK
	clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	}).Body.Close()

	// Second should fail
	resp = clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
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
	actResult := decodeJSON(t, actResp)
	token := actResult["token"].(string)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1", "token": token,
	})
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
	actResult := decodeJSON(t, actResp)
	token := actResult["token"].(string)

	adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses/"+licID+"/revoke", nil).Body.Close()

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "m1", "token": token,
	})
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "license revoked", result["reason"])
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
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "invalid token", result["reason"])
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
	result := decodeJSON(t, resp)
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, "invalid token", result["reason"])
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
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "GetMeOrg", "contact": "get@me.org",
	})
	orgResult := decodeJSON(t, resp)
	orgID := orgResult["id"].(string)

	resp = adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs/"+orgID, nil)
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
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{
		"name": "OriginalName",
	})
	orgResult := decodeJSON(t, resp)
	orgID := orgResult["id"].(string)

	resp = adminReq(t, "PUT", ts.URL+"/api/v1/admin/orgs/"+orgID, map[string]string{
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
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "NegDayOrg"})
	orgResult := decodeJSON(t, resp)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgResult["id"], "tier": "pro", "seats": 5, "days": -30,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateLicense_PastExpiresAt(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{"name": "PastExpOrg"})
	orgResult := decodeJSON(t, resp)

	resp = adminReq(t, "POST", ts.URL+"/api/v1/admin/licenses", map[string]any{
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
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer store.Close()
	require.NoError(t, store.TruncateAll(ctx))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Empty AdminKeys — should deny all admin requests
	cfg := &licenseserver.Config{
		ListenAddr: ":0",
		AdminKeys:  []string{},
		SigningKey:  priv,
		PublicKey:   pub,
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
