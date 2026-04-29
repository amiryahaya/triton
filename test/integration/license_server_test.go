//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// licenseTestDBURL returns the PostgreSQL URL for the license store test DB.
// Uses TRITON_LICENSE_TEST_DB_URL if set, otherwise substitutes "triton_test"
// with "triton_license_test" in the standard test URL. The license store has
// its own schema (organizations, licenses, activations, …) that conflicts with
// the main store's organizations table when sharing the same database.
func licenseTestDBURL() string {
	if u := os.Getenv("TRITON_LICENSE_TEST_DB_URL"); u != "" {
		return u
	}
	base := testDBURL()
	return strings.ReplaceAll(base, "/triton_test", "/triton_license_test")
}

// requireLicenseStore creates a PostgresStore for the license server.
func requireLicenseStore(t *testing.T) *licensestore.PostgresStore {
	t.Helper()
	dbURL := licenseTestDBURL()
	ctx := context.Background()
	s, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, s.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = s.TruncateAll(ctx)
		s.Close()
	})
	return s
}

// licAdminTokenCache caches the JWT per httptest server base URL so each
// test only logs in once. Evicted on t.Cleanup in requireLicenseServer.
var licAdminTokenCache sync.Map // baseURL → jwt string
var licAdminCredsMap sync.Map   // baseURL → [2]string{email, password}

// requireLicenseServer creates a real TCP httptest.Server backed by PostgreSQL
// and seeds a platform_admin user for use by licAdminReq.
func requireLicenseServer(t *testing.T) (string, *licensestore.PostgresStore, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	store := requireLicenseStore(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: t.TempDir(),
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	email, password := "inttest-admin@example.com", "IntTestPass123!"
	seedLicenseAdmin(t, store, email, password)
	licAdminCredsMap.Store(ts.URL, [2]string{email, password})
	t.Cleanup(func() {
		licAdminTokenCache.Delete(ts.URL)
		licAdminCredsMap.Delete(ts.URL)
		ts.Close()
	})
	return ts.URL, store, pub, priv
}

// seedLicenseAdmin inserts a platform_admin user directly into the store.
// Uses bcrypt.MinCost to keep integration tests fast.
func seedLicenseAdmin(t *testing.T, store *licensestore.PostgresStore, email, password string) {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	now := time.Now().UTC()
	u := &licensestore.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Email:     email,
		Name:      "Integration Test Admin",
		Role:      "platform_admin",
		Password:  string(hashed),
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, store.CreateUser(context.Background(), u))
}

// licGetJWT returns a cached JWT for the given server base URL, logging in on
// first call.
func licGetJWT(t *testing.T, baseURL string) string {
	t.Helper()
	if v, ok := licAdminTokenCache.Load(baseURL); ok {
		return v.(string)
	}
	v, ok := licAdminCredsMap.Load(baseURL)
	require.True(t, ok, "no admin credentials registered for %s — call requireLicenseServer first", baseURL)
	creds := v.([2]string)
	b, _ := json.Marshal(map[string]string{"email": creds[0], "password": creds[1]})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login must succeed for integration test admin")
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	token, ok := result["token"].(string)
	require.True(t, ok, "login response must contain token string")
	licAdminTokenCache.Store(baseURL, token)
	return token
}

// licAdminReq makes an authenticated admin request to the license server.
func licAdminReq(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	parsed, err := urlpkg.Parse(url)
	require.NoError(t, err)
	baseURL := parsed.Scheme + "://" + parsed.Host
	return licAdminReqWithJWT(t, method, url, licGetJWT(t, baseURL), body)
}

// createTestOrgAndLicense creates an org and license via the admin API.
func createTestOrgAndLicense(t *testing.T, serverURL string, seats int) (orgID, licID string) {
	t.Helper()
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "IntTest-" + t.Name(),
		"contact_name":  "Integration Test Contact",
		"contact_email": "inttest@example.com",
	})
	var orgResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgResult))
	resp.Body.Close()
	orgObj, ok := orgResult["org"].(map[string]any)
	require.True(t, ok, "org creation response missing 'org' key: %v", orgResult)
	orgID = orgObj["id"].(string)

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": seats, "days": 365,
	})
	var licResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licResult))
	resp.Body.Close()
	licID = licResult["id"].(string)
	return
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	return resp
}

// --- Integration Tests ---

func TestLicenseServer_FullLifecycle(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	client := license.NewServerClient(serverURL)

	// Activate
	actResp, err := client.Activate(licID, license.ActivationTypeAgent, "")
	require.NoError(t, err)
	assert.NotEmpty(t, actResp.Token)
	assert.Equal(t, "pro", actResp.Tier)
	assert.Equal(t, 5, actResp.Seats)
	assert.Equal(t, 1, actResp.SeatsUsed)

	// Validate
	valResp, err := client.Validate(licID, actResp.Token)
	require.NoError(t, err)
	assert.True(t, valResp.Valid)

	// Deactivate
	require.NoError(t, client.Deactivate(licID))

	// Validate again — should be invalid (machine not activated)
	valResp, err = client.Validate(licID, actResp.Token)
	require.NoError(t, err)
	assert.False(t, valResp.Valid)
}

func TestLicenseServer_SeatLimit(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 2)

	// Activate machines 1 and 2
	for i, mid := range []string{"machine-1", "machine-2"} {
		resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
			"licenseID": licID, "machineID": mid, "hostname": "h" + string(rune('1'+i)),
		})
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	// Machine 3 should fail (seats full)
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-3",
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestLicenseServer_Revocation(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "m1",
	})
	resp.Body.Close()

	// Revoke
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Validate should return invalid
	client := license.NewServerClient(serverURL)
	valResp, err := client.Validate(licID, "any-token")
	require.NoError(t, err)
	assert.False(t, valResp.Valid)
	assert.Equal(t, "validation failed", valResp.Reason)
}

func TestLicenseServer_Reactivation(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 2)

	client := license.NewServerClient(serverURL)

	_, err := client.Activate(licID, license.ActivationTypeAgent, "")
	require.NoError(t, err)
	require.NoError(t, client.Deactivate(licID))
	resp, err := client.Activate(licID, license.ActivationTypeAgent, "")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, 1, resp.SeatsUsed)
}

func TestLicenseServer_ConcurrentActivation(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 1)

	var wg sync.WaitGroup
	var successes atomic.Int32

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			machineID := "concurrent-machine-" + string(rune('a'+i))
			b, _ := json.Marshal(map[string]string{
				"licenseID": licID, "machineID": machineID,
			})
			resp, err := http.Post(serverURL+"/api/v1/license/activate", "application/json", bytes.NewReader(b))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "only 1 of 5 concurrent activations should succeed")
}

func TestLicenseServer_AdminCRUD(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create org
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name": "CRUD-Org", "contact_name": "CRUD Admin", "contact_email": "admin@crud.com",
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	var org map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
	resp.Body.Close()
	orgData, ok := org["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response")
	orgID := orgData["id"].(string)

	// Update org
	resp = licAdminReq(t, "PUT", serverURL+"/api/v1/admin/orgs/"+orgID, map[string]string{
		"name": "CRUD-Org-Updated", "contact_name": "CRUD Admin", "contact_email": "admin@crud.com",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// List orgs
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/orgs", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var orgs []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgs))
	resp.Body.Close()
	assert.Len(t, orgs, 1)
	assert.Equal(t, "CRUD-Org-Updated", orgs[0]["name"])

	// Create license
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 10,
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// List licenses
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?org="+orgID, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var lics []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lics))
	resp.Body.Close()
	assert.Len(t, lics, 1)
}

func TestLicenseServer_AuditTrail(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	client := license.NewServerClient(serverURL)
	_, _ = client.Activate(licID, license.ActivationTypeAgent, "")
	_ = client.Deactivate(licID)

	resp := licAdminReq(t, "GET", serverURL+"/api/v1/admin/audit?limit=20", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var entries []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&entries))
	resp.Body.Close()

	events := make(map[string]bool)
	for _, e := range entries {
		events[e["eventType"].(string)] = true
	}
	assert.True(t, events["org_create"])
	assert.True(t, events["license_create"])
	assert.True(t, events["activate"])
	assert.True(t, events["deactivate"])
}

func TestLicenseServer_GuardOnlineValidation(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate this machine
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID,
		"machineID": license.MachineFingerprint(),
		"hostname":  "test-host",
	})
	var actResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&actResult))
	resp.Body.Close()
	token := actResult["token"].(string)

	// Verify token is valid with our public key
	lic, err := license.Parse(token, pub)
	require.NoError(t, err)
	assert.Equal(t, license.TierPro, lic.Tier)

	g := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierPro, g.Tier())
}

func TestLicenseServer_OfflineFallback_FreshCache(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "license.meta")

	meta := &license.CacheMeta{
		ServerURL:     "http://127.0.0.1:1",
		LicenseID:     "cached-lid",
		Tier:          "pro",
		Seats:         5,
		SeatsUsed:     1,
		ExpiresAt:     time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		LastValidated: time.Now().UTC(),
	}
	require.NoError(t, meta.Save(metaPath))

	loaded, err := license.LoadCacheMeta(metaPath)
	require.NoError(t, err)
	assert.True(t, loaded.IsFresh())
}

func TestLicenseServer_OfflineFallback_StaleCache(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "license.meta")

	meta := &license.CacheMeta{
		ServerURL:     "http://127.0.0.1:1",
		LicenseID:     "cached-lid",
		Tier:          "pro",
		LastValidated: time.Now().Add(-10 * 24 * time.Hour),
	}
	require.NoError(t, meta.Save(metaPath))

	loaded, err := license.LoadCacheMeta(metaPath)
	require.NoError(t, err)
	assert.False(t, loaded.IsFresh())
}

func TestLicenseServer_BackwardCompat_OfflineToken(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	token, err := license.IssueTokenWithOptions(priv, license.TierEnterprise, "TestOrg", 10, 365, false)
	require.NoError(t, err)

	g := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierEnterprise, g.Tier())
	assert.True(t, g.Allowed(license.FeatureServerMode))
}

func TestLicenseServer_ExpiredLicense(t *testing.T) {
	serverURL, store, _, _ := requireLicenseServer(t)

	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "ExpiredOrg",
		"contact_name":  "Expired Contact",
		"contact_email": "expired@example.com",
	})
	var org map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
	resp.Body.Close()
	orgData, ok := org["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response")

	now := time.Now().UTC()
	expiredLicID := uuid.Must(uuid.NewV7()).String()
	lic := &licensestore.LicenseRecord{
		ID:        expiredLicID,
		OrgID:     orgData["id"].(string),
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  now.Add(-400 * 24 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateLicense(context.Background(), lic))

	client := license.NewServerClient(serverURL)
	_, err := client.Activate(expiredLicID, license.ActivationTypeAgent, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestLicenseServer_Health(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	client := license.NewServerClient(serverURL)
	require.NoError(t, client.Health())
}


// decodeJSONArray asserts 200 OK and decodes a JSON array response body.
func decodeJSONArray(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// licAdminReqWithJWT makes an admin request authenticated with a Bearer JWT.
func licAdminReqWithJWT(t *testing.T, method, url, jwt string, body any) *http.Response {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, url, bodyReader)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// createTestOrg is a helper that creates an org and returns its ID.
func createTestOrg(t *testing.T, serverURL, name string) string {
	t.Helper()
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          name,
		"contact_name":  "Test Contact",
		"contact_email": "contact@test.example",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var org map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
	resp.Body.Close()
	orgData, ok := org["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response")
	return orgData["id"].(string)
}

// --- Group A: Organization Lifecycle ---

func TestLicenseServer_DeleteOrg_NoLicenses(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create org
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "DeleteMe-Org",
		"contact_name":  "Delete Contact",
		"contact_email": "delete@example.com",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var org map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
	resp.Body.Close()
	orgData, ok := org["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response")
	orgID := orgData["id"].(string)

	// Delete org
	resp = licAdminReq(t, "DELETE", serverURL+"/api/v1/admin/orgs/"+orgID, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// GET org should return 404
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/orgs/"+orgID, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestLicenseServer_DuplicateOrgName(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create "UniqueOrg"
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "UniqueOrg",
		"contact_name":  "Unique Contact",
		"contact_email": "unique@example.com",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var org1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org1))
	resp.Body.Close()
	org1Data, ok := org1["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response")
	org1ID := org1Data["id"].(string)

	// Create same name again → 409
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "UniqueOrg",
		"contact_name":  "Duplicate Contact",
		"contact_email": "dup@example.com",
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()

	// Rename first org
	resp = licAdminReq(t, "PUT", serverURL+"/api/v1/admin/orgs/"+org1ID, map[string]string{
		"name":          "RenamedOrg",
		"contact_name":  "Unique Contact",
		"contact_email": "unique@example.com",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Now "UniqueOrg" should be available
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "UniqueOrg",
		"contact_name":  "New Unique Contact",
		"contact_email": "newunique@example.com",
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
}

// --- Group B: License Filters ---

func TestLicenseServer_LicenseFilter_ByOrg(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create 2 orgs
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "FilterOrg1",
		"contact_name":  "Filter Contact 1",
		"contact_email": "filter1@example.com",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var org1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org1))
	resp.Body.Close()
	org1Data, ok := org1["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response for FilterOrg1")
	org1ID := org1Data["id"].(string)

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "FilterOrg2",
		"contact_name":  "Filter Contact 2",
		"contact_email": "filter2@example.com",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var org2 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&org2))
	resp.Body.Close()
	org2Data, ok := org2["org"].(map[string]any)
	require.True(t, ok, "expected 'org' key in POST /orgs response for FilterOrg2")
	org2ID := org2Data["id"].(string)

	// Create 1 license for each org
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org1ID, "tier": "pro", "seats": 5,
	})
	resp.Body.Close()

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org2ID, "tier": "enterprise", "seats": 3,
	})
	resp.Body.Close()

	// Filter by org1
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?org="+org1ID, nil)
	lics := decodeJSONArray(t, resp)
	assert.Len(t, lics, 1)
	assert.Equal(t, "pro", lics[0]["tier"])
}

func TestLicenseServer_LicenseFilter_ByTier(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	orgID := createTestOrg(t, serverURL, "TierFilterOrg")

	// Create pro + enterprise licenses
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 2,
	})
	resp.Body.Close()

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5,
	})
	resp.Body.Close()

	// Filter by pro
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?tier=pro", nil)
	lics := decodeJSONArray(t, resp)
	assert.Len(t, lics, 1)
	assert.Equal(t, "pro", lics[0]["tier"])
}

func TestLicenseServer_LicenseFilter_ByStatus(t *testing.T) {
	serverURL, store, _, _ := requireLicenseServer(t)
	orgID := createTestOrg(t, serverURL, "StatusFilterOrg")

	// Create an active license via API
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 5, "days": 365,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var activeLic map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&activeLic))
	resp.Body.Close()

	// Create a revoked license via API and revoke it
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 2,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var revokedLic map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&revokedLic))
	resp.Body.Close()
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+revokedLic["id"].(string)+"/revoke", nil)
	resp.Body.Close()

	// Create an expired license directly via store
	now := time.Now().UTC()
	expLic := &licensestore.LicenseRecord{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Tier:      "enterprise",
		Seats:     1,
		IssuedAt:  now.Add(-400 * 24 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateLicense(context.Background(), expLic))

	// Filter active
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?status=active", nil)
	lics := decodeJSONArray(t, resp)
	assert.Len(t, lics, 1)
	assert.Equal(t, activeLic["id"], lics[0]["id"])

	// Filter revoked
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?status=revoked", nil)
	lics = decodeJSONArray(t, resp)
	assert.Len(t, lics, 1)
	assert.Equal(t, revokedLic["id"], lics[0]["id"])

	// Filter expired
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/licenses?status=expired", nil)
	lics = decodeJSONArray(t, resp)
	assert.Len(t, lics, 1)
	assert.Equal(t, expLic.ID, lics[0]["id"])
}

// --- Group C: Activation Filters ---

func TestLicenseServer_ActivationFilter_ByLicense(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create org + 2 licenses
	orgID := createTestOrg(t, serverURL, "ActFilterOrg")

	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "pro", "seats": 5,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic1))
	resp.Body.Close()

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic2 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic2))
	resp.Body.Close()

	// Activate 1 machine on each license
	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": lic1["id"].(string), "machineID": "machine-lic1",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": lic2["id"].(string), "machineID": "machine-lic2",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Filter by lic1
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?license="+lic1["id"].(string), nil)
	acts := decodeJSONArray(t, resp)
	assert.Len(t, acts, 1)
	assert.Equal(t, "machine-lic1", acts[0]["machineID"])
}

func TestLicenseServer_ActivationFilter_ByMachine(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate 3 machines
	for _, mid := range []string{"machine-1", "machine-2", "machine-3"} {
		resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
			"licenseID": licID, "machineID": mid,
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	// Filter by machine-2
	resp := licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?machine=machine-2", nil)
	acts := decodeJSONArray(t, resp)
	assert.Len(t, acts, 1)
	assert.Equal(t, "machine-2", acts[0]["machineID"])
}

func TestLicenseServer_ActivationFilter_ByActive(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate 2 machines
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "active-m",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "deactivated-m",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Deactivate one
	resp = postJSON(t, serverURL+"/api/v1/license/deactivate", map[string]string{
		"licenseID": licID, "machineID": "deactivated-m",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Filter active=true
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?active=true", nil)
	acts := decodeJSONArray(t, resp)
	assert.Len(t, acts, 1)
	assert.Equal(t, "active-m", acts[0]["machineID"])

	// Filter active=false
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?active=false", nil)
	acts = decodeJSONArray(t, resp)
	assert.Len(t, acts, 1)
	assert.Equal(t, "deactivated-m", acts[0]["machineID"])
}

// --- Group D: Audit Filters ---

func TestLicenseServer_AuditFilter_ByEventType(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	client := license.NewServerClient(serverURL)
	_, err := client.Activate(licID, license.ActivationTypeAgent, "")
	require.NoError(t, err)
	require.NoError(t, client.Deactivate(licID))

	// Filter event=activate
	resp := licAdminReq(t, "GET", serverURL+"/api/v1/admin/audit?event=activate&limit=100", nil)
	entries := decodeJSONArray(t, resp)
	for _, e := range entries {
		assert.Equal(t, "activate", e["eventType"])
	}
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestLicenseServer_AuditFilter_ByLicense(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create 2 separate orgs + licenses (can't call createTestOrgAndLicense twice — same org name)
	org1ID := createTestOrg(t, serverURL, "AuditLicFilter-Org1")
	org2ID := createTestOrg(t, serverURL, "AuditLicFilter-Org2")

	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org1ID, "tier": "pro", "seats": 5,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic1Result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic1Result))
	resp.Body.Close()
	lic1 := lic1Result["id"].(string)

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org2ID, "tier": "pro", "seats": 5,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic2Result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic2Result))
	resp.Body.Close()
	lic2 := lic2Result["id"].(string)

	// Activate on each
	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": lic1, "machineID": "audit-m1",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": lic2, "machineID": "audit-m2",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Filter by lic1
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/audit?license="+lic1+"&limit=100", nil)
	entries := decodeJSONArray(t, resp)
	for _, e := range entries {
		assert.Equal(t, lic1, e["licenseID"])
	}
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestLicenseServer_AuditFilter_ByTimeRange(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Wait until the wall clock crosses a second boundary so that RFC3339
	// (second precision) reliably separates creation events from the activate.
	startSec := time.Now().Truncate(time.Second)
	for time.Now().Truncate(time.Second).Equal(startSec) {
		time.Sleep(50 * time.Millisecond)
	}
	afterCreate := time.Now().UTC().Format(time.RFC3339)

	// Activate — this should be the only event after afterCreate
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "time-range-m",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Filter after=afterCreate
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/audit?after="+afterCreate+"&limit=100", nil)
	entries := decodeJSONArray(t, resp)
	assert.GreaterOrEqual(t, len(entries), 1)
	for _, e := range entries {
		assert.Equal(t, "activate", e["eventType"])
	}
}

// --- Group E: Seat Management ---

func TestLicenseServer_SeatRelease_AfterDeactivate(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 1) // 1-seat license

	// Activate machine A
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "seat-m-a",
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Machine B should fail (seats full)
	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "seat-m-b",
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()

	// Deactivate A
	resp = postJSON(t, serverURL+"/api/v1/license/deactivate", map[string]string{
		"licenseID": licID, "machineID": "seat-m-a",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Machine B should now succeed
	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "seat-m-b",
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
}

func TestLicenseServer_AdminDeactivate_FreesASeat(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 1) // 1-seat license

	// Activate machine A
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "admin-deact-a",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var actResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&actResult))
	resp.Body.Close()
	actID := actResult["activationID"].(string)

	// Admin deactivate by activation ID
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/activations/"+actID+"/deactivate", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Machine B should now succeed
	resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "admin-deact-b",
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
}

// --- Group F: Revocation Side Effects ---

func TestLicenseServer_Revocation_DeactivatesAll(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate 3 machines
	for _, mid := range []string{"rev-m1", "rev-m2", "rev-m3"} {
		resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
			"licenseID": licID, "machineID": mid,
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	// Revoke the license
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// All activations should be inactive
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?license="+licID+"&active=true", nil)
	activeActs := decodeJSONArray(t, resp)
	assert.Len(t, activeActs, 0)

	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/activations?license="+licID+"&active=false", nil)
	inactiveActs := decodeJSONArray(t, resp)
	assert.Len(t, inactiveActs, 3)
}

// --- Group G: Client Library ---

func TestLicenseServer_ClientLib_FullRoundTrip(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	client := license.NewServerClient(serverURL)

	// Health
	require.NoError(t, client.Health())

	// Activate
	actResp, err := client.Activate(licID, license.ActivationTypeAgent, "")
	require.NoError(t, err)
	assert.NotEmpty(t, actResp.Token)
	assert.Equal(t, "pro", actResp.Tier)
	assert.Equal(t, 5, actResp.Seats)
	assert.Equal(t, 1, actResp.SeatsUsed)
	assert.NotEmpty(t, actResp.ExpiresAt)
	assert.NotEmpty(t, actResp.ActivationID)

	// Validate
	valResp, err := client.Validate(licID, actResp.Token)
	require.NoError(t, err)
	assert.True(t, valResp.Valid)
	assert.Equal(t, "pro", valResp.Tier)

	// Parse token with public key
	lic, err := license.Parse(actResp.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, license.TierPro, lic.Tier)

	// Deactivate
	require.NoError(t, client.Deactivate(licID))

	// Validate after deactivate — should be invalid
	valResp, err = client.Validate(licID, actResp.Token)
	require.NoError(t, err)
	assert.False(t, valResp.Valid)
}

func TestLicenseServer_ClientLib_ActivateErrors(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Create 2 orgs + licenses separately to avoid duplicate org name
	org1ID := createTestOrg(t, serverURL, "ClientErrors-Org1")
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org1ID, "tier": "pro", "seats": 1,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic1Result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic1Result))
	resp.Body.Close()
	licID := lic1Result["id"].(string)

	client := license.NewServerClient(serverURL)

	// Invalid license ID → not found
	_, err := client.Activate(uuid.Must(uuid.NewV7()).String(), license.ActivationTypeAgent, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Revoked license → denied
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	resp.Body.Close()
	_, err = client.Activate(licID, license.ActivationTypeAgent, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")

	// Full seats → seats error
	org2ID := createTestOrg(t, serverURL, "ClientErrors-Org2")
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org2ID, "tier": "pro", "seats": 1,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic2Result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic2Result))
	resp.Body.Close()
	licID2 := lic2Result["id"].(string)

	// Use raw HTTP to activate with a different machine ID (client uses MachineFingerprint)
	rawResp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID2, "machineID": "fill-seat",
	})
	require.Equal(t, http.StatusCreated, rawResp.StatusCode)
	rawResp.Body.Close()

	// Now client (different machine fingerprint) should fail
	_, err = client.Activate(licID2, license.ActivationTypeAgent, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "seats")
}

// --- Group H: Guard Integration ---

func TestLicenseServer_GuardWithServer_TierElevation(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createTestOrgAndLicense(t, serverURL, 5)

	// Activate this machine via API (using this machine's fingerprint)
	resp := postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID,
		"machineID": license.MachineFingerprint(),
		"hostname":  "guard-test-host",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var actResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&actResult))
	resp.Body.Close()
	token := actResult["token"].(string)

	// Create guard from token
	g := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierPro, g.Tier())

	// Verify pro features are allowed
	assert.True(t, g.Allowed(license.FeatureProfileStandard))
	assert.True(t, g.Allowed(license.FeatureProfileComprehensive))
	assert.True(t, g.Allowed(license.FeatureDB))
	assert.True(t, g.Allowed(license.FeatureDiff))
	assert.True(t, g.Allowed(license.FeatureTrend))
	assert.True(t, g.Allowed(license.FeaturePolicyBuiltin))

	// Enterprise-only features should be denied
	assert.False(t, g.Allowed(license.FeatureServerMode))
	assert.False(t, g.Allowed(license.FeaturePolicyCustom))
}

func TestLicenseServer_GuardCacheMeta_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "license.meta")

	original := &license.CacheMeta{
		ServerURL:     "http://license.example.com",
		LicenseID:     "test-lid-123",
		Tier:          "enterprise",
		Seats:         10,
		SeatsUsed:     3,
		ExpiresAt:     time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
		LastValidated: time.Now().UTC(),
	}
	require.NoError(t, original.Save(metaPath))

	// Load and verify all fields
	loaded, err := license.LoadCacheMeta(metaPath)
	require.NoError(t, err)
	assert.Equal(t, original.ServerURL, loaded.ServerURL)
	assert.Equal(t, original.LicenseID, loaded.LicenseID)
	assert.Equal(t, original.Tier, loaded.Tier)
	assert.Equal(t, original.Seats, loaded.Seats)
	assert.Equal(t, original.SeatsUsed, loaded.SeatsUsed)
	assert.Equal(t, original.ExpiresAt, loaded.ExpiresAt)
	assert.True(t, loaded.IsFresh())

	// Modify to stale
	loaded.LastValidated = time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, loaded.Save(metaPath))

	reloaded, err := license.LoadCacheMeta(metaPath)
	require.NoError(t, err)
	assert.False(t, reloaded.IsFresh())
}

// --- Group I: JWT Auth & Stats ---

func TestLicenseServer_JWTAuthRequired(t *testing.T) {
	serverURL, _, _, _ := requireLicenseServer(t)

	// Valid JWT must succeed.
	resp := licAdminReq(t, "GET", serverURL+"/api/v1/admin/orgs", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Invalid token must be rejected.
	resp = licAdminReqWithJWT(t, "GET", serverURL+"/api/v1/admin/orgs", "invalid.jwt.token", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// No Authorization header must be rejected.
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/admin/orgs", nil)
	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	resp2.Body.Close()
}

func TestLicenseServer_StatsAccuracy(t *testing.T) {
	serverURL, store, _, _ := requireLicenseServer(t)

	// Create 2 orgs
	org1ID := createTestOrg(t, serverURL, "StatsOrg1")
	org2ID := createTestOrg(t, serverURL, "StatsOrg2")

	// Create 2 active licenses (org1)
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org1ID, "tier": "pro", "seats": 5,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var lic1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic1))
	resp.Body.Close()

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org1ID, "tier": "enterprise", "seats": 10,
	})
	resp.Body.Close()

	// Create 1 revoked license (org2)
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": org2ID, "tier": "pro", "seats": 3,
	})
	var lic3 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&lic3))
	resp.Body.Close()
	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+lic3["id"].(string)+"/revoke", nil)
	resp.Body.Close()

	// Create an expired license directly in store
	now := time.Now().UTC()
	expLic := &licensestore.LicenseRecord{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     org2ID,
		Tier:      "free",
		Seats:     1,
		IssuedAt:  now.Add(-400 * 24 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateLicense(context.Background(), expLic))

	// Activate 2 machines on lic1
	for _, mid := range []string{"stats-m1", "stats-m2"} {
		resp = postJSON(t, serverURL+"/api/v1/license/activate", map[string]string{
			"licenseID": lic1["id"].(string), "machineID": mid,
		})
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	// Check stats
	resp = licAdminReq(t, "GET", serverURL+"/api/v1/admin/stats", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var stats map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&stats))
	resp.Body.Close()

	assert.Equal(t, float64(2), stats["totalOrgs"])
	assert.Equal(t, float64(4), stats["totalLicenses"])    // 2 active + 1 revoked + 1 expired
	assert.Equal(t, float64(2), stats["activeLicenses"])   // 2 active (not revoked, not expired)
	assert.Equal(t, float64(1), stats["revokedLicenses"])  // 1 revoked
	assert.Equal(t, float64(1), stats["expiredLicenses"])  // 1 expired
	assert.Equal(t, float64(2), stats["totalActivations"]) // 2 activations
	assert.Equal(t, float64(2), stats["activeSeats"])      // 2 active seats
}

// --- Group J: Org Contact Fields + Expiry Notifications ---

// doLicAdminReqRaw makes an authenticated admin request with a raw JSON string body.
func doLicAdminReqRaw(t *testing.T, method, url, jwt, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// makeIntegrationOrg creates an org directly in the store for use in store-level tests.
func makeIntegrationOrg(t *testing.T, store *licensestore.PostgresStore, name string) *licensestore.Organization {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	org := &licensestore.Organization{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Name:         name,
		ContactName:  "Default Contact",
		ContactEmail: "default@example.com",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, store.CreateOrg(ctx, org))
	return org
}

// makeIntegrationLicense creates a license directly in the store for use in store-level tests.
func makeIntegrationLicense(t *testing.T, store *licensestore.PostgresStore, orgID string, expiresIn time.Duration) *licensestore.LicenseRecord {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	lic := &licensestore.LicenseRecord{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  now,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateLicense(ctx, lic))
	return lic
}

func TestOrgContactFields_CreateAndRead(t *testing.T) {
	baseURL, _, _, _ := requireLicenseServer(t)
	jwt := licGetJWT(t, baseURL)

	resp := doLicAdminReqRaw(t, "POST", baseURL+"/api/v1/admin/orgs", jwt, `{
		"name": "Contact Test Org",
		"contact_name": "Ahmad bin Ali",
		"contact_phone": "+60123456789",
		"contact_email": "ahmad@nacsa.gov.my"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created struct {
		Org struct {
			ID           string `json:"id"`
			ContactName  string `json:"contact_name"`
			ContactPhone string `json:"contact_phone"`
			ContactEmail string `json:"contact_email"`
		} `json:"org"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	assert.Equal(t, "Ahmad bin Ali", created.Org.ContactName)
	assert.Equal(t, "+60123456789", created.Org.ContactPhone)
	assert.Equal(t, "ahmad@nacsa.gov.my", created.Org.ContactEmail)

	// Read back via GET
	get := licAdminReqWithJWT(t, "GET", baseURL+"/api/v1/admin/orgs/"+created.Org.ID, jwt, nil)
	require.Equal(t, http.StatusOK, get.StatusCode)
	var org map[string]any
	require.NoError(t, json.NewDecoder(get.Body).Decode(&org))
	get.Body.Close()
	assert.Equal(t, "Ahmad bin Ali", org["contact_name"])
	assert.Equal(t, "+60123456789", org["contact_phone"])
	assert.Equal(t, "ahmad@nacsa.gov.my", org["contact_email"])
}

func TestOrgContactFields_CreateValidation(t *testing.T) {
	baseURL, _, _, _ := requireLicenseServer(t)
	jwt := licGetJWT(t, baseURL)

	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "missing contact_name",
			body: `{"name":"Org A","contact_email":"a@b.com"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "missing contact_email",
			body: `{"name":"Org B","contact_name":"Bob"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "invalid contact_email",
			body: `{"name":"Org C","contact_name":"Carol","contact_email":"not-an-email"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "valid with phone",
			body: `{"name":"Org D","contact_name":"Dave","contact_email":"dave@d.com","contact_phone":"+601234"}`,
			want: http.StatusCreated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doLicAdminReqRaw(t, "POST", baseURL+"/api/v1/admin/orgs", jwt, tc.body)
			resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode, "test: %s", tc.name)
		})
	}
}

func TestExpiryNotifications_30dTriggered(t *testing.T) {
	_, store, _, _ := requireLicenseServer(t)
	ctx := context.Background()

	// Create org with contact email
	org := makeIntegrationOrg(t, store, "Expiry Test Org "+t.Name())
	org.ContactEmail = "contact@example.com"
	org.ContactName = "Test Contact"
	org.UpdatedAt = time.Now().UTC()
	require.NoError(t, store.UpdateOrg(ctx, org))

	// Create license expiring in 20 days (within 30d window)
	lic := makeIntegrationLicense(t, store, org.ID, 20*24*time.Hour)

	// Verify notified_30d_at starts NULL
	results, err := store.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	var before *licensestore.LicenseWithOrg
	for i := range results {
		if results[i].LicenseID == lic.ID {
			before = &results[i]
		}
	}
	require.NotNil(t, before, "license should appear in 30d window")
	assert.Nil(t, before.Notified30dAt)

	// Mark as notified
	require.NoError(t, store.MarkLicenseNotified(ctx, lic.ID, "30d"))

	// Verify notified_30d_at is now set
	results2, err := store.ListExpiringLicenses(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	var after *licensestore.LicenseWithOrg
	for i := range results2 {
		if results2[i].LicenseID == lic.ID {
			after = &results2[i]
		}
	}
	require.NotNil(t, after)
	assert.NotNil(t, after.Notified30dAt)
	assert.Nil(t, after.Notified7dAt)
	assert.Nil(t, after.Notified1dAt)
}
