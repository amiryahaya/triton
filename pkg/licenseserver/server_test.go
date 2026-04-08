//go:build integration

package licenseserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

var serverTestSeq atomic.Int64

func setupTestServer(t *testing.T) (*httptest.Server, *licensestore.PostgresStore) {
	t.Helper()
	ts, store, _ := setupTestServerWithReport(t, nil)
	return ts, store
}

// setupTestServerWithFastLimiter returns a license server configured
// with the production 5-attempt budget but a long-enough window and
// lockout that a single test can burn the budget, verify the 429, and
// complete without the limiter auto-unlocking. Tests that want to
// exercise unlock behavior should build their own cfg with a short
// LockoutDuration.
func setupTestServerWithFastLimiter(t *testing.T) (*httptest.Server, *licensestore.PostgresStore) {
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

	rlCfg := auth.LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          1 * time.Hour,
		LockoutDuration: 1 * time.Hour,
	}
	cfg := &licenseserver.Config{
		ListenAddr:             ":0",
		AdminKeys:              []string{"test-admin-key"},
		SigningKey:             priv,
		PublicKey:              pub,
		BinariesDir:            t.TempDir(),
		LoginRateLimiterConfig: &rlCfg,
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

// setupTestServerWithReport sets up a license server optionally wired to
// a fake report server (for Phase 1.7 provisioning tests). Pass nil for
// reportHandler to skip report server configuration (same as setupTestServer).
// Returns (ts, store, reportTS) — reportTS is nil when reportHandler is nil.
func setupTestServerWithReport(t *testing.T, reportHandler http.HandlerFunc) (*httptest.Server, *licensestore.PostgresStore, *httptest.Server) {
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

	// If a report handler was supplied, spin up a fake report server
	// and wire it into the license server config.
	var reportTS *httptest.Server
	if reportHandler != nil {
		reportTS = httptest.NewServer(reportHandler)
		cfg.ReportServerURL = reportTS.URL
		cfg.ReportServerServiceKey = "test-shared-secret"
	}

	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	t.Cleanup(func() {
		ts.Close()
		if reportTS != nil {
			reportTS.Close()
		}
		_ = store.DropSchema(ctx)
		store.Close()
	})
	return ts, store, reportTS
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

// orgIDOf extracts the org ID from a CreateOrg response body, handling
// the unified {org: {...}} shape introduced in the Phase 1.7/1.8
// architecture review (Arch #8). Returns the ID as a string suitable
// for use in downstream request bodies and paths.
func orgIDOf(result map[string]any) string {
	if org, ok := result["org"].(map[string]any); ok {
		if id, ok := org["id"].(string); ok {
			return id
		}
	}
	return ""
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
	// Unified response: org lives inside result.org; admin is omitted
	// when no admin fields were supplied.
	orgBlock := result["org"].(map[string]any)
	assert.Equal(t, "Acme Corp", orgBlock["name"])
	assert.NotEmpty(t, orgBlock["id"])
	_, hasAdmin := result["admin"]
	assert.False(t, hasAdmin, "admin block must be omitted when no admin fields supplied")
}

func TestCreateOrg_MissingName(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]string{})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Phase 1.7: org create with report server provisioning ---

// TestCreateOrg_WithAdminProvisionsReportServer verifies that when the
// license server admin supplies admin_email + admin_name, the report
// server is called with a temp password, and the response surfaces the
// temp password to the caller via the unified {org, admin} shape.
func TestCreateOrg_WithAdminProvisionsReportServer(t *testing.T) {
	var receivedBody map[string]any
	var receivedKey string
	reportHandler := func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Triton-Service-Key")
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org":           map[string]any{"id": receivedBody["id"], "name": receivedBody["name"]},
			"admin_user_id": "user-xyz",
		})
	}
	ts, store, _ := setupTestServerWithReport(t, reportHandler)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Acme Corp",
		"admin_email": "alice@acme.com",
		"admin_name":  "Alice Admin",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	// Unified response: org at top level, admin as a nested block.
	orgBlock, ok := result["org"].(map[string]any)
	require.True(t, ok, "response must contain org block")
	assert.Equal(t, "Acme Corp", orgBlock["name"])

	adminBlock, ok := result["admin"].(map[string]any)
	require.True(t, ok, "response must contain admin block when provisioning")
	tempPassword := adminBlock["temp_password"].(string)
	assert.GreaterOrEqual(t, len(tempPassword), 12)
	assert.Equal(t, "alice@acme.com", adminBlock["email"])
	// email_delivered is false because this test has no Mailer configured
	assert.Equal(t, false, adminBlock["email_delivered"])

	// Report server received the correct request.
	assert.Equal(t, "test-shared-secret", receivedKey)
	assert.Equal(t, "Acme Corp", receivedBody["name"])
	assert.Equal(t, "alice@acme.com", receivedBody["admin_email"])
	assert.Equal(t, tempPassword, receivedBody["admin_temp_password"],
		"report server must receive the same temp password the license server surfaces")

	// License server org exists.
	orgs, err := store.ListOrgs(t.Context())
	require.NoError(t, err)
	require.Len(t, orgs, 1)
	assert.Equal(t, "Acme Corp", orgs[0].Name)
}

// TestCreateOrg_WithoutAdminSkipsProvisioning verifies backward compat:
// omitting admin_email/admin_name keeps the legacy behavior where the
// license server creates the org and does NOT touch the report server.
func TestCreateOrg_WithoutAdminSkipsProvisioning(t *testing.T) {
	called := false
	reportHandler := func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}
	ts, _, _ := setupTestServerWithReport(t, reportHandler)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name": "Legacy Org",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.False(t, called, "report server must not be called when admin fields are omitted")
}

// TestCreateOrg_AdminEmailWithoutName verifies partial admin fields are
// rejected — either both or neither must be supplied.
func TestCreateOrg_AdminEmailWithoutName(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Partial Org",
		"admin_email": "alice@acme.com",
		// admin_name omitted
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestCreateOrg_ProvisioningWithoutReportServerConfigured verifies that
// if the caller requests provisioning but no report server is configured,
// the request is rejected with 503 (not a generic 500).
func TestCreateOrg_ProvisioningWithoutReportServerConfigured(t *testing.T) {
	ts, _ := setupTestServer(t) // no report server
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Acme",
		"admin_email": "alice@acme.com",
		"admin_name":  "Alice",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// recordingMailer is a test Mailer that captures every SendInviteEmail
// call for later assertion. Also supports optional failure injection
// to test the "email failed, but org still created" path.
type recordingMailer struct {
	sent     []licenseserver.InviteEmailData
	failWith error
}

func (m *recordingMailer) SendInviteEmail(_ context.Context, data licenseserver.InviteEmailData) error {
	m.sent = append(m.sent, data)
	return m.failWith
}

// setupTestServerWithMailer builds a license server with both a fake
// report server (for provisioning) and a recording mailer (for email).
func setupTestServerWithMailer(t *testing.T, mailer licenseserver.Mailer) (*httptest.Server, *licensestore.PostgresStore) {
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

	// Fake report server that always accepts provisioning.
	reportTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"org":{"id":"x","name":"y"},"admin_user_id":"u"}`))
	}))

	cfg := &licenseserver.Config{
		ListenAddr:             ":0",
		AdminKeys:              []string{"test-admin-key"},
		SigningKey:             priv,
		PublicKey:              pub,
		BinariesDir:            t.TempDir(),
		ReportServerURL:        reportTS.URL,
		ReportServerServiceKey: "test-shared-secret",
		Mailer:                 mailer,
		ReportServerInviteURL:  "https://reports.test/login",
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())

	t.Cleanup(func() {
		ts.Close()
		reportTS.Close()
		_ = store.DropSchema(ctx)
		store.Close()
	})
	return ts, store
}

// TestCreateOrg_SendsInviteEmail verifies that after successful
// provisioning, the Mailer is invoked with the correct invite data
// and the response's admin.email_delivered flag reflects success.
func TestCreateOrg_SendsInviteEmail(t *testing.T) {
	mailer := &recordingMailer{}
	ts, _ := setupTestServerWithMailer(t, mailer)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Acme Corp",
		"admin_email": "alice@acme.com",
		"admin_name":  "Alice Admin",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	adminBlock := result["admin"].(map[string]any)
	tempPassword := adminBlock["temp_password"].(string)

	// email_delivered must be true when the mailer returned nil.
	assert.Equal(t, true, adminBlock["email_delivered"],
		"email_delivered must reflect Mailer success")

	// Mailer should have been called exactly once with matching data.
	require.Len(t, mailer.sent, 1)
	sent := mailer.sent[0]
	assert.Equal(t, "alice@acme.com", sent.ToEmail)
	assert.Equal(t, "Alice Admin", sent.ToName)
	assert.Equal(t, "Acme Corp", sent.OrgName)
	assert.Equal(t, tempPassword, sent.TempPassword,
		"mailer must receive the same temp password surfaced in the response")
	assert.Equal(t, "https://reports.test/login", sent.LoginURL)
}

// TestCreateOrg_EmailFailureIsNonFatal verifies that if the mailer
// fails to send (e.g., Resend API down), the org creation STILL
// succeeds, the temp password is still returned, and the response
// marks email_delivered=false so the caller knows to deliver manually.
func TestCreateOrg_EmailFailureIsNonFatal(t *testing.T) {
	mailer := &recordingMailer{failWith: errors.New("resend down")}
	ts, store := setupTestServerWithMailer(t, mailer)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Acme Corp",
		"admin_email": "alice@acme.com",
		"admin_name":  "Alice Admin",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "org creation must succeed despite email failure")

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	adminBlock := result["admin"].(map[string]any)
	assert.NotEmpty(t, adminBlock["temp_password"], "temp password must still be in response for manual delivery")
	assert.Equal(t, false, adminBlock["email_delivered"],
		"email_delivered must be false when the mailer returned an error")

	// License server should still have the org (no rollback).
	orgs, err := store.ListOrgs(t.Context())
	require.NoError(t, err)
	assert.Len(t, orgs, 1)
}

// TestCreateOrg_RollsBackOnProvisioningFailure verifies that if the
// report server rejects the provisioning call, the license server
// deletes the org it just created so the two servers stay consistent.
func TestCreateOrg_RollsBackOnProvisioningFailure(t *testing.T) {
	reportHandler := func(w http.ResponseWriter, _ *http.Request) {
		// Simulate report server failing to create (e.g., email already in use).
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"user with this email already exists"}`))
	}
	ts, store, _ := setupTestServerWithReport(t, reportHandler)

	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/orgs", map[string]any{
		"name":        "Will Rollback",
		"admin_email": "alice@acme.com",
		"admin_name":  "Alice",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	// License server should NOT have the org.
	orgs, err := store.ListOrgs(t.Context())
	require.NoError(t, err)
	assert.Empty(t, orgs, "org must have been rolled back after provisioning failure")
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
	orgID := orgIDOf(orgResult)

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
	orgID := orgIDOf(orgResult)

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
		"orgID": orgIDOf(orgResult), "tier": "invalid", "seats": 5,
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
		"orgID": orgIDOf(orgResult), "tier": "pro", "seats": 5,
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
	orgID = orgIDOf(orgResult)

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
		"orgID": orgIDOf(orgResult), "tier": "pro", "seats": 1,
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

// TestValidate_IncludesCacheTTL verifies the validate response includes
// a cacheTTL field (in seconds) that the report server's validation cache
// will honor as the maximum cache age. Centralizes the trust window in
// the license server rather than scattering it across clients.
func TestValidate_IncludesCacheTTL(t *testing.T) {
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
	require.Equal(t, true, result["valid"])
	cacheTTL, ok := result["cacheTTL"].(float64) // JSON numbers decode to float64
	require.True(t, ok, "cacheTTL must be present and numeric")
	assert.Greater(t, cacheTTL, float64(0), "cacheTTL must be positive")
}

// TestValidate_ReturnsOrgInfo verifies the validate response includes the
// orgID and orgName fields that the report server's validation cache will
// consume (Phase 2.1). Added under Task 1.6 amendment.
func TestValidate_ReturnsOrgInfo(t *testing.T) {
	ts, _ := setupTestServer(t)
	orgID, licID := createOrgAndLicense(t, ts.URL)

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
	assert.Equal(t, orgID, result["orgID"])
	// Org name was set to "ActivOrg" + t.Name() in createOrgAndLicense
	assert.Equal(t, "ActivOrg"+t.Name(), result["orgName"])
}

// TestListOrgsEmptyReturnsArray verifies that the orgs list endpoint returns
// a JSON array (`[]`) and not `null` when the table is empty. JS clients
// commonly assume `Array.isArray(response)` and crash on `null`.
func TestListOrgsEmptyReturnsArray(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(string(body)), "empty list must serialize as [] not null")
}

// TestListLicensesEmptyReturnsArray — same as TestListOrgsEmptyReturnsArray
// but for the licenses list endpoint.
func TestListLicensesEmptyReturnsArray(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/licenses", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(string(body)), "empty list must serialize as [] not null")
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
	orgID := orgIDOf(orgResult)

	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs/"+orgID, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := decodeJSON(t, resp)
	assert.Equal(t, "GetMeOrg", result["name"])
	assert.Equal(t, "get@me.org", result["contact"])
}

func TestGetOrg_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, "GET", ts.URL+"/api/v1/admin/orgs/00000000-0000-0000-0000-000000000000", nil)
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
	orgID := orgIDOf(orgResult)

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
		"orgID": orgIDOf(orgResult), "tier": "pro", "seats": 5, "days": -30,
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
		"orgID": orgIDOf(orgResult), "tier": "pro", "seats": 5,
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
	resp := adminReq(t, "POST", ts.URL+"/api/v1/admin/activations/00000000-0000-0000-0000-000000000000/deactivate", nil)
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

	resp, err := http.Get(ts.URL + "/api/v1/license/download/1.0.0/linux/amd64?license_id=00000000-0000-0000-0000-000000000000")
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
	orgID := orgIDOf(orgResult)

	// Create an already-expired license directly via store (bypasses API validation).
	expiredLicID := "deadbeef-dead-beef-dead-beefdeadbeef"
	expiredLic := &licensestore.LicenseRecord{
		ID:        expiredLicID,
		OrgID:     orgID,
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // expired yesterday
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	require.NoError(t, store.CreateLicense(ctx, expiredLic))

	uploadBinary(t, ts.URL, "1.0.0", "linux", "amd64", []byte("bin")).Body.Close()
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/license/download/1.0.0/linux/amd64?license_id=%s", ts.URL, expiredLicID))
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

// --- Auth tests ---

func createTestUser(t *testing.T, ts *httptest.Server, store *licensestore.PostgresStore, email, password, role string) (*licensestore.Organization, *licensestore.User) {
	t.Helper()
	ctx := context.Background()

	// Create org (unless platform_admin).
	var org *licensestore.Organization
	var orgID string
	if role != "platform_admin" {
		org = &licensestore.Organization{
			ID:   uuid.Must(uuid.NewV7()).String(),
			Name: "Auth Test Org " + uuid.Must(uuid.NewV7()).String()[:8],
		}
		require.NoError(t, store.CreateOrg(ctx, org))
		orgID = org.ID
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    orgID,
		Email:    email,
		Name:     "Test " + role,
		Role:     role,
		Password: string(hashed),
	}
	require.NoError(t, store.CreateUser(ctx, user))
	return org, user
}

func TestLoginSuccess(t *testing.T) {
	ts, store := setupTestServer(t)
	email := fmt.Sprintf("login-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "secret123", "platform_admin")

	body, _ := json.Marshal(map[string]string{"email": email, "password": "secret123"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.NotEmpty(t, result["token"])
	assert.NotEmpty(t, result["expiresAt"])
}

func TestLoginWrongPassword(t *testing.T) {
	ts, store := setupTestServer(t)
	email := fmt.Sprintf("wrongpw-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "correct", "platform_admin")

	body, _ := json.Marshal(map[string]string{"email": email, "password": "wrong"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLoginUnknownEmail(t *testing.T) {
	ts, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]string{"email": "nobody@test.com", "password": "x"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestLoginRateLimited_AfterRepeatedFailures verifies Phase 5.1 on the
// license server: after 5 failed login attempts the next attempt (even
// with the correct password) returns 429 with Retry-After.
func TestLoginRateLimited_AfterRepeatedFailures(t *testing.T) {
	ts, store := setupTestServerWithFastLimiter(t)
	email := fmt.Sprintf("ratelimited-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "correct-pw-123", "platform_admin")

	// Burn through the 5-attempt budget with wrong passwords.
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]string{"email": email, "password": "wrong"})
		resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "attempt %d", i+1)
	}

	// 6th attempt with the CORRECT password must return 429.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-pw-123"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"license server must rate-limit after 5 failures even with correct password")
	assert.NotEmpty(t, resp.Header.Get("Retry-After"), "429 must include Retry-After")
}

// TestLoginRateLimit_ResetsOnSuccess verifies that a successful login
// clears the counter on the license server.
func TestLoginRateLimit_ResetsOnSuccess(t *testing.T) {
	ts, store := setupTestServerWithFastLimiter(t)
	email := fmt.Sprintf("rl-reset-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "correct-pw-123", "platform_admin")

	for i := 0; i < 4; i++ {
		body, _ := json.Marshal(map[string]string{"email": email, "password": "wrong"})
		resp, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		resp.Body.Close()
	}

	// Successful login resets the counter.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-pw-123"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now we get a fresh 5-attempt budget.
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]string{"email": email, "password": "wrong"})
		resp, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"post-reset attempt %d should still be 401", i+1)
	}
}

func TestLogout(t *testing.T) {
	ts, store := setupTestServer(t)
	email := fmt.Sprintf("logout-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "pw123", "platform_admin")

	// Login first.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "pw123"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]any
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Logout.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	logoutResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer logoutResp.Body.Close()
	assert.Equal(t, http.StatusOK, logoutResp.StatusCode)
}

func TestRefresh(t *testing.T) {
	ts, store := setupTestServer(t)
	email := fmt.Sprintf("refresh-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "pw456", "platform_admin")

	// Login.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "pw456"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]any
	json.NewDecoder(resp.Body).Decode(&loginResp)
	oldToken := loginResp["token"].(string)

	// Refresh.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	refreshResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer refreshResp.Body.Close()
	assert.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshResult map[string]any
	json.NewDecoder(refreshResp.Body).Decode(&refreshResult)
	newToken := refreshResult["token"].(string)
	assert.NotEmpty(t, newToken)
	assert.NotEmpty(t, refreshResult["expiresAt"])
}

func TestLoginMissingFields(t *testing.T) {
	ts, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]string{"email": "", "password": ""})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestLoginRejectsNonPlatformAdmin verifies that users whose role is not
// platform_admin cannot log in to the license server, even with valid
// credentials. The license server is the superadmin identity authority
// per the 2026-04-07 split-identity amendment.
func TestLoginRejectsNonPlatformAdmin(t *testing.T) {
	ts, store := setupTestServer(t)

	// Create an org_admin user with a valid password.
	email := fmt.Sprintf("orgadmin-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "correct-horse-battery", "org_admin")

	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Even with the right password, login must be rejected.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestLogoutSurfacesDeleteSessionError verifies that handleLogout returns
// HTTP 500 (rather than silently 200) when the underlying DeleteSession
// call fails. Without this guarantee, a "successful" logout could leave
// the session row alive and the token still usable.
func TestLogoutSurfacesDeleteSessionError(t *testing.T) {
	_, realStore := setupTestServer(t)
	wrap := newFailingStore(realStore)
	failTs := setupTestServerWithStore(t, wrap)

	// Create user directly via store, then login normally so a session row
	// exists in the DB.
	email := fmt.Sprintf("logoutfail-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, failTs, realStore, email, "correct-horse-battery", "platform_admin")

	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	resp, err := http.Post(failTs.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]any
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Now flip the toggle so DeleteSession fails on the next call.
	wrap.deleteSessionFails.Store(true)

	// Logout should surface the failure as 500, not silently succeed.
	req, _ := http.NewRequest("POST", failTs.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	logoutResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer logoutResp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, logoutResp.StatusCode)
}

// TestRefreshSurfacesDeleteSessionError verifies that handleRefresh returns
// HTTP 500 if the old session deletion fails — preventing a "successful"
// refresh from leaving both the old and new tokens valid simultaneously.
func TestRefreshSurfacesDeleteSessionError(t *testing.T) {
	_, realStore := setupTestServer(t)
	wrap := newFailingStore(realStore)
	failTs := setupTestServerWithStore(t, wrap)

	email := fmt.Sprintf("refreshfail-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, failTs, realStore, email, "correct-horse-battery", "platform_admin")

	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	resp, err := http.Post(failTs.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]any
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	wrap.deleteSessionFails.Store(true)

	req, _ := http.NewRequest("POST", failTs.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	refreshResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer refreshResp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, refreshResp.StatusCode)
}

// TestRefreshRejectsDemotedUser verifies that refresh re-checks the user's
// current role in the DB rather than trusting the role embedded in the old
// token. If an admin deletes a superadmin, their in-flight tokens must stop
// refreshing — otherwise a compromised token grants indefinite access via
// the refresh chain.
func TestRefreshRejectsDemotedUser(t *testing.T) {
	ts, store := setupTestServer(t)
	email := fmt.Sprintf("demoted-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, user := createTestUser(t, ts, store, email, "correct-horse-battery", "platform_admin")

	// Login successfully.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]any
	json.NewDecoder(resp.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Delete the user directly in the DB. Any future refresh must fail
	// because the user no longer exists as a valid platform_admin.
	require.NoError(t, store.DeleteUser(context.Background(), user.ID))

	// Attempt to refresh — must be rejected.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	refreshResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer refreshResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, refreshResp.StatusCode)
}

// TestLoginNormalizesEmail verifies that login lowercases and trims the email
// before looking it up, matching the normalization done by handleCreateSuperadmin.
func TestLoginNormalizesEmail(t *testing.T) {
	ts, store := setupTestServer(t)

	email := fmt.Sprintf("normalized-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	_, _ = createTestUser(t, ts, store, email, "correct-horse-battery", "platform_admin")

	// Login with mixed-case email + leading whitespace.
	uppercased := "  " + strings.ToUpper(email[:1]) + email[1:]
	body, _ := json.Marshal(map[string]string{"email": uppercased, "password": "correct-horse-battery"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
