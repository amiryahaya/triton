//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// ───────────────────────── helpers ─────────────────────────────────────

// plReq is a thin helper that sends a request through the full router and
// returns the recorded response. It accepts an optional Bearer token so
// authenticated platform-admin calls are easy.
func plReq(t *testing.T, srv *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)
	return rr
}

// doSetup calls POST /api/v1/setup and returns (tempPassword, userID).
func doSetup(t *testing.T, srv *Server, name, email string) (tempPassword, id string) {
	t.Helper()
	rr := plReq(t, srv, http.MethodPost, "/api/v1/setup", "", map[string]string{
		"name":  name,
		"email": email,
	})
	require.Equal(t, http.StatusCreated, rr.Code, "setup failed: %s", rr.Body.String())
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	return resp["tempPassword"], resp["id"]
}

// doLogin calls POST /api/v1/auth/login and returns the JWT token.
func doLogin(t *testing.T, srv *Server, email, password string) string {
	t.Helper()
	rr := plReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, rr.Code, "login failed: %s", rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	token, ok := resp["token"].(string)
	require.True(t, ok, "login response missing token field")
	return token
}

// decodeJWTPayload decodes the middle segment of a JWT without verifying
// the signature, returning a map of claims. Used only to inspect
// well-structured tokens that were just issued by the test server.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT must have three dot-separated segments")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// seedOrgWithLicence inserts an org plus a tenant_licence row with the
// given status directly into the store. Used by licence enforcement tests
// to set up state without going through the HTTP API.
func seedOrgWithLicence(t *testing.T, db *store.PostgresStore, licenceStatus string) *store.Organization {
	t.Helper()
	ctx := context.Background()

	org := &store.Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      "Licence Test Org " + uuid.Must(uuid.NewV7()).String()[:8],
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, db.CreateOrg(ctx, org))

	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
	if licenceStatus == "expired" {
		expiresAt = time.Now().UTC().Add(-7 * 24 * time.Hour)
	}

	tl := &store.TenantLicence{
		OrgID:       org.ID,
		LicenceID:   "lic-" + uuid.Must(uuid.NewV7()).String()[:8],
		Token:       "tok-test",
		ActivatedAt: time.Now().UTC().Add(-24 * time.Hour),
		ExpiresAt:   expiresAt,
		Status:      licenceStatus,
	}
	require.NoError(t, db.UpsertTenantLicence(ctx, tl))

	return org
}

// ───────────────────────── TestIntegration_SetupFlow ─────────────────────────

// TestIntegration_SetupFlow verifies the full first-run setup lifecycle:
//  1. GET /api/v1/setup/status → needsSetup=true before any admin exists
//  2. POST /api/v1/setup → 201 with id + tempPassword
//  3. Second POST /api/v1/setup → 409 Conflict
//  4. GET /api/v1/setup/status → needsSetup=false after setup
func TestIntegration_SetupFlow(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	// 1. Before setup: needsSetup must be true.
	rrStatus := plReq(t, srv, http.MethodGet, "/api/v1/setup/status", "", nil)
	require.Equal(t, http.StatusOK, rrStatus.Code)
	var statusBefore map[string]bool
	require.NoError(t, json.NewDecoder(rrStatus.Body).Decode(&statusBefore))
	assert.True(t, statusBefore["needsSetup"], "needsSetup must be true before first setup")

	// 2. First POST /api/v1/setup → 201 with id + tempPassword.
	rrCreate := plReq(t, srv, http.MethodPost, "/api/v1/setup", "", map[string]string{
		"name":  "Alice Admin",
		"email": "alice.admin@example.com",
	})
	require.Equal(t, http.StatusCreated, rrCreate.Code, "first setup must return 201, body: %s", rrCreate.Body.String())
	var created map[string]string
	require.NoError(t, json.NewDecoder(rrCreate.Body).Decode(&created))
	assert.NotEmpty(t, created["id"], "response must include new user id")
	assert.NotEmpty(t, created["tempPassword"], "response must include tempPassword")

	// 3. Second POST /api/v1/setup → 409 Conflict.
	rrDup := plReq(t, srv, http.MethodPost, "/api/v1/setup", "", map[string]string{
		"name":  "Bob Duplicate",
		"email": "bob.dup@example.com",
	})
	assert.Equal(t, http.StatusConflict, rrDup.Code, "second setup call must return 409, body: %s", rrDup.Body.String())

	// 4. After setup: needsSetup must be false.
	rrStatusAfter := plReq(t, srv, http.MethodGet, "/api/v1/setup/status", "", nil)
	require.Equal(t, http.StatusOK, rrStatusAfter.Code)
	var statusAfter map[string]bool
	require.NoError(t, json.NewDecoder(rrStatusAfter.Body).Decode(&statusAfter))
	assert.False(t, statusAfter["needsSetup"], "needsSetup must be false after setup")
}

// ───────────────────────── TestIntegration_PlatformAdminLogin ────────────────

// TestIntegration_PlatformAdminLogin verifies that a platform admin created
// via POST /api/v1/setup can log in and receives a JWT with:
//   - role=platform_admin
//   - mcp=true (must change password on first login)
func TestIntegration_PlatformAdminLogin(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	// Create the first platform admin via setup.
	tempPassword, _ := doSetup(t, srv, "Alice Admin", "alice.platformlogin@example.com")

	// Login with the temp password.
	rrLogin := plReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "alice.platformlogin@example.com",
		"password": tempPassword,
	})
	require.Equal(t, http.StatusOK, rrLogin.Code, "platform admin login failed: %s", rrLogin.Body.String())

	var loginResp map[string]any
	require.NoError(t, json.NewDecoder(rrLogin.Body).Decode(&loginResp))

	token, ok := loginResp["token"].(string)
	require.True(t, ok, "login response must contain a token string")
	assert.NotEmpty(t, token)

	// The response-level mustChangePassword flag must be true.
	assert.Equal(t, true, loginResp["mustChangePassword"],
		"newly created platform admin must have mustChangePassword=true in login response")

	// Decode JWT payload (no sig verification needed — token was just issued).
	claims := decodeJWTPayload(t, token)

	// JWT role claim must be platform_admin.
	assert.Equal(t, "platform_admin", claims["role"],
		"JWT role claim must be platform_admin")

	// JWT mcp claim must be true (omitempty only omits when false).
	mcp, _ := claims["mcp"].(bool)
	assert.True(t, mcp, "JWT mcp claim must be true for a newly-setup admin")
}

// ───────────────────────── TestIntegration_TenantCreation ────────────────────

// TestIntegration_TenantCreation verifies that when the Licence Portal confirms
// a valid activation, the handler provisions the tenant org and persists the
// licence record so that subsequent list/get calls reflect the correct status.
//
// Note: the /api/v1/platform/* route group applies JWTAuth + RequirePlatformAdmin.
// JWTAuth includes a platform_admin carve-out so it doesn't block platform_admin
// tokens. However, it also enforces a session-table check (GetSessionByHash) that
// requires a live sessions row — which integration tests do not seed. We call
// handlers directly to bypass the session check while keeping the DB lifecycle
// (create org → store licence → list licence) as the integration concern.
func TestIntegration_TenantCreation(t *testing.T) {
	// Start a mock Licence Portal that returns a successful activation.
	activationJSON := `{
		"token":        "tok-integration-001",
		"activationID": "act-integration-001",
		"tier":         "enterprise",
		"seats":        10,
		"seatsUsed":    1,
		"expiresAt":    "` + time.Now().UTC().Add(365*24*time.Hour).Format(time.RFC3339) + `",
		"product_scope": "report"
	}`
	portal := mockLicencePortal(t, http.StatusCreated, activationJSON)

	srv, db := testServerWithLicencePortal(t, portal.URL)

	// Ensure the report_instance row exists so GetOrCreateInstance works.
	_, err := db.GetOrCreateInstance(context.Background())
	require.NoError(t, err)

	// POST /api/v1/platform/tenants — call the handler directly to bypass
	// the session-table check in JWTAuth (no live sessions row in this test).
	// This matches the pattern used by TestHandleCreatePlatformTenant_ValidLicence
	// in handlers_platform_test.go.
	body := map[string]string{
		"licenceKey": "LIC-INTEGRATION-001",
		"adminName":  "Tenant Admin",
		"adminEmail": "tenant.admin@example.com",
	}
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/platform/tenants", &buf)
	reqCreate.Header.Set("Content-Type", "application/json")
	rrCreate := httptest.NewRecorder()
	srv.handleCreatePlatformTenant(rrCreate, reqCreate)

	require.Equal(t, http.StatusCreated, rrCreate.Code, "tenant creation failed: %s", rrCreate.Body.String())

	var createResp map[string]any
	require.NoError(t, json.NewDecoder(rrCreate.Body).Decode(&createResp))
	assert.Equal(t, "active", createResp["licenceStatus"],
		"newly created tenant must have licenceStatus=active")
	tenantID, _ := createResp["id"].(string)
	assert.NotEmpty(t, tenantID, "response must include the new tenant org ID")
	assert.NotNil(t, createResp["expiresAt"], "response must include expiresAt")

	// GET /api/v1/platform/tenants — call the list handler directly to
	// verify the org and its licence status are persisted correctly.
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/platform/tenants", nil)
	rrList := httptest.NewRecorder()
	srv.handleListPlatformTenants(rrList, reqList)

	require.Equal(t, http.StatusOK, rrList.Code, "list tenants failed: %s", rrList.Body.String())

	var listResp []tenantResponse
	require.NoError(t, json.NewDecoder(rrList.Body).Decode(&listResp))
	require.NotEmpty(t, listResp, "tenant list must not be empty after creation")

	found := false
	for _, tenant := range listResp {
		if tenant.ID == tenantID {
			found = true
			assert.Equal(t, "active", tenant.LicenceStatus,
				"listed tenant must have licenceStatus=active")
			assert.NotNil(t, tenant.ExpiresAt, "listed tenant must have expiresAt set")
			break
		}
	}
	assert.True(t, found, "newly created tenant (id=%s) must appear in GET /platform/tenants", tenantID)
}

// ───────────────────────── TestIntegration_LicenceEnforcement ────────────────

// TestIntegration_LicenceEnforcement_GraceHeader verifies that when a tenant's
// licence status is "grace", API requests are allowed and carry
// X-Licence-Grace: true.
func TestIntegration_LicenceEnforcement_GraceHeader(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Seed an org with a grace licence.
	org := seedOrgWithLicence(t, db, "grace")

	// Create an org_admin user for that org so we have a valid JWT.
	_, user := createTestUserInOrg(t, db, org.ID, "org_admin", "grace-pw-1234567", false)
	token := doLogin(t, srv, user.Email, "grace-pw-1234567")

	// Make a request to a tenant-scoped route (GET /api/v1/scans).
	// The TenantLicenceGate middleware sits on the /api/v1 group and
	// will inspect the org ID from the JWT claims.
	rrScans := plReq(t, srv, http.MethodGet, "/api/v1/scans", token, nil)

	require.Equal(t, http.StatusOK, rrScans.Code,
		"grace licence must allow requests, body: %s", rrScans.Body.String())
	assert.Equal(t, "true", rrScans.Header().Get("X-Licence-Grace"),
		"grace licence response must carry X-Licence-Grace: true header")
}

// TestIntegration_LicenceEnforcement_ExpiredBlocks verifies that when a
// tenant's licence is "expired", API requests to tenant-scoped routes
// return 403 Forbidden.
func TestIntegration_LicenceEnforcement_ExpiredBlocks(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Seed an org with an expired licence.
	org := seedOrgWithLicence(t, db, "expired")

	// Create an org_admin user for that org.
	_, user := createTestUserInOrg(t, db, org.ID, "org_admin", "expired-pw-1234567", false)
	token := doLogin(t, srv, user.Email, "expired-pw-1234567")

	// Any request to a tenant-scoped route must be blocked.
	rrScans := plReq(t, srv, http.MethodGet, "/api/v1/scans", token, nil)

	assert.Equal(t, http.StatusForbidden, rrScans.Code,
		"expired licence must block requests with 403, body: %s", rrScans.Body.String())

	var errBody map[string]string
	_ = json.NewDecoder(rrScans.Body).Decode(&errBody)
	assert.Equal(t, "licence expired", errBody["error"],
		"403 response must carry 'licence expired' error message")
}
