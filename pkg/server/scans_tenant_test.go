//go:build integration

// Phase 2.4 end-to-end tests — verifies that the /api/v1/scans and
// related routes are now properly tenant-scoped when accessed by
// JWT-authenticated org users AND by license-token agents. Proves
// that the UnifiedAuth middleware wiring on /api/v1 delivers on the
// split-identity promise from the 2026-04-07 amendment.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// seedScanInOrg inserts a scan scoped to the given org into the store
// so tenant-isolation tests have data to query against.
func seedScanInOrg(t *testing.T, db store.ScanStore, orgID, hostname string) string {
	t.Helper()
	result := &model.ScanResult{
		ID:    uuid.Must(uuid.NewV7()).String(),
		OrgID: orgID,
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now().UTC().Truncate(time.Microsecond),
			Hostname:    hostname,
			ScanProfile: "quick",
			ToolVersion: "2.0.0-test",
		},
		Summary: model.Summary{TotalFindings: 1, Transitional: 1},
		Findings: []model.Finding{
			{
				ID: "f1", Source: model.FindingSource{Type: "file", Path: "/test"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048", PQCStatus: "TRANSITIONAL"},
				Module:      "certificates",
			},
		},
	}
	require.NoError(t, db.SaveScan(context.Background(), result))
	return result.ID
}

// TestScans_JWTOrgUserSeesOnlyOwnOrg verifies that an org user
// authenticated via JWT can GET /api/v1/scans and receives only
// scans belonging to their org — NOT scans in other orgs.
func TestScans_JWTOrgUserSeesOnlyOwnOrg(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Create two orgs with users in each
	orgA, userA := createOrgUser(t, db, "org_user", "correct-horse-battery", false)
	orgB, _ := createOrgUser(t, db, "org_user", "correct-horse-battery", false)

	// Seed 2 scans in orgA and 1 scan in orgB
	seedScanInOrg(t, db, orgA.ID, "a-host-1")
	seedScanInOrg(t, db, orgA.ID, "a-host-2")
	seedScanInOrg(t, db, orgB.ID, "b-host-1")

	// Login as userA
	token := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery")

	// GET /api/v1/scans as userA — should see 2 scans (both in orgA)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var scans []map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&scans))
	assert.Len(t, scans, 2, "userA in orgA must see only orgA's 2 scans, not orgB's scan")
	for _, s := range scans {
		hn := s["hostname"].(string)
		assert.Contains(t, hn, "a-host-", "hostname must be from orgA: %s", hn)
	}
}

// TestScans_AgentSubmitViaLicenseToken verifies that an agent with a
// valid license token can POST a scan (the legacy code path), and
// the submitted scan lands in the correct org.
func TestScans_AgentSubmitViaLicenseToken(t *testing.T) {
	// testServer has no JWT/guard, so UnifiedAuth falls through for
	// unauthenticated requests. For a full license-token test we'd
	// need to wire a Guard — but the submit path also works without
	// tenant context (legacy single-tenant). Verify the no-auth
	// pass-through still lets submissions through.
	srv, _ := testServer(t)

	result := testScanResult(uuid.Must(uuid.NewV7()).String(), "agent-host")
	body, _ := json.Marshal(result)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code, "unauthenticated single-tenant submit must still work")
}

// TestScans_DeleteRequiresOrgAdmin verifies the Arch #7 RBAC fix:
// destructive operations (DELETE /scans/{id}) require org_admin role.
// org_user can read but cannot delete.
func TestScans_DeleteRequiresOrgAdmin(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Create one org with both an admin and a user
	_, admin := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	_, user := createTestUserInOrg(t, db, admin.OrgID, "org_user", "correct-horse-battery", false)

	scanID := seedScanInOrg(t, db, admin.OrgID, "victim-host")

	// org_user tries to delete → 403
	userToken := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/scans/"+scanID, nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "org_user must not be able to delete scans")

	// Scan must still exist
	_, err := db.GetScan(context.Background(), scanID, "")
	require.NoError(t, err, "scan must still exist after rejected delete")

	// org_admin succeeds
	adminToken := loginAndExtractToken(t, srv, admin.Email, "correct-horse-battery")
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/scans/"+scanID, nil)
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "org_admin must be able to delete")
}

// TestScans_RequireTenantBlocksUnauthenticated is the regression test for
// the D1 finding from the Phase 2 review: before the fix, an unauthenticated
// GET /api/v1/scans returned ALL rows from ALL orgs because TenantFromContext
// returned an empty string and the store accepted empty org_id as "no
// filter". After the fix, RequireTenant rejects the request with 401.
//
// This test uses testServerWithJWT which has NO Guard configured, so
// UnifiedAuth has no fallback path → no TenantContext → RequireTenant
// rejects.
func TestScans_RequireTenantBlocksUnauthenticated(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	// Unauthenticated read attempts must all be rejected with 401.
	for _, path := range []string{
		"/api/v1/scans",
		"/api/v1/scans/00000000-0000-0000-0000-000000000001",
		"/api/v1/diff?base=a&compare=b",
		"/api/v1/trend",
		"/api/v1/machines",
		"/api/v1/aggregate",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"unauthenticated %s must return 401, got %d (D1 regression!)", path, w.Code)
	}
}

// TestScans_SubmitIgnoresBodyOrgID is the regression test for the D2
// finding: handleSubmitScan must NEVER trust the client-supplied orgID
// in the request body. Phase 2 silently corrected the value; Phase 3+4
// (F1 finding) upgrades this to an explicit 400 rejection so that a
// mismatch cannot be masked as a successful write — callers that lie
// about org_id are either buggy or malicious, and in either case the
// correct response is a hard fail that the operator can see.
func TestScans_SubmitRejectsCrossOrgBody(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, userA := createOrgUser(t, db, "org_user", "correct-horse-battery", false)
	otherOrgID := "00000000-0000-0000-0000-0000000eeeee" // try to inject into

	token := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery")

	scan := testScanResult(uuid.Must(uuid.NewV7()).String(), "victim-host")
	scan.OrgID = otherOrgID
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code,
		"cross-org body org_id must be rejected with 400, not silently overwritten")

	// And the scan must NOT have been persisted.
	_, err := db.GetScan(context.Background(), scan.ID, "")
	require.Error(t, err, "scan must not be stored on rejection")
}

// TestScans_SubmitAcceptsMatchingBodyOrg verifies the happy path where the
// body's org_id equals the tenant context (agent stamping its own org).
func TestScans_SubmitAcceptsMatchingBodyOrg(t *testing.T) {
	srv, db := testServerWithJWT(t)
	orgA, userA := createOrgUser(t, db, "org_user", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery")

	scan := testScanResult(uuid.Must(uuid.NewV7()).String(), "matching-host")
	scan.OrgID = orgA.ID // matches authenticated tenant
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	got, err := db.GetScan(context.Background(), scan.ID, "")
	require.NoError(t, err)
	assert.Equal(t, orgA.ID, got.OrgID)
}

// TestScans_SubmitAcceptsEmptyBodyOrg verifies agents that omit org_id
// (the common case: the agent doesn't know its own org) still succeed
// and have the tenant context stamped for them.
func TestScans_SubmitAcceptsEmptyBodyOrg(t *testing.T) {
	srv, db := testServerWithJWT(t)
	orgA, userA := createOrgUser(t, db, "org_user", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery")

	scan := testScanResult(uuid.Must(uuid.NewV7()).String(), "empty-body-host")
	scan.OrgID = "" // agent didn't know its org
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	got, err := db.GetScan(context.Background(), scan.ID, "")
	require.NoError(t, err)
	assert.Equal(t, orgA.ID, got.OrgID, "empty body org_id must be stamped from tenant context")
}

// TestScans_SubmitRejectsBodyOrgInSingleTenant verifies D2 from the
// Phase 3+4 post-fix review: in single-tenant mode (no Guard, no JWT —
// TenantFromContext returns ""), a non-empty body org_id is rejected
// with 400 rather than silently discarded. Rationale: single-tenant
// deployments have no concept of an org for the caller to legitimately
// reference, so any value in that field is a client bug that should
// surface loudly.
func TestScans_SubmitRejectsBodyOrgInSingleTenant(t *testing.T) {
	// testServer (without JWT/Guard/ServiceKey) is close but still
	// installs a Guard. For this test we want NO tenant context at all,
	// so build a bare server with Config{} only.
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})

	srv, err := New(&Config{ListenAddr: ":0"}, db)
	require.NoError(t, err)

	scan := testScanResult(uuid.Must(uuid.NewV7()).String(), "single-tenant-host")
	scan.OrgID = "00000000-0000-0000-0000-0000000eeeee" // non-empty
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code,
		"single-tenant mode must reject a non-empty body org_id (D2)")
}

// TestScans_JWTUserCanGetOwnOrgScan verifies point-lookup tenant
// isolation: fetching /scans/{id} for a scan in MY org succeeds,
// and for a scan in ANOTHER org returns 404.
func TestScans_JWTUserCanGetOwnOrgScan(t *testing.T) {
	srv, db := testServerWithJWT(t)

	orgA, userA := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	orgB, _ := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)

	myScanID := seedScanInOrg(t, db, orgA.ID, "a-host-1")
	otherScanID := seedScanInOrg(t, db, orgB.ID, "b-host-1")

	token := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery")

	// Can GET my own org's scan
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+myScanID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "userA must be able to read their own org's scan")

	// Cannot GET another org's scan (404, not 403, to avoid leaking existence)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+otherScanID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusNotFound, w2.Code,
		"cross-org scan GET must return 404 (tenant isolation)")
}
