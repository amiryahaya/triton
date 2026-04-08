//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// ============================================================
// Part 1: Store-level tenant isolation (4 tests)
// ============================================================

// T1: GetScan with correct orgID succeeds; wrong orgID returns ErrNotFound.
func TestTenantIsolation_GetScan_OrgFilter(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	orgAlpha := uuid.Must(uuid.NewV7()).String()
	orgBeta := uuid.Must(uuid.NewV7()).String()

	scan := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-a", 5)
	scan.OrgID = orgAlpha
	require.NoError(t, db.SaveScan(ctx, scan))

	// Correct org — must succeed.
	got, err := db.GetScan(ctx, scan.ID, orgAlpha)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, got.ID)

	// Wrong org — must return ErrNotFound.
	_, err = db.GetScan(ctx, scan.ID, orgBeta)
	var nf *store.ErrNotFound
	assert.True(t, errors.As(err, &nf), "wrong orgID should return ErrNotFound, got: %v", err)

	// Empty org (standalone mode) — must succeed (no filter applied).
	got, err = db.GetScan(ctx, scan.ID, "")
	require.NoError(t, err)
	assert.Equal(t, scan.ID, got.ID)
}

// T2: DeleteScan with wrong orgID does not delete the scan.
func TestTenantIsolation_DeleteScan_OrgFilter(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	orgAlpha := uuid.Must(uuid.NewV7()).String()
	orgBeta := uuid.Must(uuid.NewV7()).String()

	scan := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-a", 5)
	scan.OrgID = orgAlpha
	require.NoError(t, db.SaveScan(ctx, scan))

	// Delete with wrong org — must fail.
	err := db.DeleteScan(ctx, scan.ID, orgBeta)
	var nf *store.ErrNotFound
	assert.True(t, errors.As(err, &nf), "delete with wrong orgID should return ErrNotFound")

	// Scan must still exist.
	got, err := db.GetScan(ctx, scan.ID, orgAlpha)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, got.ID)

	// Delete with correct org — must succeed.
	require.NoError(t, db.DeleteScan(ctx, scan.ID, orgAlpha))

	// Scan must be gone.
	_, err = db.GetScan(ctx, scan.ID, "")
	assert.True(t, errors.As(err, &nf))
}

// T3: ListScans with OrgID filter returns only matching scans.
func TestTenantIsolation_ListScans_OrgFilter(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	orgAlpha := uuid.Must(uuid.NewV7()).String()
	orgBeta := uuid.Must(uuid.NewV7()).String()

	scanA := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-a", 5)
	scanA.OrgID = orgAlpha
	scanB := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-b", 5)
	scanB.OrgID = orgBeta
	scanC := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-c", 5)
	// scanC has no org (standalone)

	require.NoError(t, db.SaveScan(ctx, scanA))
	require.NoError(t, db.SaveScan(ctx, scanB))
	require.NoError(t, db.SaveScan(ctx, scanC))

	// Filter by org-alpha — only scanA.
	summaries, err := db.ListScans(ctx, store.ScanFilter{OrgID: orgAlpha})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, scanA.ID, summaries[0].ID)

	// Filter by org-beta — only scanB.
	summaries, err = db.ListScans(ctx, store.ScanFilter{OrgID: orgBeta})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, scanB.ID, summaries[0].ID)

	// No filter — all 3.
	summaries, err = db.ListScans(ctx, store.ScanFilter{})
	require.NoError(t, err)
	assert.Len(t, summaries, 3)
}

// T4: GetScan with NULL org_id and non-empty orgID filter returns ErrNotFound.
func TestTenantIsolation_GetScan_NullOrgNotMatchedByFilter(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	scan := makeScanResult(uuid.Must(uuid.NewV7()).String(), "host-a", 5)
	// OrgID is "" → stored as SQL NULL
	require.NoError(t, db.SaveScan(ctx, scan))

	// Filter with a specific org — NULL org_id must NOT match.
	_, err := db.GetScan(ctx, scan.ID, uuid.Must(uuid.NewV7()).String())
	var nf *store.ErrNotFound
	assert.True(t, errors.As(err, &nf), "scan with NULL org should not match org filter")
}

// ============================================================
// Part 2: HTTP-level tenant isolation (5 tests)
// ============================================================

// requireTenantServer creates a platform server with TenantScope middleware enabled.
// Uses the license server to create two orgs and issue activated tokens.
// Returns: platformURL, tokenA, tokenB, orgA-ID, orgB-ID.
func requireTenantServer(t *testing.T) (platformURL, tokenA, tokenB string) {
	t.Helper()

	licServerURL, _, pub, _ := requireLicenseServer(t)

	// Create two orgs with licenses (use different org names via tier param).
	orgAID, licAID := createOrgAndLicenseWithTier(t, licServerURL, "enterprise", 5, 365)
	_, licBID := createOrgAndLicenseWithTier(t, licServerURL, "pro", 5, 365)

	// Activate and get tokens (tokens contain OrgID from license server).
	tokenA = activateAndGetToken(t, licServerURL, licAID)
	tokenB = activateAndGetToken(t, licServerURL, licBID)

	// Create platform server with a guard from org-A's token (single-tenant fallback)
	// and the ephemeral public key for per-request token verification.
	guard := license.NewGuardFromToken(tokenA, pub)
	require.Equal(t, orgAID, guard.OrgID(), "guard should have org-A's ID")

	db := requireDB(t)
	cfg := &server.Config{
		ListenAddr:   ":0",
		Guard:        guard,
		TenantPubKey: pub,
	}
	srv, err := server.New(cfg, db)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	platformURL = ts.URL
	return
}

// submitScanWithToken POSTs a scan to the server with a license token header.
func submitScanWithToken(t *testing.T, serverURL, token string, scan *model.ScanResult) int {
	t.Helper()
	body, err := json.Marshal(scan)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", serverURL+"/api/v1/scans", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-License-Token", token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

// httpGetWithToken performs a GET with the license token header and returns status + body.
func httpGetWithToken(t *testing.T, url, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("X-Triton-License-Token", token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// httpDeleteWithToken performs a DELETE with the license token header.
func httpDeleteWithToken(t *testing.T, url, token string) int {
	t.Helper()
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)
	req.Header.Set("X-Triton-License-Token", token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

// T5: Org-A submits a scan; Org-B cannot read it via GET /scans/{id}.
func TestTenantIsolation_HTTP_GetScan_CrossTenant(t *testing.T) {
	platformURL, tokenA, tokenB := requireTenantServer(t)

	scanID := uuid.Must(uuid.NewV7()).String()
	scan := makeScanResult(scanID, "host-a", 5)
	status := submitScanWithToken(t, platformURL, tokenA, scan)
	require.Equal(t, http.StatusCreated, status)

	// Org-A can read its own scan.
	code, _ := httpGetWithToken(t, platformURL+"/api/v1/scans/"+scanID, tokenA)
	assert.Equal(t, http.StatusOK, code, "org-A should read its own scan")

	// Org-B cannot read org-A's scan.
	code, _ = httpGetWithToken(t, platformURL+"/api/v1/scans/"+scanID, tokenB)
	assert.Equal(t, http.StatusNotFound, code, "org-B must NOT read org-A's scan")
}

// T6: Org-B cannot delete Org-A's scan.
func TestTenantIsolation_HTTP_DeleteScan_CrossTenant(t *testing.T) {
	platformURL, tokenA, tokenB := requireTenantServer(t)

	scanID := uuid.Must(uuid.NewV7()).String()
	scan := makeScanResult(scanID, "host-a", 5)
	status := submitScanWithToken(t, platformURL, tokenA, scan)
	require.Equal(t, http.StatusCreated, status)

	// Org-B tries to delete org-A's scan — must fail.
	code := httpDeleteWithToken(t, platformURL+"/api/v1/scans/"+scanID, tokenB)
	assert.Equal(t, http.StatusNotFound, code, "org-B must NOT delete org-A's scan")

	// Org-A can still read the scan (it was not deleted).
	code, _ = httpGetWithToken(t, platformURL+"/api/v1/scans/"+scanID, tokenA)
	assert.Equal(t, http.StatusOK, code, "scan should still exist after failed cross-tenant delete")
}

// T7: ListScans returns only the requesting org's scans.
func TestTenantIsolation_HTTP_ListScans_CrossTenant(t *testing.T) {
	platformURL, tokenA, tokenB := requireTenantServer(t)

	scanAID := uuid.Must(uuid.NewV7()).String()
	scanBID := uuid.Must(uuid.NewV7()).String()
	scanA := makeScanResult(scanAID, "host-a", 5)
	scanB := makeScanResult(scanBID, "host-b", 5)
	require.Equal(t, http.StatusCreated, submitScanWithToken(t, platformURL, tokenA, scanA))
	require.Equal(t, http.StatusCreated, submitScanWithToken(t, platformURL, tokenB, scanB))

	// Org-A lists — should see only its scan.
	code, body := httpGetWithToken(t, platformURL+"/api/v1/scans", tokenA)
	require.Equal(t, http.StatusOK, code)
	var summariesA []store.ScanSummary
	require.NoError(t, json.Unmarshal(body, &summariesA))
	assert.Len(t, summariesA, 1, "org-A should see only 1 scan")
	assert.Equal(t, scanAID, summariesA[0].ID)

	// Org-B lists — should see only its scan.
	code, body = httpGetWithToken(t, platformURL+"/api/v1/scans", tokenB)
	require.Equal(t, http.StatusOK, code)
	var summariesB []store.ScanSummary
	require.NoError(t, json.Unmarshal(body, &summariesB))
	assert.Len(t, summariesB, 1, "org-B should see only 1 scan")
	assert.Equal(t, scanBID, summariesB[0].ID)
}

// T8: GetFindings is tenant-isolated.
func TestTenantIsolation_HTTP_GetFindings_CrossTenant(t *testing.T) {
	platformURL, tokenA, tokenB := requireTenantServer(t)

	scanID := uuid.Must(uuid.NewV7()).String()
	scan := makeScanResult(scanID, "host-a", 5)
	require.Equal(t, http.StatusCreated, submitScanWithToken(t, platformURL, tokenA, scan))

	// Org-A can get findings.
	code, _ := httpGetWithToken(t, platformURL+"/api/v1/scans/"+scanID+"/findings", tokenA)
	assert.Equal(t, http.StatusOK, code)

	// Org-B cannot get findings for org-A's scan.
	code, _ = httpGetWithToken(t, platformURL+"/api/v1/scans/"+scanID+"/findings", tokenB)
	assert.Equal(t, http.StatusNotFound, code, "org-B must NOT access org-A's findings")
}

// T9: Invalid token is rejected with 401.
func TestTenantIsolation_HTTP_InvalidToken_Rejected(t *testing.T) {
	platformURL, _, _ := requireTenantServer(t)

	scanID := uuid.Must(uuid.NewV7()).String()
	scan := makeScanResult(scanID, "host-a", 5)
	status := submitScanWithToken(t, platformURL, "not-a-valid-token", scan)
	assert.Equal(t, http.StatusUnauthorized, status, "invalid token should be rejected")
}
