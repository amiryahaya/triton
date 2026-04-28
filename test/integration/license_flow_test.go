//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// --- Helpers ---

// createOrgAndLicenseWithTier creates an org and license with configurable tier and days.
func createOrgAndLicenseWithTier(t *testing.T, serverURL, tier string, seats, days int) (orgID, licID string) {
	t.Helper()
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/orgs", map[string]string{
		"name":          "FlowTest-" + tier + "-" + t.Name(),
		"contact_name":  "Flow Test Contact",
		"contact_email": "flowtest@example.com",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var orgResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgResult))
	resp.Body.Close()
	orgObj, ok := orgResult["org"].(map[string]any)
	require.True(t, ok, "org creation response missing 'org' key: %v", orgResult)
	orgID = orgObj["id"].(string)

	resp = licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": tier, "seats": seats, "days": days,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var licResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licResult))
	resp.Body.Close()
	licID = licResult["id"].(string)
	return
}

// activateAndGetToken activates the current machine via the license server client
// and returns the signed token.
func activateAndGetToken(t *testing.T, serverURL, licenseID string) string {
	t.Helper()
	client := license.NewServerClient(serverURL)
	actResp, err := client.Activate(licenseID)
	require.NoError(t, err)
	require.NotEmpty(t, actResp.Token)
	return actResp.Token
}

// requireServerWithExternalGuard creates a platform server with an externally-created Guard.
func requireServerWithExternalGuard(t *testing.T, guard *license.Guard) (string, *store.PostgresStore) {
	t.Helper()
	db := requireDB(t)
	cfg := &server.Config{
		ListenAddr:        ":0",
		Guard:             guard,
		DisableSetupGuard: true,
	}
	srv, err := server.New(cfg, db)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts.URL, db
}

// ============================================================
// Part 1: License Server → Standalone Client (5 tests)
// ============================================================

func TestLicenseFlow_Standalone_ProGuard(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, serverURL, "pro", 5, 365)
	token := activateAndGetToken(t, serverURL, licID)

	guard := license.NewGuardFromToken(token, pub)

	// Assert tier
	assert.Equal(t, license.TierPro, guard.Tier())
	require.NotNil(t, guard.License())

	// Assert pro features allowed
	for _, f := range []license.Feature{
		license.FeatureDiff, license.FeatureTrend, license.FeatureDB,
		license.FeaturePolicyBuiltin, license.FeatureProfileStandard,
		license.FeatureProfileComprehensive,
	} {
		assert.True(t, guard.Allowed(f), "pro should allow %s", f)
	}

	// Assert enterprise-only features blocked
	for _, f := range []license.Feature{
		license.FeatureServerMode, license.FeatureAgentMode,
		license.FeaturePolicyCustom,
	} {
		assert.False(t, guard.Allowed(f), "pro should block %s", f)
	}

	// Assert formats: json/html/pdf/csv allowed; cdx/xlsx/sarif blocked for pro
	assert.NoError(t, guard.EnforceFormat("json"))
	assert.NoError(t, guard.EnforceFormat("html"))
	assert.NoError(t, guard.EnforceFormat("pdf"))
	assert.NoError(t, guard.EnforceFormat("csv"))
	assert.Error(t, guard.EnforceFormat("cdx"))
	assert.Error(t, guard.EnforceFormat("xlsx"))
	assert.Error(t, guard.EnforceFormat("sarif"))

	// Assert FilterConfig: pro keeps comprehensive profile but restricts modules
	// to the pro-tier allowed set (intersection of comprehensive + allowed).
	cfg := scannerconfig.Load("comprehensive")
	guard.FilterConfig(cfg)
	assert.Equal(t, "comprehensive", cfg.Profile)
	proAllowed := make(map[string]bool)
	for _, m := range license.AllowedModules(license.TierPro) {
		proAllowed[m] = true
	}
	for _, m := range cfg.Modules {
		assert.True(t, proAllowed[m], "module %q should be allowed for pro tier", m)
	}
}

func TestLicenseFlow_Standalone_EnterpriseGuard(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, serverURL, "enterprise", 100, 365)
	token := activateAndGetToken(t, serverURL, licID)

	guard := license.NewGuardFromToken(token, pub)

	// Assert tier
	assert.Equal(t, license.TierEnterprise, guard.Tier())

	// Assert ALL features allowed
	for _, f := range []license.Feature{
		license.FeatureDiff, license.FeatureTrend, license.FeatureDB,
		license.FeaturePolicyBuiltin, license.FeaturePolicyCustom,
		license.FeatureServerMode, license.FeatureAgentMode,
		license.FeatureProfileStandard, license.FeatureProfileComprehensive,
	} {
		assert.True(t, guard.Allowed(f), "enterprise should allow %s", f)
	}

	// Assert enterprise formats (html/pdf/csv/json/sarif allowed; cdx/xlsx not in compat set)
	for _, fmt := range []string{"json", "html", "pdf", "csv", "sarif"} {
		assert.NoError(t, guard.EnforceFormat(fmt), "enterprise should allow format %s", fmt)
	}

	// Assert FilterConfig preserves everything
	cfg := scannerconfig.Load("comprehensive")
	cfg.DBUrl = "postgres://triton:triton@localhost:5434/triton?sslmode=disable"
	guard.FilterConfig(cfg)
	assert.Equal(t, "comprehensive", cfg.Profile)
	compProfile, _ := scannerconfig.GetProfile("comprehensive")
	assert.Equal(t, len(compProfile.Modules), len(cfg.Modules))
	assert.NotEmpty(t, cfg.DBUrl)
}

func TestLicenseFlow_Standalone_FreeGuard(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, serverURL, "free", 1, 365)
	token := activateAndGetToken(t, serverURL, licID)

	guard := license.NewGuardFromToken(token, pub)

	// Assert tier
	assert.Equal(t, license.TierFree, guard.Tier())

	// Assert FilterConfig restricts to free tier
	cfg := scannerconfig.Load("comprehensive")
	cfg.DBUrl = "postgres://triton:triton@localhost:5434/triton?sslmode=disable"
	guard.FilterConfig(cfg)
	assert.Equal(t, "quick", cfg.Profile)
	assert.Len(t, cfg.Modules, 4)
	expected := map[string]bool{"certificates": true, "keys": true, "packages": true, "ldif": true}
	for _, m := range cfg.Modules {
		assert.True(t, expected[m], "unexpected module for free tier: %s", m)
	}
	assert.Empty(t, cfg.DBUrl)

	// Assert features blocked
	for _, f := range []license.Feature{
		license.FeatureDiff, license.FeatureTrend,
		license.FeatureDB, license.FeatureServerMode,
	} {
		assert.False(t, guard.Allowed(f), "free should block %s", f)
	}

	// Assert formats: only json allowed
	assert.NoError(t, guard.EnforceFormat("json"))
	assert.Error(t, guard.EnforceFormat("cdx"))
	assert.Error(t, guard.EnforceFormat("html"))
	assert.Error(t, guard.EnforceFormat("sarif"))
}

func TestLicenseFlow_Standalone_ScanPipeline(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, serverURL, "pro", 5, 365)
	token := activateAndGetToken(t, serverURL, licID)

	guard := license.NewGuardFromToken(token, pub)

	// Load config and apply guard filtering
	cfg := scannerconfig.Load("standard")
	guard.FilterConfig(cfg)

	// Scan fixtures with fast modules
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
	}
	cfg.Modules = []string{"certificates", "keys", "packages"}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 500)
	go func() {
		for range progressCh {
		}
	}()
	result := eng.Scan(context.Background(), progressCh)
	require.NotNil(t, result)
	assert.Greater(t, len(result.Findings), 0, "scan should produce findings")

	// Generate allowed reports
	outDir := t.TempDir()
	gen := report.New(outDir)

	jsonFile := filepath.Join(outDir, "report.json")
	require.NoError(t, gen.GenerateTritonJSON(result, jsonFile))
	assertFileValid(t, jsonFile, "findings")

	cdxFile := filepath.Join(outDir, "report.cdx.json")
	require.NoError(t, gen.GenerateCycloneDXBOM(result, cdxFile))
	assertFileValid(t, cdxFile, "bomFormat")

	htmlFile := filepath.Join(outDir, "report.html")
	require.NoError(t, gen.GenerateHTML(result, htmlFile))
	assertFileValid(t, htmlFile, "<html")

	// SARIF blocked by licence guard
	assert.Error(t, guard.EnforceFormat("sarif"))
}

func TestLicenseFlow_Standalone_RevokedLicense(t *testing.T) {
	serverURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, serverURL, "enterprise", 5, 365)
	token := activateAndGetToken(t, serverURL, licID)

	// Confirm enterprise tier before revocation
	guard := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierEnterprise, guard.Tier())

	// Revoke the license
	resp := licAdminReq(t, "POST", serverURL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Online validate should report invalid/revoked
	client := license.NewServerClient(serverURL)
	valResp, err := client.Validate(licID, token)
	require.NoError(t, err)
	assert.False(t, valResp.Valid)
	assert.Contains(t, valResp.Reason, "validation failed")

	// Offline parse still succeeds (signature is valid, not expired)
	lic, err := license.Parse(token, pub)
	require.NoError(t, err)
	assert.Equal(t, license.TierEnterprise, lic.Tier)

	// Offline guard still returns enterprise (cannot detect revocation offline)
	offlineGuard := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierEnterprise, offlineGuard.Tier())
}

// ============================================================
// Part 2: License Server → Platform Server → Clients (6 tests)
// ============================================================

func TestLicenseFlow_Platform_ProRouteAccess(t *testing.T) {
	licServerURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "pro", 5, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	guard := license.NewGuardFromToken(token, pub)
	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Seed 2 scans (set OrgID to match guard so tenant-scoped queries find them)
	s1 := makeScanResult("", "flow-host", 5)
	s1.OrgID = guard.OrgID()
	s2 := makeScanResult("", "flow-host", 5)
	s2.OrgID = guard.OrgID()
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Diff should succeed (pro allows)
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", platformURL, s1.ID, s2.ID))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access /diff")

	// Trend should succeed
	resp, err = http.Get(platformURL + "/api/v1/trend?hostname=flow-host")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access /trend")

	// JSON report should succeed
	resp, err = http.Get(platformURL + "/api/v1/reports/" + s1.ID + "/json")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access JSON report")

	// SARIF report should be blocked
	resp, err = http.Get(platformURL + "/api/v1/reports/" + s1.ID + "/sarif")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "pro should be blocked from SARIF")
}

func TestLicenseFlow_Platform_FreeRouteBlocking(t *testing.T) {
	licServerURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "free", 1, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	guard := license.NewGuardFromToken(token, pub)
	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Seed 2 scans (set OrgID to match guard so tenant-scoped queries find them)
	s1 := makeScanResult("", "flow-host", 5)
	s1.OrgID = guard.OrgID()
	s2 := makeScanResult("", "flow-host", 5)
	s2.OrgID = guard.OrgID()
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Diff should be blocked
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", platformURL, s1.ID, s2.ID))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "free should be blocked from /diff")
	assert.Contains(t, string(body), "higher licence tier")

	// Trend should be blocked
	resp, err = http.Get(platformURL + "/api/v1/trend?hostname=flow-host")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "free should be blocked from /trend")

	// Scans should be accessible (unrestricted route)
	resp, err = http.Get(platformURL + "/api/v1/scans")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "free should access /scans")
}

func TestLicenseFlow_Platform_EnterpriseAllRoutes(t *testing.T) {
	licServerURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "enterprise", 100, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	guard := license.NewGuardFromToken(token, pub)
	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Seed 2 scans with PQC findings (set OrgID to match guard)
	s1 := makeScanResultWithPQC("", "flow-host", 2, 1, 1, 1)
	s1.OrgID = guard.OrgID()
	s2 := makeScanResultWithPQC("", "flow-host", 1, 2, 1, 1)
	s2.OrgID = guard.OrgID()
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Diff should succeed
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", platformURL, s1.ID, s2.ID))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access /diff")

	// Trend should succeed
	resp, err = http.Get(platformURL + "/api/v1/trend?hostname=flow-host")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access /trend")

	// SARIF report should succeed
	resp, err = http.Get(platformURL + "/api/v1/reports/" + s1.ID + "/sarif")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access SARIF report")

	// Builtin policy should succeed
	resp = postJSON(t, platformURL+"/api/v1/policy/evaluate", map[string]string{
		"scanID": s1.ID, "policyName": "nacsa-2030",
	})
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access builtin policy")

	// Custom policy should succeed
	customPolicy := `name: test-policy
version: "1.0"
rules:
  - id: test-rule
    description: "Test rule"
    match:
      pqcStatus: UNSAFE
    action: flag
`
	resp = postJSON(t, platformURL+"/api/v1/policy/evaluate", map[string]string{
		"scanID": s1.ID, "policyYAML": customPolicy,
	})
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access custom policy")
}

func TestLicenseFlow_Platform_ProBlocksCustomPolicy(t *testing.T) {
	licServerURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "pro", 5, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	guard := license.NewGuardFromToken(token, pub)
	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Seed scan with PQC findings (set OrgID to match guard)
	s1 := makeScanResultWithPQC("", "flow-host", 2, 1, 1, 1)
	s1.OrgID = guard.OrgID()
	require.NoError(t, db.SaveScan(context.Background(), s1))

	// Builtin policy should succeed
	resp := postJSON(t, platformURL+"/api/v1/policy/evaluate", map[string]string{
		"scanID": s1.ID, "policyName": "nacsa-2030",
	})
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access builtin policy")

	// Custom policy should be blocked
	customPolicy := `name: test-policy
version: "1.0"
rules:
  - id: test-rule
    description: "Test rule"
    match:
      pqcStatus: UNSAFE
    action: flag
`
	resp = postJSON(t, platformURL+"/api/v1/policy/evaluate", map[string]string{
		"scanID": s1.ID, "policyYAML": customPolicy,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "pro should be blocked from custom policy")
	assert.Contains(t, string(body), "higher licence tier")
}

func TestLicenseFlow_Platform_WrongPubKeyDegrades(t *testing.T) {
	licServerURL, _, _, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "enterprise", 100, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	// Create guard with wrong public key
	wrongPub, _, err := license.GenerateKeypair()
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, wrongPub)

	// Should degrade to free tier
	assert.Equal(t, license.TierFree, guard.Tier())

	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Seed 2 scans (guard is free tier from wrong key — OrgID is empty, no tenant scoping)
	s1 := makeScanResult("", "flow-host", 5)
	s2 := makeScanResult("", "flow-host", 5)
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Diff should be blocked (degraded to free)
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", platformURL, s1.ID, s2.ID))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "wrong pub key should block /diff")

	// Trend should be blocked
	resp, err = http.Get(platformURL + "/api/v1/trend?hostname=flow-host")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "wrong pub key should block /trend")

	// Scans requires auth — degraded guard has empty OrgID so unauthenticated
	// requests get 401 (RequireTenant not satisfied without a valid org binding).
	resp, err = http.Get(platformURL + "/api/v1/scans")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong pub key: unauthenticated /scans must return 401")
}

func TestLicenseFlow_FullCrossComponent(t *testing.T) {
	// Phase 0: License server issues token
	licServerURL, _, pub, _ := requireLicenseServer(t)
	_, licID := createOrgAndLicenseWithTier(t, licServerURL, "pro", 5, 365)
	token := activateAndGetToken(t, licServerURL, licID)

	guard := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierPro, guard.Tier())

	// Phase A: Standalone scan with license-gated config
	cfg := scannerconfig.Load("standard")
	guard.FilterConfig(cfg)
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
	}
	cfg.Modules = []string{"certificates", "keys", "packages"}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 500)
	go func() {
		for range progressCh {
		}
	}()
	scanResult := eng.Scan(context.Background(), progressCh)
	require.NotNil(t, scanResult)
	assert.Greater(t, len(scanResult.Findings), 0, "scan should produce findings")

	// Assign a stable hostname for storage (ID is already a valid UUID from scanner)
	scanResult.Metadata.Hostname = "flow-cross-host"

	// Phase B: Platform server receives scan result
	platformURL, db := requireServerWithExternalGuard(t, guard)

	// Submit scan result from Phase A
	submitScan(t, platformURL, scanResult)

	// Submit a second synthetic scan for diff/trend (set OrgID to match guard)
	s2 := makeScanResult("", "flow-cross-host", 5)
	s2.OrgID = guard.OrgID()
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Retrieve scan
	got := getScan(t, platformURL, scanResult.ID)
	assert.Equal(t, "flow-cross-host", got.Metadata.Hostname)

	// Diff should succeed (pro allows)
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", platformURL, scanResult.ID, s2.ID))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access /diff")

	// Trend should succeed
	resp, err = http.Get(platformURL + "/api/v1/trend?hostname=flow-cross-host")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access /trend")

	// JSON report should succeed
	resp, err = http.Get(platformURL + "/api/v1/reports/" + scanResult.ID + "/json")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "pro should access JSON report")

	// SARIF report should be blocked (pro blocks)
	resp, err = http.Get(platformURL + "/api/v1/reports/" + scanResult.ID + "/sarif")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "pro should block SARIF report")
}
