//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// generateTestToken creates an ephemeral Ed25519 keypair and issues a signed
// licence token for the given tier. Returns the token and public key.
func generateTestToken(t *testing.T, tier license.Tier, org string, seats, days int) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	token, err := license.IssueToken(priv, tier, org, seats, days)
	require.NoError(t, err)
	return token, pub
}

// generateExpiredToken creates a token with ExpiresAt set 24 hours in the past
// (well beyond the 5-minute grace period).
func generateExpiredToken(t *testing.T, tier license.Tier) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "expired-test",
		Tier:      tier,
		Org:       "Expired Corp",
		Seats:     100,
		IssuedAt:  time.Now().Add(-48 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(), // expired 24h ago
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	return token, pub
}

// --- Test 1: Free tier FilterConfig ---

func TestLicenseTier_FreeTierFilterConfig(t *testing.T) {
	token, pub := generateTestToken(t, license.TierFree, "FreeOrg", 1, 365)
	guard := license.NewGuardFromToken(token, pub)

	assert.Equal(t, license.TierFree, guard.Tier())

	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)

	// Free tier downgrades to quick
	assert.Equal(t, "quick", cfg.Profile)

	// Free tier allows only 3 modules
	assert.Len(t, cfg.Modules, 3)
	expected := map[string]bool{"certificates": true, "keys": true, "packages": true}
	for _, m := range cfg.Modules {
		assert.True(t, expected[m], "unexpected module for free tier: %s", m)
	}

	// Seats default to 1
	assert.Equal(t, 1, guard.Seats())
}

// --- Test 2: Pro tier FilterConfig ---

func TestLicenseTier_ProTierFilterConfig(t *testing.T) {
	token, pub := generateTestToken(t, license.TierPro, "ProOrg", 25, 365)
	guard := license.NewGuardFromToken(token, pub)

	assert.Equal(t, license.TierPro, guard.Tier())

	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)

	// Pro tier preserves comprehensive profile
	assert.Equal(t, "comprehensive", cfg.Profile)

	// Pro tier allows all modules (nil from AllowedModules = no filtering)
	compProfile, _ := config.GetProfile("comprehensive")
	assert.Equal(t, len(compProfile.Modules), len(cfg.Modules), "pro tier should keep all modules")

	// Pro tier blocks SARIF format
	err := guard.EnforceFormat("sarif")
	assert.Error(t, err)
	var gated *license.ErrFeatureGated
	assert.True(t, errors.As(err, &gated))
	assert.Equal(t, license.FeatureFormatSARIF, gated.Feature)

	// Pro tier allows JSON, CDX, HTML
	assert.NoError(t, guard.EnforceFormat("json"))
	assert.NoError(t, guard.EnforceFormat("cdx"))
	assert.NoError(t, guard.EnforceFormat("html"))
}

// --- Test 3: Enterprise tier unlocks everything ---

func TestLicenseTier_EnterpriseTierUnlocksEverything(t *testing.T) {
	token, pub := generateTestToken(t, license.TierEnterprise, "EntCorp", 500, 365)
	guard := license.NewGuardFromToken(token, pub)

	assert.Equal(t, license.TierEnterprise, guard.Tier())

	// All profiles allowed
	for _, p := range []string{"quick", "standard", "comprehensive"} {
		assert.NoError(t, guard.EnforceProfile(p), "enterprise should allow profile: %s", p)
	}

	// All formats allowed including SARIF
	for _, f := range []string{"json", "cdx", "html", "xlsx", "sarif"} {
		assert.NoError(t, guard.EnforceFormat(f), "enterprise should allow format: %s", f)
	}

	// All features allowed
	allFeatures := []license.Feature{
		license.FeatureServerMode, license.FeatureAgentMode,
		license.FeatureMetrics, license.FeatureIncremental,
		license.FeatureDiff, license.FeatureTrend,
		license.FeatureDB, license.FeaturePolicyBuiltin, license.FeaturePolicyCustom,
	}
	for _, f := range allFeatures {
		assert.True(t, guard.Allowed(f), "enterprise should allow feature: %s", f)
	}

	// All modules preserved
	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)
	compProfile, _ := config.GetProfile("comprehensive")
	assert.Equal(t, len(compProfile.Modules), len(cfg.Modules))

	// Seats and org correct
	assert.Equal(t, 500, guard.Seats())
	assert.Equal(t, "EntCorp", guard.License().Org)
}

// --- Test 4: Pro tier feature enforcement ---

func TestLicenseTier_ProEnforceFeatures(t *testing.T) {
	token, pub := generateTestToken(t, license.TierPro, "ProOrg", 10, 365)
	guard := license.NewGuardFromToken(token, pub)

	// Pro-allowed features
	allowed := []license.Feature{
		license.FeatureDiff, license.FeatureTrend,
		license.FeatureMetrics, license.FeatureDB,
		license.FeaturePolicyBuiltin,
	}
	for _, f := range allowed {
		assert.NoError(t, guard.EnforceFeature(f), "pro should allow: %s", f)
	}

	// Pro-blocked features
	blocked := []license.Feature{
		license.FeatureServerMode, license.FeatureAgentMode,
		license.FeaturePolicyCustom,
	}
	for _, f := range blocked {
		err := guard.EnforceFeature(f)
		assert.Error(t, err, "pro should block: %s", f)
		var gated *license.ErrFeatureGated
		assert.True(t, errors.As(err, &gated))
		assert.Equal(t, f, gated.Feature)
		assert.Equal(t, license.TierPro, gated.Tier)
	}
}

// --- Test 5: Enterprise tier feature enforcement ---

func TestLicenseTier_EnterpriseEnforceFeatures(t *testing.T) {
	token, pub := generateTestToken(t, license.TierEnterprise, "NACSA", 100, 365)
	guard := license.NewGuardFromToken(token, pub)

	// Enterprise-exclusive features all allowed
	exclusive := []license.Feature{
		license.FeatureServerMode, license.FeatureAgentMode,
		license.FeaturePolicyCustom, license.FeatureFormatSARIF,
	}
	for _, f := range exclusive {
		assert.NoError(t, guard.EnforceFeature(f), "enterprise should allow: %s", f)
	}

	// Verify licence metadata
	lic := guard.License()
	require.NotNil(t, lic)
	assert.Equal(t, "NACSA", lic.Org)
	assert.Equal(t, 100, lic.Seats)
	assert.Equal(t, license.TierEnterprise, lic.Tier)
	assert.False(t, lic.IsExpired())
}

// --- Test 6: Expired token degrades to free ---

func TestLicenseTier_ExpiredTokenDegradesToFree(t *testing.T) {
	token, pub := generateExpiredToken(t, license.TierEnterprise)
	guard := license.NewGuardFromToken(token, pub)

	// Degraded to free tier
	assert.Equal(t, license.TierFree, guard.Tier())

	// Licence is nil for free tier
	assert.Nil(t, guard.License())

	// Config downgraded
	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)
	assert.Equal(t, "quick", cfg.Profile)
	assert.Len(t, cfg.Modules, 3)
}

// --- Test 7: Tampered token degrades to free ---

func TestLicenseTier_TamperedTokenDegradesToFree(t *testing.T) {
	token, pub := generateTestToken(t, license.TierPro, "ProOrg", 10, 365)

	// Tamper with the claims: decode, modify, re-encode (without re-signing)
	parts := splitToken(t, token)
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	claims["tier"] = "enterprise"
	claims["seats"] = 9999

	modifiedJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	tamperedClaims := base64.RawURLEncoding.EncodeToString(modifiedJSON)
	tamperedToken := tamperedClaims + "." + parts[1] // original signature

	guard := license.NewGuardFromToken(tamperedToken, pub)

	// Signature mismatch → free tier
	assert.Equal(t, license.TierFree, guard.Tier())
	assert.Nil(t, guard.License())
}

// --- Test 8: Wrong key degrades to free ---

func TestLicenseTier_WrongKeyDegradesToFree(t *testing.T) {
	token, _ := generateTestToken(t, license.TierEnterprise, "EntCorp", 100, 365)

	// Generate a different keypair
	differentPub, _, err := license.GenerateKeypair()
	require.NoError(t, err)

	guard := license.NewGuardFromToken(token, differentPub)

	// Wrong key → free tier
	assert.Equal(t, license.TierFree, guard.Tier())
	assert.Nil(t, guard.License())
}

// --- Test 9: Pro scan pipeline ---

func TestLicenseTier_ProScanPipeline(t *testing.T) {
	token, pub := generateTestToken(t, license.TierPro, "ProOrg", 10, 365)
	guard := license.NewGuardFromToken(token, pub)

	// Load comprehensive and apply guard filtering
	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)
	assert.Equal(t, "comprehensive", cfg.Profile) // Pro allows comprehensive

	// Scan fixtures with pro-allowed modules
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
	}
	// Restrict to fast modules for test speed
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

	// Generate allowed reports (JSON, CDX, HTML)
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

	// SARIF should be blocked by licence guard
	err := guard.EnforceFormat("sarif")
	assert.Error(t, err)
}

// --- Test 10: Enterprise scan pipeline with SARIF ---

func TestLicenseTier_EnterpriseScanPipelineWithSARIF(t *testing.T) {
	token, pub := generateTestToken(t, license.TierEnterprise, "EntCorp", 500, 365)
	guard := license.NewGuardFromToken(token, pub)

	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)

	// Scan fixtures
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

	// Enterprise allows SARIF
	assert.NoError(t, guard.EnforceFormat("sarif"))

	outDir := t.TempDir()
	gen := report.New(outDir)

	sarifFile := filepath.Join(outDir, "report.sarif")
	require.NoError(t, gen.GenerateSARIF(result, sarifFile))
	assertFileValid(t, sarifFile, "$schema", "results")

	// Verify all other formats also work
	jsonFile := filepath.Join(outDir, "report.json")
	require.NoError(t, gen.GenerateTritonJSON(result, jsonFile))

	cdxFile := filepath.Join(outDir, "report.cdx.json")
	require.NoError(t, gen.GenerateCycloneDXBOM(result, cdxFile))

	htmlFile := filepath.Join(outDir, "report.html")
	require.NoError(t, gen.GenerateHTML(result, htmlFile))

	// Verify all files are valid
	for _, f := range []string{jsonFile, cdxFile, htmlFile, sarifFile} {
		info, err := os.Stat(f)
		require.NoError(t, err, "file should exist: %s", f)
		assert.True(t, info.Size() > 0, "file should be non-empty: %s", f)
	}
}

// --- Test 11: Pro "all" format generates only allowed formats ---

func TestLicenseTier_ProAllowedFormats(t *testing.T) {
	allowed := license.AllowedFormats(license.TierPro)
	assert.Contains(t, allowed, "json")
	assert.Contains(t, allowed, "cdx")
	assert.Contains(t, allowed, "html")
	assert.Contains(t, allowed, "xlsx")
	assert.NotContains(t, allowed, "sarif", "Pro tier should not include SARIF")
}

// --- Test 12: Server middleware blocks free tier from /diff ---

func TestLicenseTier_ServerMiddlewareBlocksFreeDiff(t *testing.T) {
	serverURL, db := requireServerWithGuard(t, license.TierFree)

	// Seed two scans so diff has valid targets
	s1 := makeScanResult("diff-free-1", "host-a", 5)
	s2 := makeScanResult("diff-free-2", "host-a", 5)
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	resp, err := http.Get(serverURL + "/api/v1/diff?base=diff-free-1&compare=diff-free-2")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "free tier should be blocked from /diff")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "higher licence tier")
}

// --- Test 13: Server middleware blocks free tier from /trend ---

func TestLicenseTier_ServerMiddlewareBlocksFreeTrend(t *testing.T) {
	serverURL, _ := requireServerWithGuard(t, license.TierFree)

	resp, err := http.Get(serverURL + "/api/v1/trend?hostname=host-a")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "free tier should be blocked from /trend")
}

// --- Test 14: Enterprise server allows diff and trend ---

func TestLicenseTier_ServerMiddlewareAllowsEnterprise(t *testing.T) {
	serverURL, db := requireServerWithGuard(t, license.TierEnterprise)

	s1 := makeScanResult("diff-ent-1", "host-a", 5)
	s2 := makeScanResult("diff-ent-2", "host-a", 5)
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	// Diff should succeed
	resp, err := http.Get(serverURL + "/api/v1/diff?base=diff-ent-1&compare=diff-ent-2")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "enterprise should access /diff")

	// Trend should succeed
	resp2, err := http.Get(serverURL + "/api/v1/trend?hostname=host-a")
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "enterprise should access /trend")
}

// --- Test 15: Pro server blocks SARIF report format ---

func TestLicenseTier_ServerBlocksSarifForPro(t *testing.T) {
	serverURL, db := requireServerWithGuard(t, license.TierPro)

	scan := makeScanResult("rpt-pro-sarif", "host-a", 3)
	require.NoError(t, db.SaveScan(context.Background(), scan))

	// SARIF should be blocked
	resp, err := http.Get(serverURL + "/api/v1/reports/rpt-pro-sarif/sarif")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "pro tier should not get SARIF")

	// JSON should be allowed
	resp2, err := http.Get(serverURL + "/api/v1/reports/rpt-pro-sarif/json")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "pro tier should get JSON")
}

// --- Test 16: Free tier FilterConfig clears DBUrl ---

func TestLicenseTier_FreeTierClearsDBUrl(t *testing.T) {
	token, pub := generateTestToken(t, license.TierFree, "FreeOrg", 1, 365)
	guard := license.NewGuardFromToken(token, pub)

	cfg := config.Load("comprehensive")
	cfg.DBUrl = "postgres://triton:triton@localhost:5434/triton?sslmode=disable"

	guard.FilterConfig(cfg)

	assert.Empty(t, cfg.DBUrl, "free tier FilterConfig should clear DBUrl")
	assert.Equal(t, "quick", cfg.Profile, "free tier should downgrade profile")
}

// --- Test 17: Pro tier FilterConfig preserves DBUrl ---

func TestLicenseTier_ProTierPreservesDBUrl(t *testing.T) {
	token, pub := generateTestToken(t, license.TierPro, "ProOrg", 10, 365)
	guard := license.NewGuardFromToken(token, pub)

	dbURL := "postgres://triton:triton@localhost:5434/triton?sslmode=disable"
	cfg := config.Load("standard")
	cfg.DBUrl = dbURL

	guard.FilterConfig(cfg)

	assert.Equal(t, dbURL, cfg.DBUrl, "pro tier FilterConfig should preserve DBUrl")
}

// --- Test 18: Machine-bound token mismatch degrades full pipeline ---

func TestLicenseTier_MachineMismatchDegradesToFreePipeline(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	// Create a token bound to a fake machine fingerprint
	lic := &license.License{
		ID:        "wrong-machine",
		Tier:      license.TierEnterprise,
		Org:       "EntCorp",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		MachineID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)

	// Guard should degrade to free tier
	guard := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierFree, guard.Tier(), "machine mismatch should degrade to free")

	// Full pipeline: config should be restricted to free tier
	cfg := config.Load("comprehensive")
	cfg.DBUrl = "postgres://localhost:5434/triton?sslmode=disable"
	guard.FilterConfig(cfg)

	assert.Equal(t, "quick", cfg.Profile, "degraded guard should force quick profile")
	assert.Len(t, cfg.Modules, 3, "degraded guard should restrict to 3 modules")
	assert.Empty(t, cfg.DBUrl, "degraded guard should clear DBUrl")

	// Enterprise features should be blocked
	assert.Error(t, guard.EnforceFeature(license.FeatureServerMode))
	assert.Error(t, guard.EnforceFeature(license.FeatureDiff))
	assert.Error(t, guard.EnforceFormat("sarif"))
}

// --- Test 19: Machine-bound token match succeeds full pipeline ---

func TestLicenseTier_MachineMatchSucceedsPipeline(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	// Create a token bound to THIS machine
	lic := &license.License{
		ID:        "correct-machine",
		Tier:      license.TierEnterprise,
		Org:       "EntCorp",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		MachineID: license.MachineFingerprint(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)

	guard := license.NewGuardFromToken(token, pub)
	assert.Equal(t, license.TierEnterprise, guard.Tier(), "matching machine should preserve tier")

	// Full pipeline: config should be unrestricted
	cfg := config.Load("comprehensive")
	dbURL := "postgres://localhost:5434/triton?sslmode=disable"
	cfg.DBUrl = dbURL
	guard.FilterConfig(cfg)

	assert.Equal(t, "comprehensive", cfg.Profile)
	compProfile, _ := config.GetProfile("comprehensive")
	assert.Equal(t, len(compProfile.Modules), len(cfg.Modules))
	assert.Equal(t, dbURL, cfg.DBUrl, "enterprise should keep DBUrl")

	// All features available
	assert.NoError(t, guard.EnforceFeature(license.FeatureServerMode))
	assert.NoError(t, guard.EnforceFeature(license.FeatureDiff))
	assert.NoError(t, guard.EnforceFormat("sarif"))
}

// splitToken splits a licence token into its claims and signature parts.
func splitToken(t *testing.T, token string) [2]string {
	t.Helper()
	for i, c := range token {
		if c == '.' {
			return [2]string{token[:i], token[i+1:]}
		}
	}
	t.Fatal("invalid token format: no dot separator")
	return [2]string{}
}
