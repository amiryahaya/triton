//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// testDBURL returns the PostgreSQL connection URL for integration tests.
// It checks TRITON_TEST_DB_URL first, falling back to the default local URL.
func testDBURL() string {
	if u := os.Getenv("TRITON_TEST_DB_URL"); u != "" {
		return u
	}
	return "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
}

// requireDB creates a PostgresStore for integration testing.
// Connects to test PostgreSQL, truncates all data, registers cleanup.
// Skips the test if the database is unavailable.
func requireDB(t *testing.T) *store.PostgresStore {
	t.Helper()
	dbURL := testDBURL()
	ctx := context.Background()
	s, err := store.NewPostgresStore(ctx, dbURL)
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

// testOrgID is the org ID used by requireServer's single-tenant Guard
// so Phase 2's RequireTenant middleware is satisfied without any
// per-request auth. Matches the testOrgID used by pkg/server's unit
// tests for consistency.
const testOrgID = "00000000-0000-0000-0000-000000000abc"

// requireServer creates a real TCP httptest.NewServer backed by PostgreSQL.
// Returns the server URL (no trailing slash) and the underlying store.
// Configures a single-tenant Guard so data routes work without requiring
// per-request authentication.
func requireServer(t *testing.T) (string, *store.PostgresStore) {
	t.Helper()
	db := requireDB(t)

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	lic := &license.License{
		ID:        "integration-test",
		Tier:      license.TierEnterprise,
		OrgID:     testOrgID,
		Org:       "IntegrationTest",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, pub)

	cfg := &server.Config{
		ListenAddr: ":0",
		Guard:      guard,
	}
	srv := server.New(cfg, db)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts.URL, db
}

// requireServerWithAuth was removed in Phase 4 — API key auth no longer
// exists. Tests that previously used it should either use requireServer
// (unauthenticated single-tenant) or build a server with a license-token
// Guard if they need a tenant context. See pkg/server tests for the
// license-token auth path.

// requireServerWithGuard creates a real TCP httptest.NewServer with licence enforcement.
// Generates an ephemeral keypair, issues a token for the given tier, and configures the
// server's LicenceGate middleware accordingly. The license also includes an OrgID so
// Phase 2's RequireTenant middleware is satisfied via the guard fallback.
func requireServerWithGuard(t *testing.T, tier license.Tier) (string, *store.PostgresStore) {
	t.Helper()
	db := requireDB(t)

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	lic := &license.License{
		ID:        "integration-tier-test",
		Tier:      tier,
		OrgID:     testOrgID,
		Org:       "IntegrationTest",
		Seats:     1,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, pub)

	cfg := &server.Config{
		ListenAddr: ":0",
		Guard:      guard,
	}
	srv := server.New(cfg, db)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts.URL, db
}

// scanFixtures runs a real scan against test/fixtures/ with the given profile and modules.
func scanFixtures(t *testing.T, profile string, mods []string) *model.ScanResult {
	t.Helper()
	cfg := config.Load(profile)
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
	}
	if len(mods) > 0 {
		cfg.Modules = mods
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 500)
	go func() {
		for range progressCh {
		}
	}()
	result := eng.Scan(context.Background(), progressCh)
	require.NotNil(t, result)
	return result
}

// fixturesDir returns the absolute path to test/fixtures/ relative to this file.
func fixturesDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed: cannot determine fixtures directory")
	}
	return filepath.Join(filepath.Dir(filename), "..", "fixtures")
}

// makeScanResult generates a synthetic ScanResult with nFindings findings.
// If id is not a valid UUID, a new UUIDv7 is generated automatically.
// PQC statuses are distributed: 40% SAFE, 30% TRANSITIONAL, 20% DEPRECATED, 10% UNSAFE.
func makeScanResult(id, hostname string, nFindings int) *model.ScanResult {
	if _, err := uuid.Parse(id); err != nil {
		id = uuid.Must(uuid.NewV7()).String()
	}
	return makeScanResultWithPQC(id, hostname,
		nFindings*40/100,
		nFindings*30/100,
		nFindings*20/100,
		nFindings-nFindings*40/100-nFindings*30/100-nFindings*20/100,
	)
}

// makeScanResultWithPQC generates a ScanResult with exact PQC breakdown counts.
// If id is not a valid UUID, a new UUIDv7 is generated automatically.
func makeScanResultWithPQC(id, hostname string, safe, trans, dep, unsafe int) *model.ScanResult {
	if _, err := uuid.Parse(id); err != nil {
		id = uuid.Must(uuid.NewV7()).String()
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	total := safe + trans + dep + unsafe

	findings := make([]model.Finding, 0, total)
	idx := 0

	addFindings := func(count int, status, algo string, category int) {
		for i := 0; i < count; i++ {
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("f-%s-%d", id, idx),
				Category: category,
				Source: model.FindingSource{
					Type: "file",
					Path: fmt.Sprintf("/test/path/%s/%d", status, idx),
				},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: algo,
					PQCStatus: status,
					KeySize:   256,
					Function:  "encryption",
				},
				Module:     "certificates",
				Confidence: 0.95,
				Timestamp:  now,
			})
			idx++
		}
	}

	addFindings(safe, "SAFE", "ML-KEM-768", 5)
	addFindings(trans, "TRANSITIONAL", "RSA-2048", 5)
	addFindings(dep, "DEPRECATED", "SHA-1", 5)
	addFindings(unsafe, "UNSAFE", "DES", 5)

	return &model.ScanResult{
		ID:    id,
		OrgID: testOrgID, // matches the single-tenant Guard configured by requireServer
		Metadata: model.ScanMetadata{
			Timestamp:   now,
			Hostname:    hostname,
			OS:          runtime.GOOS,
			ScanProfile: "quick",
			ToolVersion: "2.4.0-test",
		},
		Findings: findings,
		Summary: model.Summary{
			TotalFindings:     total,
			TotalCryptoAssets: total,
			Safe:              safe,
			Transitional:      trans,
			Deprecated:        dep,
			Unsafe:            unsafe,
		},
	}
}

// submitScan POSTs a scan to the server and asserts a 201 response. Returns the scan ID.
// The second parameter (formerly apiKey) is now unused and kept for signature
// compatibility with call sites that still pass "". Will be removed in a
// follow-up cleanup.
func submitScan(t *testing.T, serverURL, _ string, scan *model.ScanResult) string {
	t.Helper()
	body, err := json.Marshal(scan)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", serverURL+"/api/v1/scans", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "submit scan failed: %s", string(respBody))

	return scan.ID
}

// getScan GETs a scan from the server and asserts a 200 response. Returns the result.
func getScan(t *testing.T, serverURL, scanID string) *model.ScanResult {
	t.Helper()
	resp, err := http.Get(serverURL + "/api/v1/scans/" + scanID)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result model.ScanResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return &result
}

// assertFileValid asserts that the file at the given path exists, is non-empty,
// and contains all of the specified strings.
func assertFileValid(t *testing.T, path string, contains ...string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "file should exist: %s", path)
	require.True(t, info.Size() > 0, "file should be non-empty: %s", path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, s := range contains {
		require.Contains(t, string(data), s, "file %s should contain %q", path, s)
	}
}
