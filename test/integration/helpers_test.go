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

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// requireDB creates a PostgresStore for integration testing.
// Connects to test PostgreSQL, truncates all data, registers cleanup.
// Skips the test if the database is unavailable.
func requireDB(t *testing.T) *store.PostgresStore {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
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

// requireServer creates a real TCP httptest.NewServer backed by PostgreSQL.
// Returns the server URL (no trailing slash) and the underlying store.
func requireServer(t *testing.T) (string, *store.PostgresStore) {
	t.Helper()
	db := requireDB(t)
	cfg := &server.Config{ListenAddr: ":0"}
	srv := server.New(cfg, db)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts.URL, db
}

// requireServerWithAuth creates a real TCP httptest.NewServer with API key auth.
func requireServerWithAuth(t *testing.T, keys []string) (string, *store.PostgresStore) {
	t.Helper()
	db := requireDB(t)
	cfg := &server.Config{
		ListenAddr: ":0",
		APIKeys:    keys,
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
	result := eng.Scan(context.Background(), progressCh)
	// Drain any remaining progress messages
	for range progressCh {
	}
	require.NotNil(t, result)
	return result
}

// fixturesDir returns the absolute path to test/fixtures/ relative to this file.
func fixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "fixtures")
}

// makeScanResult generates a synthetic ScanResult with nFindings findings.
// PQC statuses are distributed: 40% SAFE, 30% TRANSITIONAL, 20% DEPRECATED, 10% UNSAFE.
func makeScanResult(id, hostname string, nFindings int) *model.ScanResult {
	return makeScanResultWithPQC(id, hostname,
		nFindings*40/100,
		nFindings*30/100,
		nFindings*20/100,
		nFindings-nFindings*40/100-nFindings*30/100-nFindings*20/100,
	)
}

// makeScanResultWithPQC generates a ScanResult with exact PQC breakdown counts.
func makeScanResultWithPQC(id, hostname string, safe, trans, dep, unsafe int) *model.ScanResult {
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
		ID: id,
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
func submitScan(t *testing.T, serverURL, apiKey string, scan *model.ScanResult) string {
	t.Helper()
	body, err := json.Marshal(scan)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", serverURL+"/api/v1/scans", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Triton-API-Key", apiKey)
	}

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
