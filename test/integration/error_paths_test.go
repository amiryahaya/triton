//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// F1: Non-existent path → no crash, empty findings
func TestError_ScanInvalidTarget(t *testing.T) {
	cfg := config.Load("quick")
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: "/nonexistent/path/that/does/not/exist", Depth: 3},
	}
	cfg.Modules = []string{"certificates", "keys"}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 100)
	result := eng.Scan(context.Background(), progressCh)

	require.NotNil(t, result, "should return a result even for invalid target")
	// No crash = success; findings may be empty
}

// F2: Bad DB URL → NewPostgresStore returns error
func TestError_StoreUnavailable(t *testing.T) {
	ctx := context.Background()
	_, err := store.NewPostgresStore(ctx, "postgres://baduser:badpass@localhost:59999/nonexistent?sslmode=disable&connect_timeout=2")
	assert.Error(t, err, "should fail with bad DB URL")
}

// F3: >10MB POST → server returns 413 or 400
func TestError_OversizedPayload(t *testing.T) {
	serverURL, _ := requireServer(t)

	// Create a huge payload
	bigData := strings.Repeat("x", 11*1024*1024) // 11MB
	resp, err := http.Post(serverURL+"/api/v1/scans", "application/json", strings.NewReader(bigData))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should reject with 400 or 413
	assert.True(t, resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusRequestEntityTooLarge,
		"should reject oversized payload, got %d", resp.StatusCode)
}

// F4: Bad JSON to all POST endpoints → 400
func TestError_MalformedJSON(t *testing.T) {
	serverURL, _ := requireServer(t)

	endpoints := []string{
		"/api/v1/scans",
		"/api/v1/policy/evaluate",
	}

	for _, ep := range endpoints {
		resp, err := http.Post(serverURL+ep, "application/json", strings.NewReader("{invalid json"))
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"endpoint %s should return 400 for malformed JSON", ep)
	}
}

// F5: Cancel after first module → partial results, clean return
func TestError_ContextCancelMidScan(t *testing.T) {
	cfg := config.Load("standard")
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 10},
	}
	cfg.Modules = []string{"certificates", "keys", "libraries", "binaries", "scripts", "webapp"}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	ctx, cancel := context.WithCancel(context.Background())
	progressCh := make(chan scanner.Progress, 200)

	// Cancel after the first progress event to ensure scan has started
	go func() {
		select {
		case <-progressCh:
		case <-time.After(5 * time.Second):
		}
		cancel()
		for range progressCh {
		}
	}()

	result := eng.Scan(ctx, progressCh)
	require.NotNil(t, result, "should return result on cancellation")
	// Result may have partial findings, that's fine
}

// F6: POST policy/evaluate with bad YAML → 400
func TestError_InvalidPolicyYAML(t *testing.T) {
	serverURL, _ := requireServer(t)

	// First submit a scan so we have something to evaluate
	s := makeScanResult("", "err-host", 5)
	submitScan(t, serverURL, "", s)

	body := fmt.Sprintf(`{"scanID":"%s","policyYAML":"this is not : valid : yaml : ["}`, s.ID)
	resp, err := http.Post(serverURL+"/api/v1/policy/evaluate", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// F7: Zero-finding scan → GET returns empty array (not null)
func TestError_EmptyScan(t *testing.T) {
	serverURL, _ := requireServer(t)

	scanID := uuid.Must(uuid.NewV7()).String()
	emptyScan := &model.ScanResult{
		ID: scanID,
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now().UTC().Truncate(time.Microsecond),
			Hostname:    "empty-host",
			ScanProfile: "quick",
			ToolVersion: "2.4.0-test",
		},
		Findings: []model.Finding{},
		Summary:  model.Summary{TotalFindings: 0},
	}
	submitScan(t, serverURL, "", emptyScan)

	// Get findings
	resp, err := http.Get(serverURL + "/api/v1/scans/" + scanID + "/findings")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var findings []model.Finding
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&findings))
	assert.NotNil(t, findings, "should return empty array, not null")
	assert.Empty(t, findings)
}

// F8: Diff base==compare → valid diff with 0 added/removed/changed
func TestError_DiffSameScan(t *testing.T) {
	serverURL, _ := requireServer(t)

	s := makeScanResult("", "diff-host", 10)
	submitScan(t, serverURL, "", s)

	resp, err := http.Get(fmt.Sprintf("%s/api/v1/diff?base=%s&compare=%s", serverURL, s.ID, s.ID))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var d diff.ScanDiff
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&d))
	assert.Equal(t, 0, d.Summary.AddedCount)
	assert.Equal(t, 0, d.Summary.RemovedCount)
	assert.Equal(t, 0, d.Summary.ChangedCount)
}

// F9: GET /scans/nonexistent → 404
func TestError_ScanNotFound(t *testing.T) {
	serverURL, _ := requireServer(t)

	// Use a valid UUID format that doesn't exist in the DB
	fakeID := uuid.Must(uuid.NewV7()).String()
	resp, err := http.Get(serverURL + "/api/v1/scans/" + fakeID)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// F10: GET /reports/nonexistent/json → 404
func TestError_ReportNonexistentScan(t *testing.T) {
	serverURL, _ := requireServer(t)

	fakeID := uuid.Must(uuid.NewV7()).String()
	resp, err := http.Get(serverURL + "/api/v1/reports/" + fakeID + "/json")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
