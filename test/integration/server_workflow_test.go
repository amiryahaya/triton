//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/store"
)

// B1: POST scan1 → POST scan2 → GET diff → verify added/removed/changed
func TestWorkflow_SubmitRetrieveDiff(t *testing.T) {
	serverURL, _ := requireServer(t)

	s1 := makeScanResultWithPQC("wf-diff-base", "host-a", 3, 2, 1, 0)
	s1.Metadata.Timestamp = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s1)

	// Add an extra finding in scan2
	s2 := makeScanResultWithPQC("wf-diff-compare", "host-a", 4, 2, 1, 0)
	s2.Metadata.Timestamp = time.Now().UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s2)

	resp, err := http.Get(serverURL + "/api/v1/diff?base=wf-diff-base&compare=wf-diff-compare")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var d diff.ScanDiff
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&d))
	assert.Equal(t, "wf-diff-base", d.BaseID)
	assert.Equal(t, "wf-diff-compare", d.CompareID)
	// Scans have 6 vs 7 findings with different paths, so there should be differences
	totalChanges := d.Summary.AddedCount + d.Summary.RemovedCount + d.Summary.ChangedCount
	assert.True(t, totalChanges > 0, "diff should detect additions between scans with different finding counts")
}

// B2: POST 5 scans → GET trend → verify chronological points
func TestWorkflow_SubmitMultipleGetTrend(t *testing.T) {
	serverURL, _ := requireServer(t)

	base := time.Now().Add(-5 * time.Hour).UTC()
	for i := 0; i < 5; i++ {
		s := makeScanResultWithPQC(
			fmt.Sprintf("wf-trend-%d", i), "trend-host",
			10+i, 5, 3, 2-min(i, 2),
		)
		s.Metadata.Timestamp = base.Add(time.Duration(i) * time.Hour).Truncate(time.Microsecond)
		submitScan(t, serverURL, "", s)
	}

	resp, err := http.Get(serverURL + "/api/v1/trend?hostname=trend-host&last=10")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var trend struct {
		Points []json.RawMessage `json:"points"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&trend))
	assert.Len(t, trend.Points, 5, "should have 5 trend points")
}

// B3: POST scan → POST policy/evaluate → verify verdict
func TestWorkflow_SubmitThenPolicyEvaluate(t *testing.T) {
	serverURL, _ := requireServer(t)

	s := makeScanResultWithPQC("wf-policy", "policy-host", 5, 3, 2, 1)
	submitScan(t, serverURL, "", s)

	body := `{"scanID":"wf-policy","policyName":"nacsa-2030"}`
	resp, err := http.Post(serverURL+"/api/v1/policy/evaluate", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "verdict")
}

// B4: POST scan → GET reports/{id}/json → Content-Disposition + valid JSON
func TestWorkflow_SubmitThenGenerateReport(t *testing.T) {
	serverURL, _ := requireServer(t)

	s := makeScanResult("wf-report", "report-host", 10)
	submitScan(t, serverURL, "", s)

	resp, err := http.Get(serverURL + "/api/v1/reports/wf-report/json")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	assert.True(t, json.Valid(respBody), "response should be valid JSON")
}

// B5: Full chain: POST scan1 → POST scan2 → GET diff → GET trend → POST policy → GET report
func TestWorkflow_FullChain(t *testing.T) {
	serverURL, _ := requireServer(t)

	s1 := makeScanResultWithPQC("wf-chain-1", "chain-host", 5, 3, 2, 1)
	s1.Metadata.Timestamp = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s1)

	s2 := makeScanResultWithPQC("wf-chain-2", "chain-host", 7, 2, 1, 0)
	s2.Metadata.Timestamp = time.Now().UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s2)

	// Diff
	resp, err := http.Get(serverURL + "/api/v1/diff?base=wf-chain-1&compare=wf-chain-2")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Trend
	resp, err = http.Get(serverURL + "/api/v1/trend?hostname=chain-host&last=5")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Policy
	body := `{"scanID":"wf-chain-2","policyName":"nacsa-2030"}`
	resp, err = http.Post(serverURL+"/api/v1/policy/evaluate", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Report
	resp, err = http.Get(serverURL + "/api/v1/reports/wf-chain-2/json")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// B6: POST 3 scans (2 hosts) → GET machines → GET aggregate → machineCount=2
func TestWorkflow_MachineAggregation(t *testing.T) {
	serverURL, _ := requireServer(t)

	submitScan(t, serverURL, "", makeScanResult("wf-machine-1", "host-alpha", 5))
	submitScan(t, serverURL, "", makeScanResult("wf-machine-2", "host-alpha", 5))
	submitScan(t, serverURL, "", makeScanResult("wf-machine-3", "host-beta", 5))

	// List machines
	resp, err := http.Get(serverURL + "/api/v1/machines")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var machines []store.ScanSummary
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&machines))
	assert.Len(t, machines, 2, "should have 2 unique machines")

	// Aggregate
	resp2, err := http.Get(serverURL + "/api/v1/aggregate")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var agg map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&agg))
	assert.Equal(t, float64(2), agg["machineCount"])
}

// B7: POST scan → DELETE → GET returns 404
func TestWorkflow_DeleteAndVerify(t *testing.T) {
	serverURL, _ := requireServer(t)

	submitScan(t, serverURL, "", makeScanResult("wf-delete", "del-host", 5))

	// DELETE
	req, err := http.NewRequest("DELETE", serverURL+"/api/v1/scans/wf-delete", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// GET should 404
	resp, err = http.Get(serverURL + "/api/v1/scans/wf-delete")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// B8: POST scan → POST same ID updated → GET returns updated findings
func TestWorkflow_UpsertScan(t *testing.T) {
	serverURL, _ := requireServer(t)

	s := makeScanResultWithPQC("wf-upsert", "upsert-host", 2, 1, 0, 0)
	submitScan(t, serverURL, "", s)

	// Submit again with updated summary
	s.Summary.Safe = 10
	s.Summary.TotalFindings = 10
	submitScan(t, serverURL, "", s)

	got := getScan(t, serverURL, "wf-upsert")
	assert.Equal(t, 10, got.Summary.Safe, "should reflect updated data after upsert")
}

// B9: POST 4 scans (diff hosts/profiles) → filter by hostname → filter by profile
func TestWorkflow_ListWithFilters(t *testing.T) {
	serverURL, _ := requireServer(t)

	s1 := makeScanResult("wf-filter-1", "filter-host-a", 5)
	s1.Metadata.ScanProfile = "quick"
	s1.Metadata.Timestamp = time.Now().Add(-4 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s1)

	s2 := makeScanResult("wf-filter-2", "filter-host-a", 5)
	s2.Metadata.ScanProfile = "standard"
	s2.Metadata.Timestamp = time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s2)

	s3 := makeScanResult("wf-filter-3", "filter-host-b", 5)
	s3.Metadata.ScanProfile = "quick"
	s3.Metadata.Timestamp = time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s3)

	s4 := makeScanResult("wf-filter-4", "filter-host-b", 5)
	s4.Metadata.ScanProfile = "comprehensive"
	s4.Metadata.Timestamp = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Microsecond)
	submitScan(t, serverURL, "", s4)

	// Filter by hostname
	resp, err := http.Get(serverURL + "/api/v1/scans?hostname=filter-host-a")
	require.NoError(t, err)
	defer resp.Body.Close()

	var summaries []store.ScanSummary
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&summaries))
	assert.Len(t, summaries, 2, "should return 2 scans for filter-host-a")

	// Filter by profile
	resp2, err := http.Get(serverURL + "/api/v1/scans?profile=quick")
	require.NoError(t, err)
	defer resp2.Body.Close()

	var summaries2 []store.ScanSummary
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&summaries2))
	assert.Len(t, summaries2, 2, "should return 2 scans with quick profile")
}
