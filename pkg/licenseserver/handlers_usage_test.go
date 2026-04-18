//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

func postUsage(t *testing.T, tsURL, licenseID, instanceID string, metrics []map[string]any) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"licenseID":  licenseID,
		"instanceID": instanceID,
		"metrics":    metrics,
	})
	require.NoError(t, err)
	resp, err := http.Post(tsURL+"/api/v1/license/usage", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

func decodeUsageResponse(t *testing.T, resp *http.Response) licenseserver.UsageResponse {
	t.Helper()
	defer resp.Body.Close()
	var out licenseserver.UsageResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func TestUsage_UpsertsAndReturnsRemaining(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicenseV2(t, ts.URL,
		licensestore.Features{Report: true, Manage: true},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
			{Metric: "scans", Window: "monthly", Cap: 1000},
		},
	)

	inst := uuid.NewString()
	resp := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 12},
		{"metric": "scans", "window": "monthly", "value": 45},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	out := decodeUsageResponse(t, resp)
	assert.True(t, out.OK)
	assert.Equal(t, int64(38), out.Remaining["seats"]["total"])
	assert.Equal(t, int64(955), out.Remaining["scans"]["monthly"])
	assert.Empty(t, out.OverCap)
	assert.Empty(t, out.InBuffer)
}

func TestUsage_OverCapFlagged(t *testing.T) {
	// cap=10, buffer=10% → ceiling=11; value=12 → over cap AND over buffer → over_cap
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicenseV2(t, ts.URL,
		licensestore.Features{Report: true},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 10},
		},
	)

	inst := uuid.NewString()
	resp := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 12},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	out := decodeUsageResponse(t, resp)
	assert.True(t, out.OK)
	// remaining is clamped to 0 when over cap
	assert.Equal(t, int64(0), out.Remaining["seats"]["total"])
	require.Len(t, out.OverCap, 1)
	assert.Equal(t, "seats", out.OverCap[0].Metric)
	assert.Equal(t, "total", out.OverCap[0].Window)
	assert.Empty(t, out.InBuffer)
}

func TestUsage_InBufferFlagged(t *testing.T) {
	// cap=10, buffer=10% → ceiling=11; value=11 → over cap (10) but NOT over ceiling (11 > 11 is false) → in_buffer
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicenseV2(t, ts.URL,
		licensestore.Features{Report: true},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 10},
		},
	)

	inst := uuid.NewString()
	resp := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 11},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	out := decodeUsageResponse(t, resp)
	assert.True(t, out.OK)
	assert.Equal(t, int64(0), out.Remaining["seats"]["total"])
	assert.Empty(t, out.OverCap)
	require.Len(t, out.InBuffer, 1)
	assert.Equal(t, "seats", out.InBuffer[0].Metric)
}

func TestUsage_Upsert_IdempotentOnSameInstance(t *testing.T) {
	// The same instance reporting the same metric twice should replace,
	// not accumulate.
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicenseV2(t, ts.URL,
		licensestore.Features{Report: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 50}},
	)

	inst := uuid.NewString()

	// First report: 10 seats
	resp1 := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 10},
	})
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	out1 := decodeUsageResponse(t, resp1)
	assert.Equal(t, int64(40), out1.Remaining["seats"]["total"])

	// Second report: 15 seats (replaces, not adds)
	resp2 := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 15},
	})
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	out2 := decodeUsageResponse(t, resp2)
	assert.Equal(t, int64(35), out2.Remaining["seats"]["total"])
}

func TestUsage_MultipleInstances_SummedInSummary(t *testing.T) {
	// Two different instances reporting seats — summary should sum both.
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicenseV2(t, ts.URL,
		licensestore.Features{Report: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 50}},
	)

	inst1 := uuid.NewString()
	inst2 := uuid.NewString()

	postUsage(t, ts.URL, licID, inst1, []map[string]any{
		{"metric": "seats", "window": "total", "value": 10},
	}).Body.Close()

	resp := postUsage(t, ts.URL, licID, inst2, []map[string]any{
		{"metric": "seats", "window": "total", "value": 15},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeUsageResponse(t, resp)
	// 50 - (10 + 15) = 25
	assert.Equal(t, int64(25), out.Remaining["seats"]["total"])
}

func TestUsage_MissingLicenseID_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"instanceID": "inst-1",
		"metrics":    []map[string]any{{"metric": "seats", "window": "total", "value": 1}},
	})
	resp, err := http.Post(ts.URL+"/api/v1/license/usage", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUsage_MissingInstanceID_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"licenseID": "some-id",
		"metrics":   []map[string]any{{"metric": "seats", "window": "total", "value": 1}},
	})
	resp, err := http.Post(ts.URL+"/api/v1/license/usage", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUsage_EmptyMetrics_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL)
	body, _ := json.Marshal(map[string]any{
		"licenseID":  licID,
		"instanceID": "inst-1",
		"metrics":    []map[string]any{},
	})
	resp, err := http.Post(ts.URL+"/api/v1/license/usage", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestUsage_UnknownLicenseID_Returns404(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := postUsage(t, ts.URL, "00000000-0000-0000-0000-000000000000", "inst-1", []map[string]any{
		{"metric": "seats", "window": "total", "value": 1},
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUsage_LegacyLicense_CompatLimitsApplied(t *testing.T) {
	// A legacy (tier-only) licence without explicit limits should get
	// CompatLimits applied. "pro" tier → seats/total cap=50.
	ts, _ := setupTestServer(t)
	_, licID := createOrgAndLicense(t, ts.URL) // "pro", seats=3, no v2 limits

	inst := uuid.NewString()
	resp := postUsage(t, ts.URL, licID, inst, []map[string]any{
		{"metric": "seats", "window": "total", "value": 5},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	out := decodeUsageResponse(t, resp)
	assert.True(t, out.OK)
	// CompatLimits("pro") has seats/total cap=50, so remaining=45
	assert.Equal(t, int64(45), out.Remaining["seats"]["total"])
}
