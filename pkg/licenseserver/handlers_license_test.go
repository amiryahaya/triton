//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers specific to license-schedule tests ---

// createOrgViaAPI creates an org and returns its ID.
func createOrgViaAPI(t *testing.T, tsURL, adminKey, name string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"name": name})
	req, _ := http.NewRequest(http.MethodPost, tsURL+"/api/v1/admin/orgs", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-Admin-Key", adminKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return orgIDOf(result)
}

// createLicenseViaAPIWithFields creates a license with arbitrary extra fields
// and returns its ID.
func createLicenseViaAPIWithFields(t *testing.T, tsURL, adminKey, orgID string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{
		"orgID": orgID,
		"tier":  "pro",
		"seats": 1,
		"days":  30,
	}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, tsURL+"/api/v1/admin/licenses", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-Admin-Key", adminKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result["id"].(string)
}

// adminDo performs an authenticated admin JSON request and returns the decoded body.
type adminResponse struct {
	Code int
	Body map[string]any
}

func adminDo(t *testing.T, tsURL, adminKey, method, path string, body any) adminResponse {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(method, tsURL+path, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-Admin-Key", adminKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return adminResponse{Code: resp.StatusCode, Body: result}
}

// --- POST /api/v1/admin/licenses — cron validation ---

func TestCreateLicense_InvalidCronRejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID":                 orgID,
		"tier":                  "pro",
		"seats":                 1,
		"days":                  30,
		"schedule":              "this is not cron",
		"scheduleJitterSeconds": 0,
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	msg, _ := resp.Body["error"].(string)
	if !strings.Contains(strings.ToLower(msg), "cron") && !strings.Contains(strings.ToLower(msg), "schedule") {
		t.Errorf("error = %q, want mention of cron/schedule", msg)
	}
}

func TestCreateLicense_ValidCronAccepted(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID":                 orgID,
		"tier":                  "pro",
		"seats":                 1,
		"days":                  30,
		"schedule":              "0 2 * * *",
		"scheduleJitterSeconds": 30,
	})
	require.Equal(t, http.StatusCreated, resp.Code)
	assert.Equal(t, "0 2 * * *", resp.Body["schedule"])
	jitter, ok := resp.Body["scheduleJitterSeconds"].(float64)
	require.True(t, ok, "scheduleJitterSeconds should be a number in response")
	assert.Equal(t, 30, int(jitter))
}

func TestCreateLicense_NegativeJitterRejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID":                 orgID,
		"tier":                  "pro",
		"seats":                 1,
		"days":                  30,
		"scheduleJitterSeconds": -1,
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	msg, _ := resp.Body["error"].(string)
	assert.Contains(t, strings.ToLower(msg), "jitter")
}

// --- PATCH /api/v1/admin/licenses/{id} ---

func TestUpdateLicense_SetAndClearSchedule(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")
	licID := createLicenseViaAPIWithFields(t, ts.URL, adminKey, orgID, nil)

	// Set schedule.
	setResp := adminDo(t, ts.URL, adminKey, http.MethodPatch, "/api/v1/admin/licenses/"+licID,
		map[string]any{"schedule": "0 2 * * 0", "scheduleJitterSeconds": 30})
	require.Equal(t, http.StatusOK, setResp.Code)

	// GET and verify.
	got := adminDo(t, ts.URL, adminKey, http.MethodGet, "/api/v1/admin/licenses/"+licID, nil)
	require.Equal(t, http.StatusOK, got.Code)
	assert.Equal(t, "0 2 * * 0", got.Body["schedule"])
	jitter, ok := got.Body["scheduleJitterSeconds"].(float64)
	require.True(t, ok)
	assert.Equal(t, 30, int(jitter))

	// Clear via empty string + zero.
	clr := adminDo(t, ts.URL, adminKey, http.MethodPatch, "/api/v1/admin/licenses/"+licID,
		map[string]any{"schedule": "", "scheduleJitterSeconds": 0})
	require.Equal(t, http.StatusOK, clr.Code)

	got = adminDo(t, ts.URL, adminKey, http.MethodGet, "/api/v1/admin/licenses/"+licID, nil)
	require.Equal(t, http.StatusOK, got.Code)
	sched := got.Body["schedule"]
	if sched != "" && sched != nil {
		t.Errorf("schedule after clear = %v, want empty/nil", sched)
	}
}

func TestUpdateLicense_InvalidCronRejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")
	licID := createLicenseViaAPIWithFields(t, ts.URL, adminKey, orgID, nil)

	resp := adminDo(t, ts.URL, adminKey, http.MethodPatch, "/api/v1/admin/licenses/"+licID,
		map[string]any{"schedule": "nope"})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	msg, _ := resp.Body["error"].(string)
	if !strings.Contains(strings.ToLower(msg), "cron") && !strings.Contains(strings.ToLower(msg), "schedule") {
		t.Errorf("error = %q, want mention of cron/schedule", msg)
	}
}

func TestUpdateLicense_NegativeJitterRejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SchedCo")
	licID := createLicenseViaAPIWithFields(t, ts.URL, adminKey, orgID, nil)

	resp := adminDo(t, ts.URL, adminKey, http.MethodPatch, "/api/v1/admin/licenses/"+licID,
		map[string]any{"scheduleJitterSeconds": -5})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestUpdateLicense_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	resp := adminDo(t, ts.URL, adminKey, http.MethodPatch,
		"/api/v1/admin/licenses/00000000-0000-0000-0000-000000000000",
		map[string]any{"schedule": "0 2 * * *"})
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestCreateLicense_SeatsZeroScansZero_Rejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "ZeroZero")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID": orgID,
		"tier":  "pro",
		"seats": 0,
		"days":  30,
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, strings.ToLower(resp.Body["error"].(string)),
		"at least one of seats or scans")
}

func TestCreateLicense_SeatsZeroScansSet_Accepted(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "ScansOnly")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID": orgID,
		"tier":  "pro",
		"seats": 0,
		"days":  30,
		"limits": []map[string]any{
			{"metric": "scans", "window": "total", "cap": 1000},
		},
	})
	assert.Equal(t, http.StatusCreated, resp.Code)
}

func TestCreateLicense_SeatsSetScansZero_Accepted(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SeatsOnly")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID": orgID,
		"tier":  "pro",
		"seats": 5,
		"days":  30,
	})
	assert.Equal(t, http.StatusCreated, resp.Code)
}

func TestCreateLicense_ReportsGeneratedStripped(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"
	orgID := createOrgViaAPI(t, ts.URL, adminKey, "StripRG")

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost, "/api/v1/admin/licenses", map[string]any{
		"orgID": orgID,
		"tier":  "pro",
		"seats": 1,
		"days":  30,
		"limits": []map[string]any{
			{"metric": "scans", "window": "total", "cap": 100},
			{"metric": "reports_generated", "window": "monthly", "cap": 10},
		},
	})
	require.Equal(t, http.StatusCreated, resp.Code)

	licenceID := resp.Body["id"].(string)
	get := adminDo(t, ts.URL, adminKey, http.MethodGet, "/api/v1/admin/licenses/"+licenceID, nil)
	require.Equal(t, http.StatusOK, get.Code)

	limits, ok := get.Body["limits"].([]any)
	require.True(t, ok, "limits should be a JSON array")
	// After stripping, only the scans entry remains.
	assert.Len(t, limits, 1)
	first := limits[0].(map[string]any)
	assert.Equal(t, "scans", first["metric"])
}
