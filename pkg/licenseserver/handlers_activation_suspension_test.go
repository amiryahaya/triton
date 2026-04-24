//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedOrgAndLicense(t *testing.T, tsURL, adminKey, orgName string) (orgID, licID string) {
	t.Helper()
	orgID = createOrgViaAPI(t, tsURL, adminKey, orgName)
	licID = createLicenseViaAPIWithFields(t, tsURL, adminKey, orgID, map[string]any{
		"tier":  "pro",
		"seats": 5,
		"days":  365,
		"features": map[string]any{
			"report": true, "manage": false, "comprehensive_profile": false,
			"diff_trend": false, "custom_policy": false, "sso": false,
		},
		"limits":        []any{},
		"product_scope": "report",
	})
	return
}

func TestHandleActivate_OrgSuspended(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"

	orgID, licID := seedOrgAndLicense(t, ts.URL, adminKey, "SuspendActivateCo")

	// Suspend the org
	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
		"/api/v1/admin/orgs/"+orgID+"/suspend",
		map[string]any{"suspended": true})
	require.Equal(t, http.StatusNoContent, resp.Code)

	// Attempt to activate — must be rejected with 403
	body, _ := json.Marshal(map[string]any{
		"licenseID": licID,
		"machineID": "machine-abc",
		"hostname":  "host.example.com",
		"os":        "linux",
		"arch":      "amd64",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/activate",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestHandleValidate_OrgSuspended(t *testing.T) {
	ts, store := setupTestServer(t)
	const adminKey = "test-admin-key"

	orgID, licID := seedOrgAndLicense(t, ts.URL, adminKey, "SuspendValidateCo")

	// Activate a machine while the org is still active
	activateBody, _ := json.Marshal(map[string]any{
		"licenseID": licID,
		"machineID": "machine-xyz",
		"hostname":  "host.example.com",
		"os":        "linux",
		"arch":      "amd64",
	})
	activateReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/activate",
		bytes.NewReader(activateBody))
	activateReq.Header.Set("Content-Type", "application/json")
	activateRes, err := http.DefaultClient.Do(activateReq)
	require.NoError(t, err)
	var activateResp map[string]any
	require.NoError(t, json.NewDecoder(activateRes.Body).Decode(&activateResp))
	activateRes.Body.Close()
	require.Equal(t, http.StatusCreated, activateRes.StatusCode)
	token, ok := activateResp["token"].(string)
	require.True(t, ok, "token should be a string")

	// Suspend the org via the store directly
	require.NoError(t, store.SuspendOrg(t.Context(), orgID, true))

	// Attempt to validate — must be rejected with 403
	validateBody, _ := json.Marshal(map[string]any{
		"licenseID": licID,
		"machineID": "machine-xyz",
		"token":     token,
	})
	validateReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/validate",
		bytes.NewReader(validateBody))
	validateReq.Header.Set("Content-Type", "application/json")
	validateRes, err := http.DefaultClient.Do(validateReq)
	require.NoError(t, err)
	validateRes.Body.Close()
	assert.Equal(t, http.StatusForbidden, validateRes.StatusCode)

	// Unsuspend — validate should succeed again
	require.NoError(t, store.SuspendOrg(t.Context(), orgID, false))
	validateReq2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/license/validate",
		bytes.NewReader(validateBody))
	validateReq2.Header.Set("Content-Type", "application/json")
	validateRes2, err := http.DefaultClient.Do(validateReq2)
	require.NoError(t, err)
	var validateResp2 map[string]any
	require.NoError(t, json.NewDecoder(validateRes2.Body).Decode(&validateResp2))
	validateRes2.Body.Close()
	assert.Equal(t, http.StatusOK, validateRes2.StatusCode)
	assert.Equal(t, true, validateResp2["valid"])
}
