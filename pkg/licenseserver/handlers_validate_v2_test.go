//go:build integration

package licenseserver_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestValidate_V2FieldsInResponse(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicenseV2(t, ts.URL, jwt,
		licensestore.Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
		},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
			{Metric: "scans", Window: "monthly", Cap: 10000},
		},
	)

	// First activate to get a token.
	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-v2-validate", "hostname": "host1", "os": "linux", "arch": "amd64",
	})
	actResult := decodeJSON(t, actResp)
	require.Equal(t, http.StatusCreated, actResp.StatusCode)
	token := actResult["token"].(string)

	// Now validate.
	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "machine-v2-validate", "token": token,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON(t, resp)
	assert.Equal(t, true, result["valid"])

	// Existing fields must still be present.
	assert.Equal(t, "enterprise", result["tier"])
	assert.NotEmpty(t, result["expiresAt"])
	assert.NotNil(t, result["cacheTTL"])

	// v2 fields must be present.
	assert.NotNil(t, result["features"], "features should be present in v2 validate response")
	assert.NotNil(t, result["limits"], "limits should be present in v2 validate response")
	assert.NotNil(t, result["usage"], "usage should be present in v2 validate response")

	// Verify features shape.
	featuresRaw, err := json.Marshal(result["features"])
	require.NoError(t, err)
	var features licensestore.Features
	require.NoError(t, json.Unmarshal(featuresRaw, &features))
	assert.True(t, features.Report)
	assert.True(t, features.Manage)
	assert.True(t, features.ComprehensiveProfile)

	// Verify limits shape.
	limitsRaw, err := json.Marshal(result["limits"])
	require.NoError(t, err)
	var limits licensestore.Limits
	require.NoError(t, json.Unmarshal(limitsRaw, &limits))
	require.NotEmpty(t, limits)
	seatsLimit := limits.Find("seats", "total")
	require.NotNil(t, seatsLimit)
	assert.Equal(t, int64(50), seatsLimit.Cap)
}

func TestValidate_V2LegacyLicense_CompatFeaturesInResponse(t *testing.T) {
	// A legacy licence (tier-only, no v2 features) should still include
	// compat-derived features in the validate response.
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicense(t, ts.URL, jwt) // "pro", no v2 fields

	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-legacy-val",
	})
	actResult := decodeJSON(t, actResp)
	require.Equal(t, http.StatusCreated, actResp.StatusCode)
	token := actResult["token"].(string)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "machine-legacy-val", "token": token,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON(t, resp)
	assert.Equal(t, true, result["valid"])

	// Features should be compat-derived from tier "pro".
	assert.NotNil(t, result["features"])
	featuresRaw, err := json.Marshal(result["features"])
	require.NoError(t, err)
	var features licensestore.Features
	require.NoError(t, json.Unmarshal(featuresRaw, &features))
	assert.True(t, features.Report) // CompatFeatures("pro").Report == true
}

func TestValidate_V2UsageReflectedAfterPush(t *testing.T) {
	// Push usage via /usage, then verify /validate response reflects current usage.
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicenseV2(t, ts.URL, jwt,
		licensestore.Features{Report: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 50}},
	)

	// Activate to get a token.
	actResp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-usage-check",
	})
	actResult := decodeJSON(t, actResp)
	require.Equal(t, http.StatusCreated, actResp.StatusCode)
	token := actResult["token"].(string)

	// Push some usage (use UUID for instance ID as required by the DB schema).
	postUsage(t, ts.URL, licID, uuid.NewString(), []map[string]any{
		{"metric": "seats", "window": "total", "value": 20},
	}).Body.Close()

	// Validate — usage should reflect the push.
	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": "machine-usage-check", "token": token,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON(t, resp)
	assert.Equal(t, true, result["valid"])

	usageRaw, err := json.Marshal(result["usage"])
	require.NoError(t, err)
	var usage map[string]map[string]int64
	require.NoError(t, json.Unmarshal(usageRaw, &usage))
	assert.Equal(t, int64(20), usage["seats"]["total"])
}
