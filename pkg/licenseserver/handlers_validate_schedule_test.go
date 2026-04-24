//go:build integration

package licenseserver_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// activateAndValidate is a small helper: activate a machine, then
// validate with the returned token. Returns the decoded validate body.
func activateAndValidate(t *testing.T, tsURL, licID, machineID string) map[string]any {
	t.Helper()
	actResp := clientReq(t, "POST", tsURL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": machineID,
		"hostname": "h-" + machineID, "os": "linux", "arch": "amd64",
	})
	actResult := decodeJSON(t, actResp)
	require.Equal(t, http.StatusCreated, actResp.StatusCode)
	token := actResult["token"].(string)

	valResp := clientReq(t, "POST", tsURL+"/api/v1/license/validate", map[string]string{
		"licenseID": licID, "machineID": machineID, "token": token,
	})
	defer valResp.Body.Close()
	require.Equal(t, http.StatusOK, valResp.StatusCode)
	return decodeJSON(t, valResp)
}

// TestValidate_SchedulePresentWhenSet verifies that a license with a
// portal-pushed schedule carries the schedule + jitter fields on the
// /validate response.
func TestValidate_SchedulePresentWhenSet(t *testing.T) {
	ts, store := setupTestServer(t)
	email, password := setupAdminUser(t, store)
	jwt := loginViaAPI(t, ts.URL, email, password)

	orgID := createOrgViaAPI(t, ts.URL, jwt, "SchedOrg")
	licID := createLicenseViaAPIWithFields(t, ts.URL, jwt, orgID, map[string]any{
		"schedule":              "0 2 * * 0",
		"scheduleJitterSeconds": 45,
	})

	result := activateAndValidate(t, ts.URL, licID, "machine-sched-set")

	assert.Equal(t, true, result["valid"])
	assert.Equal(t, "0 2 * * 0", result["schedule"])
	// JSON numbers deserialize as float64 in map[string]any.
	require.NotNil(t, result["scheduleJitterSeconds"])
	assert.Equal(t, float64(45), result["scheduleJitterSeconds"])
}

// TestValidate_ScheduleAbsentWhenUnset verifies the schedule keys are
// omitted from the response when the license has no schedule. Old
// agents must see a clean response; the keys should simply not exist.
func TestValidate_ScheduleAbsentWhenUnset(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	// Create a v2 licence with no schedule (uses the v2 helper so the
	// other v2 fields are populated — reuses an existing helper).
	_, licID := createOrgAndLicenseV2(t, ts.URL, jwt,
		licensestore.Features{Report: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 5}},
	)

	result := activateAndValidate(t, ts.URL, licID, "machine-sched-unset")

	assert.Equal(t, true, result["valid"])
	// omitempty on the wire + no value set → key absent from map.
	_, hasSchedule := result["schedule"]
	_, hasJitter := result["scheduleJitterSeconds"]
	assert.False(t, hasSchedule, "schedule key should be absent when license has none")
	assert.False(t, hasJitter, "scheduleJitterSeconds key should be absent when license has none")
}
