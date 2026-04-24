//go:build integration

package licenseserver_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// splitToken splits a license token into [claims, signature] parts.
func splitToken(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.SplitN(token, ".", 2)
	require.Len(t, parts, 2, "expected token in claims.sig format")
	return parts
}

// decodeBase64URL decodes a raw (unpadded) base64url string.
func decodeBase64URL(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err, "failed to base64url decode")
	return b
}

// createOrgAndLicenseV2 creates an org + v2 licence with explicit features and limits.
func createOrgAndLicenseV2(t *testing.T, tsURL, jwt string, features licensestore.Features, limits licensestore.Limits) (orgID, licID string) {
	t.Helper()
	orgResp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/orgs", map[string]string{"name": "V2Org" + t.Name()})
	defer orgResp.Body.Close()
	orgResult := decodeJSON(t, orgResp)
	orgID = orgIDOf(orgResult)

	body := map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 50, "days": 365,
		"features":        features,
		"limits":          limits,
		"soft_buffer_pct": 10,
		"product_scope":   "bundle",
	}
	licResp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses", body)
	defer licResp.Body.Close()
	licResult := decodeJSON(t, licResp)
	licID = licResult["id"].(string)
	return
}

func TestActivate_V2FieldsInResponse(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicenseV2(t, ts.URL, jwt,
		licensestore.Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			ExportFormats:        []string{"html", "pdf", "csv", "json"},
		},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
			{Metric: "scans", Window: "monthly", Cap: 10000},
		},
	)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-v2-test", "hostname": "host1", "os": "linux", "arch": "amd64",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	result := decodeJSON(t, resp)

	// Existing fields must still be present.
	assert.NotEmpty(t, result["token"])
	assert.Equal(t, "enterprise", result["tier"])
	assert.Equal(t, float64(50), result["seats"])
	assert.Equal(t, float64(1), result["seatsUsed"])
	assert.NotEmpty(t, result["expiresAt"])

	// v2 fields must be present.
	assert.NotNil(t, result["features"], "features should be present in v2 response")
	assert.NotNil(t, result["limits"], "limits should be present in v2 response")
	assert.NotNil(t, result["usage"], "usage should be present in v2 response")
	assert.Equal(t, float64(7*24*3600), result["grace_seconds"])

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

func TestActivate_V2LegacyLicense_CompatFeaturesInResponse(t *testing.T) {
	// A licence created without explicit v2 features (legacy tier-only) should
	// still produce compat-derived features in the activate response.
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicense(t, ts.URL, jwt) // uses "pro", seats=3, no v2 fields

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-legacy", "hostname": "host2", "os": "linux", "arch": "amd64",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	result := decodeJSON(t, resp)
	// Features should be compat-derived from tier "pro" (non-nil, non-empty).
	assert.NotNil(t, result["features"])
	assert.NotNil(t, result["limits"])

	featuresRaw, err := json.Marshal(result["features"])
	require.NoError(t, err)
	var features licensestore.Features
	require.NoError(t, json.Unmarshal(featuresRaw, &features))
	// CompatFeatures("pro") has Report=true.
	assert.True(t, features.Report)
}

func TestActivate_V2TokenCarriesV2Claims(t *testing.T) {
	// Verify that the signed token returned by /activate carries v2 claims.
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	_, licID := createOrgAndLicenseV2(t, ts.URL, jwt,
		licensestore.Features{Report: true, Manage: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 50}},
	)

	resp := clientReq(t, "POST", ts.URL+"/api/v1/license/activate", map[string]string{
		"licenseID": licID, "machineID": "machine-token-v2",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	result := decodeJSON(t, resp)
	token, ok := result["token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, token)

	// The token is a base64url(claims).base64url(sig) JWT-like format.
	// We can decode the claims part to verify v2 fields are present.
	// Use the internal/license.ParseUnsafe — but it's not exported.
	// Instead, decode manually.
	parts := splitToken(t, token)
	require.Len(t, parts, 2)

	claimsJSON := decodeBase64URL(t, parts[0])
	var claims map[string]any
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))

	assert.NotNil(t, claims["features"], "token should carry features claim")
	assert.NotNil(t, claims["limits"], "token should carry limits claim")
}
