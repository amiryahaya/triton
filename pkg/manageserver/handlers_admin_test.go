//go:build integration

package manageserver_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminCRUD_ZonesAndHosts exercises the full admin CRUD lifecycle over
// HTTP through the injectInstanceOrg middleware. Covers:
//   - POST /api/v1/admin/zones (201)
//   - POST /api/v1/admin/hosts (201)
//   - GET  /api/v1/admin/zones (200, list)
//   - GET  /api/v1/admin/zones/{id} (200, single)
//   - DELETE /api/v1/admin/zones/{id} (204)
//   - GET  /api/v1/admin/zones/{id} (404 post-delete)
//
// Role enforcement on DELETE is deferred (see Batch C notes); this test
// therefore expects 204, not 403.
func TestAdminCRUD_ZonesAndHosts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	user := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// --- Create zone ---
	zoneID := createZone(t, ts.URL, token, "dmz")

	// --- Create host in that zone ---
	createHost(t, ts.URL, token, "db-01", zoneID)

	// --- List zones: expect 1 ---
	zones := listZones(t, ts.URL, token)
	require.Len(t, zones, 1, "expected exactly one zone after create")
	assert.Equal(t, "dmz", zones[0]["name"])

	// --- Get single zone ---
	getResp, err := authorizedRequest(t, ts.URL+"/api/v1/admin/zones/"+zoneID.String(), "GET", token)
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	// --- Delete zone ---
	delResp, err := authorizedRequest(t, ts.URL+"/api/v1/admin/zones/"+zoneID.String(), "DELETE", token)
	require.NoError(t, err)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode,
		"DELETE should succeed (role enforcement deferred)")

	// --- Get deleted zone: 404 ---
	missResp, err := authorizedRequest(t, ts.URL+"/api/v1/admin/zones/"+zoneID.String(), "GET", token)
	require.NoError(t, err)
	defer missResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, missResp.StatusCode)
}

// TestAdmin_RequiresJWT — unauthenticated request to /api/v1/admin/* → 401.
func TestAdmin_RequiresJWT(t *testing.T) {
	srv, _, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/admin/zones")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAdmin_RejectsInSetupMode — operational gate must still return 503
// when the server is in setup mode, even on /api/v1/admin routes.
func TestAdmin_RejectsInSetupMode(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/admin/zones")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// --- helpers -------------------------------------------------------------

func postJSON(t *testing.T, url, token string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest("POST", url, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func createZone(t *testing.T, baseURL, token, name string) uuid.UUID {
	t.Helper()
	resp := postJSON(t, baseURL+"/api/v1/admin/zones", token, map[string]string{"name": name})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create zone should return 201")

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	idStr, ok := out["id"].(string)
	require.True(t, ok && idStr != "", "zone response must carry a non-empty id")
	id, err := uuid.Parse(idStr)
	require.NoError(t, err)
	return id
}

func createHost(t *testing.T, baseURL, token, hostname string, zoneID uuid.UUID) {
	t.Helper()
	zid := zoneID.String()
	resp := postJSON(t, baseURL+"/api/v1/admin/hosts", token, map[string]any{
		"hostname": hostname,
		"zone_id":  zid,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create host: want 201, got %d (body: %s)", resp.StatusCode, string(body))
	}
}

func listZones(t *testing.T, baseURL, token string) []map[string]any {
	t.Helper()
	resp, err := authorizedRequest(t, baseURL+"/api/v1/admin/zones", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

