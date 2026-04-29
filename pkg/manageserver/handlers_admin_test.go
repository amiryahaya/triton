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
// HTTP through the injectInstanceOrg middleware. Zones were replaced by Tags;
// this test now covers:
//   - POST /api/v1/admin/tags  (201)
//   - POST /api/v1/admin/hosts (201, ip required)
//   - GET  /api/v1/admin/tags  (200, list)
//   - DELETE /api/v1/admin/tags/{id} (204)
//   - GET  /api/v1/admin/tags  (200, list empty after delete)
func TestAdminCRUD_ZonesAndHosts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	user := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// --- Create tag ---
	tagID := createTag(t, ts.URL, token, "dmz")

	// --- Create host (ip is now required) ---
	createHost(t, ts.URL, token, "10.0.9.1", "db-01")

	// --- List tags: expect 13 built-in + 1 created ---
	tags := listTags(t, ts.URL, token)
	require.Len(t, tags, 14, "expected 13 built-in tags + 1 created tag")
	var found bool
	for _, tag := range tags {
		if tag["name"] == "dmz" {
			found = true
			break
		}
	}
	assert.True(t, found, "created tag 'dmz' must appear in list")

	// --- Delete tag ---
	delResp, err := authorizedRequest(t, ts.URL+"/api/v1/admin/tags/"+tagID.String(), "DELETE", token)
	require.NoError(t, err)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE tag should return 204")

	// --- List tags: expect 13 built-in tags remain after delete ---
	tagsAfter := listTags(t, ts.URL, token)
	assert.Len(t, tagsAfter, 13, "tag list must have 13 built-in tags after delete")
}

// TestAdmin_RequiresJWT — unauthenticated request to /api/v1/admin/* → 401.
func TestAdmin_RequiresJWT(t *testing.T) {
	srv, _, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/admin/tags")
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

	resp, err := http.Get(ts.URL + "/api/v1/admin/tags")
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

func createTag(t *testing.T, baseURL, token, name string) uuid.UUID {
	t.Helper()
	resp := postJSON(t, baseURL+"/api/v1/admin/tags/", token, map[string]string{
		"name":  name,
		"color": "#6366F1",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create tag should return 201")

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	idStr, ok := out["id"].(string)
	require.True(t, ok && idStr != "", "tag response must carry a non-empty id")
	id, err := uuid.Parse(idStr)
	require.NoError(t, err)
	return id
}

func createHost(t *testing.T, baseURL, token, ip, hostname string) {
	t.Helper()
	resp := postJSON(t, baseURL+"/api/v1/admin/hosts/", token, map[string]any{
		"ip":       ip,
		"hostname": hostname,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create host: want 201, got %d (body: %s)", resp.StatusCode, string(body))
	}
}

func listTags(t *testing.T, baseURL, token string) []map[string]any {
	t.Helper()
	resp, err := authorizedRequest(t, baseURL+"/api/v1/admin/tags/", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}
