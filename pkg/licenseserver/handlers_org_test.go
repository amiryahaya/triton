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

func TestHandleSuspendOrg_Success(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"

	orgID := createOrgViaAPI(t, ts.URL, adminKey, "SuspendCo")

	// Suspend
	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
		"/api/v1/admin/orgs/"+orgID+"/suspend",
		map[string]any{"suspended": true})
	assert.Equal(t, http.StatusNoContent, resp.Code)

	// Verify org is suspended by listing orgs
	listReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/orgs", nil)
	require.NoError(t, err)
	listReq.Header.Set("X-Triton-Admin-Key", adminKey)
	listRes, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listRes.StatusCode)
	var orgs []map[string]any
	require.NoError(t, json.NewDecoder(listRes.Body).Decode(&orgs))
	listRes.Body.Close()

	var found map[string]any
	for _, o := range orgs {
		if o["id"] == orgID {
			found = o
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, true, found["suspended"])

	// Unsuspend
	resp2 := adminDo(t, ts.URL, adminKey, http.MethodPost,
		"/api/v1/admin/orgs/"+orgID+"/suspend",
		map[string]any{"suspended": false})
	assert.Equal(t, http.StatusNoContent, resp2.Code)
}

func TestHandleSuspendOrg_NotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"

	resp := adminDo(t, ts.URL, adminKey, http.MethodPost,
		"/api/v1/admin/orgs/00000000-0000-0000-0000-000000000000/suspend",
		map[string]any{"suspended": true})
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestHandleSuspendOrg_BadBody(t *testing.T) {
	ts, _ := setupTestServer(t)
	const adminKey = "test-admin-key"

	orgID := createOrgViaAPI(t, ts.URL, adminKey, "BadBodyCo")

	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		bytes.NewBufferString("not-json"))
	req.Header.Set("X-Triton-Admin-Key", adminKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestHandleSuspendOrg_RequiresAdminKey(t *testing.T) {
	ts, _ := setupTestServer(t)

	orgID := createOrgViaAPI(t, ts.URL, "test-admin-key", "AuthTestCo")

	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		bytes.NewBufferString(`{"suspended":true}`))
	req.Header.Set("Content-Type", "application/json")
	// No admin key header
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
