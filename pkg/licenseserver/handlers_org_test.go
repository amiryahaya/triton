//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSuspendOrg_Success(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)

	orgID := createOrgViaAPI(t, ts.URL, jwt, "SuspendCo")

	// Suspend
	resp := adminReq(t, jwt, http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		map[string]any{"suspended": true})
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify org is suspended by listing orgs.
	listResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/orgs", nil)
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var orgs []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&orgs))
	listResp.Body.Close()

	var found map[string]any
	for _, o := range orgs {
		if o["id"] == orgID {
			found = o
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, true, found["suspended"])

	// Unsuspend
	resp2 := adminReq(t, jwt, http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		map[string]any{"suspended": false})
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode)
}

func TestHandleSuspendOrg_NotFound(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)

	resp := adminReq(t, jwt, http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/00000000-0000-0000-0000-000000000000/suspend",
		map[string]any{"suspended": true})
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleSuspendOrg_BadBody(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)

	orgID := createOrgViaAPI(t, ts.URL, jwt, "BadBodyCo")

	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		bytes.NewBufferString("not-json"))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestHandleSuspendOrg_RequiresAuth(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)

	orgID := createOrgViaAPI(t, ts.URL, jwt, "AuthTestCo")

	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/orgs/"+orgID+"/suspend",
		bytes.NewBufferString(`{"suspended":true}`))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header — must be rejected.
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
