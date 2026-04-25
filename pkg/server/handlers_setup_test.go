//go:build integration

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupReq is a thin helper that sends a request directly to a handler
// (bypassing the router) and returns the recorded response.
func setupReq(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	switch path {
	case "/api/v1/setup/status":
		srv.handleSetupStatus(rr, req)
	case "/api/v1/setup":
		srv.handleFirstSetup(rr, req)
	default:
		t.Fatalf("setupReq: unrecognised path %q", path)
	}
	return rr
}

// TestHandleSetupStatus_NeedsSetup verifies that GET /api/v1/setup/status
// returns {"needsSetup":true} when no platform_admin exists yet.
func TestHandleSetupStatus_NeedsSetup(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	rr := setupReq(t, srv, http.MethodGet, "/api/v1/setup/status", nil)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp["needsSetup"], "expected needsSetup=true before first setup")
}

// TestHandleFirstSetup_CreatesAdmin verifies that POST /api/v1/setup returns
// 201 with an "id" and "tempPassword" when no platform_admin exists yet.
func TestHandleFirstSetup_CreatesAdmin(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	rr := setupReq(t, srv, http.MethodPost, "/api/v1/setup", map[string]string{
		"name":  "Alice",
		"email": "alice@example.com",
	})

	require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotEmpty(t, resp["id"], "response must include the new user's id")
	assert.NotEmpty(t, resp["tempPassword"], "response must include the temp password")
}

// TestHandleFirstSetup_BlocksSecondCall verifies that a second POST to
// /api/v1/setup returns 409 Conflict once a platform_admin already exists.
func TestHandleFirstSetup_BlocksSecondCall(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	// First call — should succeed.
	rr := setupReq(t, srv, http.MethodPost, "/api/v1/setup", map[string]string{
		"name":  "Alice",
		"email": "alice@example.com",
	})
	require.Equal(t, http.StatusCreated, rr.Code, "first setup call failed: %s", rr.Body.String())

	// Second call — must be blocked.
	rr2 := setupReq(t, srv, http.MethodPost, "/api/v1/setup", map[string]string{
		"name":  "Bob",
		"email": "bob@example.com",
	})
	assert.Equal(t, http.StatusConflict, rr2.Code, "second setup call should return 409, got: %s", rr2.Body.String())
}

// TestHandleSetupStatus_ReadyAfterSetup verifies that after a successful
// POST /api/v1/setup, GET /api/v1/setup/status returns {"needsSetup":false}.
func TestHandleSetupStatus_ReadyAfterSetup(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	// Create the first platform admin.
	rr := setupReq(t, srv, http.MethodPost, "/api/v1/setup", map[string]string{
		"name":  "Alice",
		"email": "alice@example.com",
	})
	require.Equal(t, http.StatusCreated, rr.Code, "setup call failed: %s", rr.Body.String())

	// Status should now report needsSetup=false.
	rr2 := setupReq(t, srv, http.MethodGet, "/api/v1/setup/status", nil)
	require.Equal(t, http.StatusOK, rr2.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(rr2.Body).Decode(&resp))
	assert.False(t, resp["needsSetup"], "expected needsSetup=false after setup")
}
