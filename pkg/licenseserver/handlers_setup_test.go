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

func TestSetupStatus_EmptyDB_NeedsSetupTrue(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["needsSetup"])
}

func TestSetupStatus_WithUser_NeedsSetupFalse(t *testing.T) {
	ts, cfg := setupTestServer(t)
	setupAdminUser(t, cfg)

	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["needsSetup"])
}

func TestSetup_NoUsers_CreatesFirstAdmin(t *testing.T) {
	ts, _ := setupTestServer(t)
	b, _ := json.Marshal(map[string]string{
		"name":  "Alice",
		"email": "alice@example.com",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	user := body["user"].(map[string]any)
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, "platform_admin", user["role"])
	assert.Equal(t, true, user["mustChangePassword"])
	assert.NotEmpty(t, body["tempPassword"])
	// emailSent is false when mailer is nil (test server default).
	assert.Equal(t, false, body["emailSent"])
}

func TestSetup_AlreadySeeded_Returns409(t *testing.T) {
	ts, cfg := setupTestServer(t)
	setupAdminUser(t, cfg)

	b, _ := json.Marshal(map[string]string{
		"name":  "Bob",
		"email": "bob@example.com",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestSetup_InvalidEmail_Returns400(t *testing.T) {
	ts, _ := setupTestServer(t)
	b, _ := json.Marshal(map[string]string{
		"name":  "Bob",
		"email": "not-an-email",
	})
	resp, err := http.Post(ts.URL+"/api/v1/setup/first-admin",
		"application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
