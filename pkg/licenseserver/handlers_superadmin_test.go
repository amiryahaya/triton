//go:build integration

package licenseserver_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

// createSuperadmin posts a superadmin and returns the parsed response.
func createSuperadmin(t *testing.T, tsURL string, body map[string]any) *http.Response {
	t.Helper()
	return adminReq(t, http.MethodPost, tsURL+"/api/v1/admin/superadmins", body)
}

// validSuperadminBody returns a body that should always pass validation.
func validSuperadminBody(email string) map[string]any {
	return map[string]any{
		"email":    email,
		"name":     "Test Admin",
		"password": "correct-horse-battery-staple",
	}
}

// --- Happy paths ---

func TestCreateSuperadmin(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("alice@example.com"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	body := decodeJSON(t, resp)
	assert.NotEmpty(t, body["id"])
	assert.Equal(t, "alice@example.com", body["email"])
	assert.Equal(t, "Test Admin", body["name"])
	assert.Equal(t, "platform_admin", body["role"])
	_, hasPwd := body["password"]
	assert.False(t, hasPwd, "password field must not appear in response")
}

func TestListSuperadmins(t *testing.T) {
	ts, _ := setupTestServer(t)
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		resp := createSuperadmin(t, ts.URL, validSuperadminBody(email))
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	resp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	assert.Len(t, list, 3)
}

func TestGetSuperadmin(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("get@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	getResp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
	got := decodeJSON(t, getResp)
	assert.Equal(t, id, got["id"])
	assert.Equal(t, "get@example.com", got["email"])
}

func TestUpdateSuperadminName(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("rename@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	updateResp := adminReq(t, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{
		"name": "New Name",
	})
	defer updateResp.Body.Close()
	require.Equal(t, http.StatusOK, updateResp.StatusCode)
	updated := decodeJSON(t, updateResp)
	assert.Equal(t, "New Name", updated["name"])
}

func TestUpdateSuperadminPassword(t *testing.T) {
	ts, store := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("pwchange@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	// Capture original hash via store directly.
	original, err := store.GetUser(t.Context(), id)
	require.NoError(t, err)
	originalHash := original.Password

	updateResp := adminReq(t, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{
		"password": "another-strong-passphrase",
	})
	defer updateResp.Body.Close()
	require.Equal(t, http.StatusOK, updateResp.StatusCode)

	// Confirm hash changed.
	after, err := store.GetUser(t.Context(), id)
	require.NoError(t, err)
	assert.NotEqual(t, originalHash, after.Password, "password hash must change after update")
}

func TestDeleteSuperadmin(t *testing.T) {
	ts, _ := setupTestServer(t)
	// Create two superadmins so deleting one doesn't trip the last-admin guard.
	resp1 := createSuperadmin(t, ts.URL, validSuperadminBody("keeper@example.com"))
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	resp1.Body.Close()

	resp2 := createSuperadmin(t, ts.URL, validSuperadminBody("delete@example.com"))
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
	created := decodeJSON(t, resp2)
	resp2.Body.Close()
	id := created["id"].(string)

	delResp := adminReq(t, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)

	getResp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// TestDeleteLastSuperadminRefused verifies that the final platform_admin
// cannot be deleted, preventing permanent admin lockout of the license
// server. Without this guard, an operator who deletes all but one admin
// and then deletes the last would need to directly manipulate the DB to
// recover.
func TestDeleteLastSuperadminRefused(t *testing.T) {
	ts, _ := setupTestServer(t)
	// Only one superadmin in the table.
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("only@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	delResp := adminReq(t, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusConflict, delResp.StatusCode)

	// And the user must still exist.
	getResp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
}

// --- Validation edge cases ---

func TestCreateSuperadminMissingEmail(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, map[string]any{
		"name":     "No Email",
		"password": "correct-horse-battery-staple",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateSuperadminMissingPassword(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, map[string]any{
		"email": "nopw@example.com",
		"name":  "No Password",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateSuperadminWeakPassword(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, map[string]any{
		"email":    "weak@example.com",
		"name":     "Weak Pwd",
		"password": "short",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateSuperadminInvalidEmail(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, map[string]any{
		"email":    "notanemail",
		"name":     "Bad Email",
		"password": "correct-horse-battery-staple",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateSuperadminDuplicateEmail(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp1 := createSuperadmin(t, ts.URL, validSuperadminBody("dup@example.com"))
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	resp1.Body.Close()

	resp2 := createSuperadmin(t, ts.URL, validSuperadminBody("dup@example.com"))
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestCreateSuperadminIgnoresRole(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, map[string]any{
		"email":    "sneaky@example.com",
		"name":     "Sneaky",
		"password": "correct-horse-battery-staple",
		"role":     "org_user", // should be ignored
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decodeJSON(t, resp)
	assert.Equal(t, "platform_admin", body["role"], "role from request body must be ignored")
}

// TestUpdateSuperadminEmptyBodyRejected verifies that a PUT with neither
// name nor password fields returns 400, rather than silently touching the
// row and polluting the audit log with a no-op event.
func TestUpdateSuperadminEmptyBodyRejected(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("emptyput@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	updateResp := adminReq(t, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{})
	defer updateResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, updateResp.StatusCode)
}

func TestGetSuperadminNotFound(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/00000000-0000-0000-0000-000000000000", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Auth ---

func TestSuperadminRoutesRequireAdminKey(t *testing.T) {
	ts, _ := setupTestServer(t)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/superadmins", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Security ---

func TestPasswordNeverInResponse(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp := createSuperadmin(t, ts.URL, validSuperadminBody("pwleak@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	_, hasPwdCreate := created["password"]
	assert.False(t, hasPwdCreate, "password must not appear in create response")

	getResp := adminReq(t, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	got := decodeJSON(t, getResp)
	_, hasPwdGet := got["password"]
	assert.False(t, hasPwdGet, "password must not appear in get response")
}
