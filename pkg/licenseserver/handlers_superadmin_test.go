//go:build integration

package licenseserver_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

// createSuperadmin posts a superadmin and returns the parsed response.
func createSuperadmin(t *testing.T, tsURL, jwt string, body map[string]any) *http.Response {
	t.Helper()
	return adminReq(t, jwt, http.MethodPost, tsURL+"/api/v1/admin/superadmins", body)
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
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("alice@example.com"))
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
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	wantEmails := []string{"a@example.com", "b@example.com", "c@example.com"}
	for _, email := range wantEmails {
		resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody(email))
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	}

	resp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	// The schema also contains the setup admin user created by quickAdminJWT,
	// so there is at least len(wantEmails) + 1 entries.
	assert.GreaterOrEqual(t, len(list), len(wantEmails))
	gotEmails := make([]string, 0, len(list))
	for _, u := range list {
		gotEmails = append(gotEmails, u["email"].(string))
	}
	for _, e := range wantEmails {
		assert.Contains(t, gotEmails, e)
	}
}

func TestGetSuperadmin(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("get@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	getResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
	got := decodeJSON(t, getResp)
	assert.Equal(t, id, got["id"])
	assert.Equal(t, "get@example.com", got["email"])
}

func TestUpdateSuperadminName(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("rename@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	updateResp := adminReq(t, jwt, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{
		"name": "New Name",
	})
	defer updateResp.Body.Close()
	require.Equal(t, http.StatusOK, updateResp.StatusCode)
	updated := decodeJSON(t, updateResp)
	assert.Equal(t, "New Name", updated["name"])
}

func TestUpdateSuperadminPassword(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("pwchange@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	// Capture original hash via store directly.
	original, err := store.GetUser(t.Context(), id)
	require.NoError(t, err)
	originalHash := original.Password

	updateResp := adminReq(t, jwt, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{
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
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	// Create two superadmins so deleting one doesn't trip the last-admin guard.
	resp1 := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("keeper@example.com"))
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	resp1.Body.Close()

	resp2 := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("delete@example.com"))
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
	created := decodeJSON(t, resp2)
	resp2.Body.Close()
	id := created["id"].(string)

	delResp := adminReq(t, jwt, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusOK, delResp.StatusCode)
	delBody := decodeJSON(t, delResp)
	assert.Equal(t, "deleted", delBody["status"])

	getResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// TestDeleteLastSuperadminRefused verifies that the final platform_admin
// cannot be deleted, preventing permanent admin lockout of the license
// server. Without this guard, an operator who deletes all but one admin
// and then deletes the last would need to directly manipulate the DB to
// recover.
func TestDeleteLastSuperadminRefused(t *testing.T) {
	ts, store := setupTestServer(t)
	setupEmail, _ := setupAdminUser(t, store)
	jwt := loginViaAPI(t, ts.URL, setupEmail, "TestPassword123!")

	// Create a second admin with a known password so we can log in as them later.
	const onlyPwd = "correct-horse-battery-staple"
	onlyBody := map[string]any{
		"email": "only@example.com", "name": "Only Admin", "password": onlyPwd,
	}
	resp := createSuperadmin(t, ts.URL, jwt, onlyBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	onlyID := created["id"].(string)

	// Delete the setup admin so that "only@example.com" is the sole admin.
	listResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var list []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&list))
	listResp.Body.Close()
	var setupAdminID string
	for _, u := range list {
		if u["email"].(string) == setupEmail {
			setupAdminID = u["id"].(string)
		}
	}
	require.NotEmpty(t, setupAdminID, "could not find setup admin in list")
	delSetup := adminReq(t, jwt, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+setupAdminID, nil)
	delSetup.Body.Close()
	require.Equal(t, http.StatusOK, delSetup.StatusCode)

	// The setup admin's JWT is now invalidated (user deleted). Log in as the
	// sole remaining admin to get a fresh token.
	onlyJWT := loginViaAPI(t, ts.URL, "only@example.com", onlyPwd)

	// Now only "only@example.com" remains — deleting it must be refused.
	delResp := adminReq(t, onlyJWT, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+onlyID, nil)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusConflict, delResp.StatusCode)

	// And the user must still exist.
	getResp := adminReq(t, onlyJWT, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+onlyID, nil)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
}

// --- Validation edge cases ---

// errorBody decodes a 4xx response and returns the "error" string from
// the standard {"error": "..."} envelope. Used to assert WHY a validation
// failed rather than just THAT it failed (preventing tests from passing
// for the wrong reason — e.g., a body parse error returning 400 with a
// message about JSON, rather than the field-specific message we expected).
func errorBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body := decodeJSON(t, resp)
	msg, _ := body["error"].(string)
	return msg
}

func TestCreateSuperadminMissingEmail(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
		"name":     "No Email",
		"password": "correct-horse-battery-staple",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, strings.ToLower(errorBody(t, resp)), "email")
}

func TestCreateSuperadminMissingPassword(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
		"email": "nopw@example.com",
		"name":  "No Password",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, strings.ToLower(errorBody(t, resp)), "password")
}

func TestCreateSuperadminWeakPassword(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
		"email":    "weak@example.com",
		"name":     "Weak Pwd",
		"password": "short",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, strings.ToLower(errorBody(t, resp)), "password")
}

func TestCreateSuperadminInvalidEmail(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
		"email":    "notanemail",
		"name":     "Bad Email",
		"password": "correct-horse-battery-staple",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, strings.ToLower(errorBody(t, resp)), "email")
}

func TestCreateSuperadminDuplicateEmail(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp1 := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("dup@example.com"))
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	resp1.Body.Close()

	resp2 := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("dup@example.com"))
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestCreateSuperadminIgnoresRole(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
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
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("emptyput@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	updateResp := adminReq(t, jwt, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{})
	defer updateResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, updateResp.StatusCode)
}

func TestGetSuperadminNotFound(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/00000000-0000-0000-0000-000000000000", nil)
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
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("pwleak@example.com"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	id := created["id"].(string)

	_, hasPwdCreate := created["password"]
	assert.False(t, hasPwdCreate, "password must not appear in create response")

	// GET single
	getResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins/"+id, nil)
	defer getResp.Body.Close()
	got := decodeJSON(t, getResp)
	_, hasPwdGet := got["password"]
	assert.False(t, hasPwdGet, "password must not appear in get response")

	// LIST — must not leak password on any element
	listResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
	defer listResp.Body.Close()
	var listBody []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	require.NotEmpty(t, listBody)
	for _, item := range listBody {
		_, hasPwdList := item["password"]
		assert.False(t, hasPwdList, "password must not appear in list response items")
	}

	// UPDATE — response is the updated user, must not leak password
	updateResp := adminReq(t, jwt, http.MethodPut, ts.URL+"/api/v1/admin/superadmins/"+id, map[string]any{
		"name": "Renamed",
	})
	defer updateResp.Body.Close()
	require.Equal(t, http.StatusOK, updateResp.StatusCode)
	updated := decodeJSON(t, updateResp)
	_, hasPwdUpdate := updated["password"]
	assert.False(t, hasPwdUpdate, "password must not appear in update response")
}
