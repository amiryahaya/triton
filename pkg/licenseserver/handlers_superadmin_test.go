//go:build integration

package licenseserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

// createSuperadmin posts a superadmin and returns the raw *http.Response.
func createSuperadmin(t *testing.T, tsURL, jwt string, body map[string]any) *http.Response {
	t.Helper()
	return adminReq(t, jwt, http.MethodPost, tsURL+"/api/v1/admin/superadmins", body)
}

// validSuperadminBody returns a body that should always pass validation.
// The password field is omitted — the handler now generates a temp password.
func validSuperadminBody(email string) map[string]any {
	return map[string]any{
		"email": email,
		"name":  "Test Admin",
	}
}

// userFromCreateResp extracts the nested "user" map from a 201 create response.
func userFromCreateResp(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	user, ok := resp["user"].(map[string]any)
	require.True(t, ok, "create response missing 'user' field: %v", resp)
	return user
}

// postLogin POSTs to /api/v1/auth/login and returns adminResponse
// regardless of status code. Used to assert failure paths.
func postLogin(t *testing.T, tsURL, email, password string) adminResponse {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, tsURL+"/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return adminResponse{Code: resp.StatusCode, Body: body}
}

// --- Happy paths ---

func TestCreateSuperadmin(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, validSuperadminBody("alice@example.com"))
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	body := decodeJSON(t, resp)
	user := userFromCreateResp(t, body)
	assert.NotEmpty(t, user["id"])
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, "Test Admin", user["name"])
	assert.Equal(t, "platform_admin", user["role"])
	assert.Equal(t, true, user["mustChangePassword"])
	_, hasPwd := user["password"]
	assert.False(t, hasPwd, "password field must not appear in user response")
	assert.NotEmpty(t, body["tempPassword"], "create response must include tempPassword")
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
	id := userFromCreateResp(t, created)["id"].(string)

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
	id := userFromCreateResp(t, created)["id"].(string)

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
	id := userFromCreateResp(t, created)["id"].(string)

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
	id := userFromCreateResp(t, created)["id"].(string)

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
	// Create two admins: setup (will be deleted to leave only one) and the target
	// solo admin (whose delete must then be refused).
	setupEmail, _ := setupAdminUser(t, store)
	setupJWT := loginViaAPI(t, ts.URL, setupEmail, "TestPassword123!")

	// Create the solo admin via API; capture its temp password.
	resp := createSuperadmin(t, ts.URL, setupJWT, map[string]any{
		"email": "only@example.com", "name": "Only Admin",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decodeJSON(t, resp)
	resp.Body.Close()
	onlyID := userFromCreateResp(t, created)["id"].(string)
	onlyTempPwd := created["tempPassword"].(string)

	// Log in as the solo admin and change the temp password so that
	// BlockUntilPasswordChanged lets subsequent admin-API calls through.
	onlyJWT := loginViaAPI(t, ts.URL, "only@example.com", onlyTempPwd)
	const onlyNewPwd = "OnlyNewPwd1234!"
	chg := authedDo(t, ts.URL, onlyJWT, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"current": onlyTempPwd, "next": onlyNewPwd})
	require.Equal(t, http.StatusOK, chg.Code)
	onlyJWT = chg.Body["token"].(string)

	// The solo admin deletes the setup admin (cross-delete — not self-delete).
	// After this, "only@example.com" is the sole remaining platform_admin.
	listResp := adminReq(t, setupJWT, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
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
	// The solo admin (onlyJWT) deletes the setup admin — not a self-delete.
	delSetup := adminReq(t, onlyJWT, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+setupAdminID, nil)
	delSetup.Body.Close()
	require.Equal(t, http.StatusOK, delSetup.StatusCode)

	// Now only "only@example.com" remains — deleting it must be refused
	// (last-platform-admin guard, not the self-delete guard).
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
		"name": "No Email",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, strings.ToLower(errorBody(t, resp)), "email")
}

func TestCreateSuperadminInvalidEmail(t *testing.T) {
	ts, store := setupTestServer(t)
	jwt := quickAdminJWT(t, ts, store)
	resp := createSuperadmin(t, ts.URL, jwt, map[string]any{
		"email": "notanemail",
		"name":  "Bad Email",
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
		"email": "sneaky@example.com",
		"name":  "Sneaky",
		"role":  "org_user", // should be ignored
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decodeJSON(t, resp)
	user := userFromCreateResp(t, body)
	assert.Equal(t, "platform_admin", user["role"], "role from request body must be ignored")
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
	id := userFromCreateResp(t, created)["id"].(string)

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
	user := userFromCreateResp(t, created)
	id := user["id"].(string)

	// The top-level create response should NOT expose the bcrypt hash directly
	// on the user object (tempPassword is a plaintext invite token — fine).
	_, hasPwdCreate := user["password"]
	assert.False(t, hasPwdCreate, "password hash must not appear in user create response")

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

// --- Invite flow ---

func TestCreateSuperadmin_GeneratesTempPassword(t *testing.T) {
	ts, cfg := setupTestServer(t)
	email, password := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, email, password)

	resp := adminDo(t, ts.URL, jwt, http.MethodPost, "/api/v1/admin/superadmins",
		map[string]any{"name": "Bob", "email": "bob@example.com"})
	require.Equal(t, http.StatusCreated, resp.Code)
	assert.NotEmpty(t, resp.Body["tempPassword"])
	user := resp.Body["user"].(map[string]any)
	assert.Equal(t, true, user["mustChangePassword"])
	assert.Equal(t, "bob@example.com", user["email"])
}

func TestResendInvite_RegeneratesPassword(t *testing.T) {
	ts, cfg := setupTestServer(t)
	adminEmail, adminPw := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, adminEmail, adminPw)

	// Create target user.
	create := adminDo(t, ts.URL, jwt, http.MethodPost, "/api/v1/admin/superadmins",
		map[string]any{"name": "Carol", "email": "carol@example.com"})
	require.Equal(t, http.StatusCreated, create.Code)
	userID := create.Body["user"].(map[string]any)["id"].(string)
	oldTemp := create.Body["tempPassword"].(string)

	// Resend.
	resend := adminDo(t, ts.URL, jwt, http.MethodPost,
		"/api/v1/admin/superadmins/"+userID+"/resend-invite", nil)
	require.Equal(t, http.StatusOK, resend.Code)
	newTemp := resend.Body["tempPassword"].(string)
	assert.NotEqual(t, oldTemp, newTemp, "resend must rotate the password")

	// Old temp must no longer work.
	oldLogin := postLogin(t, ts.URL, "carol@example.com", oldTemp)
	assert.Equal(t, http.StatusUnauthorized, oldLogin.Code)

	// New temp must work.
	newLogin := postLogin(t, ts.URL, "carol@example.com", newTemp)
	assert.Equal(t, http.StatusOK, newLogin.Code)
}

func TestDeleteSuperadmin_SelfBlocked_Returns409(t *testing.T) {
	ts, cfg := setupTestServer(t)
	// Create the first admin so last-user guard doesn't fire when the
	// second admin attempts self-delete.
	_, _ = setupAdminUser(t, cfg)

	// Create a second admin via the store and log in as them.
	secondEmail, secondPw := setupAdminUser(t, cfg)
	jwt := loginViaAPI(t, ts.URL, secondEmail, secondPw)

	// Look up the second admin's ID from the list.
	// handleListSuperadmins returns a bare JSON array.
	listResp := adminReq(t, jwt, http.MethodGet, ts.URL+"/api/v1/admin/superadmins", nil)
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var rawList []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&rawList))
	var selfID string
	for _, u := range rawList {
		if u["email"] == secondEmail {
			selfID = u["id"].(string)
			break
		}
	}
	require.NotEmpty(t, selfID, "second admin not found in list")

	del := adminReq(t, jwt, http.MethodDelete, ts.URL+"/api/v1/admin/superadmins/"+selfID, nil)
	defer del.Body.Close()
	assert.Equal(t, http.StatusConflict, del.StatusCode)
}
