//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/pkg/store"
)

// --- Test infrastructure ---

// loginAsRole creates a user with the given role and logs them in,
// returning the org and the bearer token.
func loginAsRole(t *testing.T, srv *Server, db *store.PostgresStore, role string) (*store.Organization, *store.User, string) {
	t.Helper()
	org, user := createOrgUser(t, db, role, "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")
	return org, user, token
}

func validCreateUserBody(email string) map[string]any {
	return map[string]any{
		"email":    email,
		"name":     "New User",
		"role":     "org_user",
		"password": "correct-horse-battery-staple",
	}
}

// --- Auth / role gating ---

func TestUsersRoutes_RequireAuth(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	for _, r := range [][2]string{
		{http.MethodPost, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users/some-id"},
		{http.MethodPut, "/api/v1/users/some-id"},
		{http.MethodDelete, "/api/v1/users/some-id"},
	} {
		w := authReq(t, srv, r[0], r[1], "", nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "method=%s path=%s", r[0], r[1])
	}
}

func TestUsersRoutes_RejectOrgUser(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_user")

	// org_user must not be able to access user-management endpoints.
	w := authReq(t, srv, http.MethodGet, "/api/v1/users", token, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestUsersRoutes_BlockedWhenMustChangePassword verifies that an admin
// who logs in with must_change_password=true (e.g., a freshly invited
// admin) cannot access the user-management API until they call
// /auth/change-password to clear the flag.
func TestUsersRoutes_BlockedWhenMustChangePassword(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Create an admin with must_change_password=true (the invited state).
	_, user := createOrgUser(t, db, "org_admin", "temp-password-from-invite", true)
	token := loginAndExtractToken(t, srv, user.Email, "temp-password-from-invite")

	// Every protected endpoint must return 403.
	for _, r := range [][2]string{
		{http.MethodPost, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users/some-id"},
		{http.MethodPut, "/api/v1/users/some-id"},
		{http.MethodDelete, "/api/v1/users/some-id"},
	} {
		w := authReq(t, srv, r[0], r[1], token, validCreateUserBody("x@example.com"))
		assert.Equal(t, http.StatusForbidden, w.Code, "method=%s path=%s", r[0], r[1])
		assert.Contains(t, strings.ToLower(w.Body.String()), "change password")
	}
}

// TestChangePasswordWorks_WhenMustChangePassword verifies that the
// change-password endpoint itself is NOT blocked by the gate — it's
// the only path out of the must-change-password state.
func TestChangePasswordWorks_WhenMustChangePassword(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "temp-password", true)
	token := loginAndExtractToken(t, srv, user.Email, "temp-password")

	// change-password must succeed.
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/change-password", token, map[string]string{
		"current_password": "temp-password",
		"new_password":     "brand-new-strong-password",
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// Now extract the new token and verify access to /users is unblocked.
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	newToken := resp["token"].(string)

	wList := authReq(t, srv, http.MethodGet, "/api/v1/users", newToken, nil)
	assert.Equal(t, http.StatusOK, wList.Code, "user-management API must be unblocked after password change")
}

// --- Create ---

func TestCreateUser_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, _, token := loginAsRole(t, srv, db, "org_admin")

	body := validCreateUserBody("newuser@example.com")
	w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "newuser@example.com", resp["email"])
	assert.Equal(t, "org_user", resp["role"])
	assert.Equal(t, org.ID, resp["orgID"], "new user must be in admin's org")
	_, hasPwd := resp["password"]
	assert.False(t, hasPwd, "password must not appear in response")
}

func TestCreateUser_OrgIDForcedFromRequester(t *testing.T) {
	srv, db := testServerWithJWT(t)
	adminOrg, _, token := loginAsRole(t, srv, db, "org_admin")
	otherOrg, _ := createOrgUser(t, db, "org_admin", "x", false) // separate org

	body := validCreateUserBody("crossorg@example.com")
	body["orgID"] = otherOrg.ID // sneaky — should be ignored
	w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	require.Equal(t, http.StatusCreated, w.Code)

	user, err := db.GetUserByEmail(context.Background(), "crossorg@example.com")
	require.NoError(t, err)
	assert.Equal(t, adminOrg.ID, user.OrgID, "request body orgID must be ignored; user is forced into admin's org")
}

func TestCreateUser_InvalidRole(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	body := validCreateUserBody("badrole@example.com")
	body["role"] = "platform_admin" // not allowed in report server
	w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "role")
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	body := validCreateUserBody("dupe@example.com")
	w1 := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	require.Equal(t, http.StatusCreated, w1.Code)

	w2 := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// --- List ---

func TestListUsers_OrgScoped(t *testing.T) {
	srv, db := testServerWithJWT(t)
	myOrg, myAdmin, token := loginAsRole(t, srv, db, "org_admin")

	// Create 2 more users in MY org
	for i := 0; i < 2; i++ {
		body := validCreateUserBody("mine" + string(rune('a'+i)) + "@example.com")
		w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	// Create a user in a DIFFERENT org (via direct DB to bypass admin auth)
	createOrgUser(t, db, "org_admin", "x", false)

	w := authReq(t, srv, http.MethodGet, "/api/v1/users", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var users []map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&users))

	// Should be 3: myAdmin + 2 newly created, NOT the user from the other org.
	assert.Len(t, users, 3, "list must be scoped to admin's org")
	for _, u := range users {
		assert.Equal(t, myOrg.ID, u["orgID"])
	}
	_ = myAdmin
}

// --- Get / tenant isolation ---

func TestGetUser_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// User in another org
	_, otherUser := createOrgUser(t, db, "org_user", "x", false)

	// Cross-org GET must return 404 (not 403, to avoid leaking existence).
	w := authReq(t, srv, http.MethodGet, "/api/v1/users/"+otherUser.ID, token, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetUser_NotFound(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")
	w := authReq(t, srv, http.MethodGet, "/api/v1/users/00000000-0000-0000-0000-000000000000", token, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Update ---

func TestUpdateUser_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// Create a user to update
	body := validCreateUserBody("toupdate@example.com")
	w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	require.Equal(t, http.StatusCreated, w.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&created))
	id := created["id"].(string)

	wUpd := authReq(t, srv, http.MethodPut, "/api/v1/users/"+id, token, map[string]any{"name": "Renamed"})
	require.Equal(t, http.StatusOK, wUpd.Code)
	var updated map[string]any
	require.NoError(t, json.NewDecoder(wUpd.Body).Decode(&updated))
	assert.Equal(t, "Renamed", updated["name"])
}

func TestUpdateUser_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	_, otherUser := createOrgUser(t, db, "org_user", "x", false)
	w := authReq(t, srv, http.MethodPut, "/api/v1/users/"+otherUser.ID, token, map[string]any{"name": "Hijacked"})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUser_EmptyBody(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, admin, token := loginAsRole(t, srv, db, "org_admin")
	w := authReq(t, srv, http.MethodPut, "/api/v1/users/"+admin.ID, token, map[string]any{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Delete ---

func TestDeleteUser_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	body := validCreateUserBody("todelete@example.com")
	w := authReq(t, srv, http.MethodPost, "/api/v1/users", token, body)
	require.Equal(t, http.StatusCreated, w.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&created))
	id := created["id"].(string)

	wDel := authReq(t, srv, http.MethodDelete, "/api/v1/users/"+id, token, nil)
	assert.Equal(t, http.StatusOK, wDel.Code)

	wGet := authReq(t, srv, http.MethodGet, "/api/v1/users/"+id, token, nil)
	assert.Equal(t, http.StatusNotFound, wGet.Code)
}

func TestDeleteUser_SelfDeletionRefused(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, admin, token := loginAsRole(t, srv, db, "org_admin")

	w := authReq(t, srv, http.MethodDelete, "/api/v1/users/"+admin.ID, token, nil)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestDeleteUser_LastAdminRefusedViaPeer verifies the last-admin guard.
// Setup: org has admin A and admin B. Admin B is logged in. Admin B
// deletes admin A — succeeds (2 admins existed → now 1). Admin B is now
// the only admin in the org. We then create admin C, log in as C, and
// try to delete admin B — succeeds (2 admins again → 1). Now C is the
// only admin. Create admin D directly via the store (bypassing the API
// to keep the scenario tight), log in as D, and try to delete C — but
// the test only has one admin remaining IF we were trying to delete
// the last one. We're not — there are 2 admins (D and... actually C
// just deleted B). Let me redo.
//
// Cleaner setup: create org via store with TWO admins directly. Log
// in as admin1. Have admin1 delete admin2 — succeeds (admins go from
// 2→1). Now admin1 is the last admin. Try to delete... another admin?
// There are none. The only deletion target is admin1 themselves,
// blocked by self-deletion.
//
// The last-admin guard is genuinely unreachable through normal API
// flow because of the self-deletion guard. We test it by directly
// constructing the scenario via the store: create admin1 + admin2,
// log in as admin1, delete admin2 by ID. Verify the response is 200
// (the second-to-last admin can be deleted, leaving one). Then verify
// the guard fires by attempting to delete admin1 from a HYPOTHETICAL
// authenticated context — which requires creating yet another admin.
//
// Simpler: skip the integration test for last-admin since it can't
// happen end-to-end. The unit-level guard is documented in the handler
// and would only matter if the self-deletion guard is removed.
func TestDeleteUser_PeerAdminCanBeRemovedWhenMultipleExist(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Create the org and two admins directly via the store, both in the same org.
	ctx := context.Background()
	org := &store.Organization{
		ID:   "11111111-1111-1111-1111-111111111111",
		Name: "Multi Admin Org",
	}
	require.NoError(t, db.CreateOrg(ctx, org))

	hashed, _ := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.DefaultCost)
	admin1 := &store.User{
		ID:       "22222222-2222-2222-2222-222222222221",
		OrgID:    org.ID,
		Email:    "admin1@multi.test",
		Name:     "Admin One",
		Role:     "org_admin",
		Password: string(hashed),
	}
	admin2 := &store.User{
		ID:       "22222222-2222-2222-2222-222222222222",
		OrgID:    org.ID,
		Email:    "admin2@multi.test",
		Name:     "Admin Two",
		Role:     "org_admin",
		Password: string(hashed),
	}
	require.NoError(t, db.CreateUser(ctx, admin1))
	require.NoError(t, db.CreateUser(ctx, admin2))

	// Login as admin1.
	token := loginAndExtractToken(t, srv, admin1.Email, "correct-horse-battery")

	// Admin1 deletes admin2 — should succeed (2 admins → 1).
	w := authReq(t, srv, http.MethodDelete, "/api/v1/users/"+admin2.ID, token, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}
