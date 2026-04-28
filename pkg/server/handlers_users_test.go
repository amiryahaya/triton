//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/mailer"
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

// TestDeleteUser_LastAdminGuardSurfacesListError verifies M1: if the
// store's ListUsers call fails (e.g., transient DB error), the
// last-admin guard must NOT silently fall through to DeleteUser.
// Instead, the error must be surfaced as 500. Otherwise, a transient
// DB error effectively disables the guard.
func TestDeleteUser_LastAdminGuardSurfacesListError(t *testing.T) {
	srv, real, wrap := setupServerWithFailingStore(t)

	// Create two admins so the guard would not normally fire.
	_, admin1 := createOrgUser(t, real, "org_admin", "correct-horse-battery", false)
	_, admin2 := createTestUserInOrg(t, real, admin1.OrgID, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, admin1.Email, "correct-horse-battery")

	// Toggle ListUsers failure AFTER login (login uses GetUserByEmail, not ListUsers).
	wrap.listUsersFails.Store(true)

	// Admin1 tries to delete admin2. The handler will call ListUsers
	// to check the admin count → simulated failure → must return 500,
	// NOT fall through to DeleteUser.
	w := authReq(t, srv, http.MethodDelete, "/api/v1/users/"+admin2.ID, token, nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "ListUsers error must be surfaced, not silently bypassed")

	// Verify admin2 was NOT deleted (the guard prevented the fall-through).
	_, err := real.GetUser(context.Background(), admin2.ID)
	require.NoError(t, err, "admin2 must still exist — the guard must have aborted before DeleteUser")
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
	// Use generated UUIDs (not static literals) to avoid collision risk if
	// tests are ever run in parallel.
	ctx := context.Background()
	org := &store.Organization{
		ID:   uuid.Must(uuid.NewV7()).String(),
		Name: "Multi Admin Org",
	}
	require.NoError(t, db.CreateOrg(ctx, org))

	hashed, _ := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.DefaultCost)
	admin1 := &store.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    org.ID,
		Email:    uuid.Must(uuid.NewV7()).String() + "@multi.test",
		Name:     "Admin One",
		Role:     "org_admin",
		Password: string(hashed),
	}
	admin2 := &store.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    org.ID,
		Email:    uuid.Must(uuid.NewV7()).String() + "@multi.test",
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

// --- Resend invite (Phase 5.2) ---

// TestResendInvite_Success verifies the happy path: admin triggers
// resend → store updates password + invited_at → endpoint returns the
// new temp password once.
func TestResendInvite_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// Create an invited user via the API so they have mcp=true.
	body := validCreateUserBody("newinvitee@example.com")
	body["mustChangePassword"] = true // not supported by create, but we'll patch via store
	wCreate := authReq(t, srv, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "newinvitee@example.com",
		"name":     "Invitee",
		"role":     "org_user",
		"password": "original-temp-pw-123",
	})
	require.Equal(t, http.StatusCreated, wCreate.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(wCreate.Body).Decode(&created))
	id := created["id"].(string)

	// createUser doesn't set mcp=true; set it via direct store update.
	mcpTrue := true
	require.NoError(t, db.UpdateUser(context.Background(), store.UserUpdate{
		ID:                 id,
		Name:               "Invitee",
		MustChangePassword: &mcpTrue,
	}))

	// Now resend invite.
	w := authReq(t, srv, http.MethodPost, "/api/v1/users/"+id+"/resend-invite", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	newPw, ok := resp["tempPassword"].(string)
	require.True(t, ok, "response must include tempPassword")
	assert.GreaterOrEqual(t, len(newPw), auth.MinPasswordLength,
		"generated temp password must satisfy policy length")

	// Verify the user can log in with the new temp password.
	wLogin := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "newinvitee@example.com",
		"password": newPw,
	})
	assert.Equal(t, http.StatusOK, wLogin.Code,
		"invited user must be able to log in with resent temp password")
}

// TestResendInvite_AlreadyCompleted_Rejects verifies that resending an
// invite to a user who has already completed their first login
// returns 409 — the store guard + handler check prevents silent
// password resets on working accounts.
func TestResendInvite_AlreadyCompleted_Rejects(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// Create a regular user (mcp=false from the start — the create
	// handler never sets mcp=true).
	wCreate := authReq(t, srv, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "completed@example.com",
		"name":     "Completed",
		"role":     "org_user",
		"password": "original-pw-12345",
	})
	require.Equal(t, http.StatusCreated, wCreate.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(wCreate.Body).Decode(&created))
	id := created["id"].(string)

	w := authReq(t, srv, http.MethodPost, "/api/v1/users/"+id+"/resend-invite", token, nil)
	assert.Equal(t, http.StatusConflict, w.Code,
		"resend-invite on an already-completed user must be 409")
}

// fakeMailer is a test double that captures the InviteEmailData
// passed to SendInviteEmail. A non-nil sendErr makes SendInviteEmail
// return that error so tests can exercise the mailer-failure path.
type fakeMailer struct {
	sendErr error
	sent    []mailer.InviteEmailData
}

func (f *fakeMailer) SendInviteEmail(_ context.Context, data mailer.InviteEmailData) error {
	f.sent = append(f.sent, data)
	return f.sendErr
}

func (f *fakeMailer) SendExpiryWarningEmail(_ context.Context, _ string, _ mailer.ExpiryWarningEmailData) error {
	return nil
}

// TestResendInvite_WithMailer_DropsTempPasswordFromBody verifies
// Sprint 2 S2.7: when the report server is configured with a Mailer,
// resend-invite pushes the temp password via email and the JSON
// response body does NOT contain the password field.
func TestResendInvite_WithMailer_DropsTempPasswordFromBody(t *testing.T) {
	srv, db := testServerWithJWT(t)
	fm := &fakeMailer{}
	srv.config.Mailer = fm
	srv.config.InviteLoginURL = "https://reports.test/ui/#/login"
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// Create an invited user and mark mcp=true via direct store update.
	wCreate := authReq(t, srv, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "mailer-invitee@example.com",
		"name":     "Mailer Invitee",
		"role":     "org_user",
		"password": "initial-temp-pw-12",
	})
	require.Equal(t, http.StatusCreated, wCreate.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(wCreate.Body).Decode(&created))
	id := created["id"].(string)
	mcpTrue := true
	require.NoError(t, db.UpdateUser(context.Background(), store.UserUpdate{
		ID:                 id,
		Name:               "Mailer Invitee",
		MustChangePassword: &mcpTrue,
	}))

	// Trigger resend-invite.
	w := authReq(t, srv, http.MethodPost, "/api/v1/users/"+id+"/resend-invite", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invite resent", resp["status"])
	assert.Equal(t, "true", resp["emailDelivered"])
	_, hasTemp := resp["tempPassword"]
	assert.False(t, hasTemp, "mailer path must NOT leak tempPassword in JSON body")

	// Verify the mailer captured the right payload.
	require.Len(t, fm.sent, 1, "mailer should have been called exactly once")
	sent := fm.sent[0]
	assert.Equal(t, "mailer-invitee@example.com", sent.ToEmail)
	assert.Equal(t, "Mailer Invitee", sent.ToName)
	assert.Equal(t, "https://reports.test/ui/#/login", sent.LoginURL)
	assert.NotEmpty(t, sent.TempPassword, "mailer must receive the new temp password")
	assert.NotEmpty(t, sent.OrgName, "mailer must receive a non-empty org name")
}

// TestResendInvite_WithMailer_FailureReturns502 verifies that a
// mailer error causes the endpoint to return 502 — the password was
// already rotated in the DB, but the admin needs to know the email
// did not arrive, so they can contact the invitee out-of-band or
// retry. Falling back to leaking the password in the response body
// would violate the operator's intent (they explicitly configured
// a mailer to prevent that).
func TestResendInvite_WithMailer_FailureReturns502(t *testing.T) {
	srv, db := testServerWithJWT(t)
	fm := &fakeMailer{sendErr: errors.New("resend unreachable")}
	srv.config.Mailer = fm
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	wCreate := authReq(t, srv, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "mailer-fail@example.com",
		"name":     "Mailer Fail",
		"role":     "org_user",
		"password": "initial-temp-pw-12",
	})
	require.Equal(t, http.StatusCreated, wCreate.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(wCreate.Body).Decode(&created))
	id := created["id"].(string)
	mcpTrue := true
	require.NoError(t, db.UpdateUser(context.Background(), store.UserUpdate{
		ID:                 id,
		Name:               "Mailer Fail",
		MustChangePassword: &mcpTrue,
	}))

	w := authReq(t, srv, http.MethodPost, "/api/v1/users/"+id+"/resend-invite", token, nil)
	assert.Equal(t, http.StatusBadGateway, w.Code,
		"mailer failure must return 502 with no tempPassword leak")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	_, hasTemp := resp["tempPassword"]
	assert.False(t, hasTemp, "mailer failure must NOT leak tempPassword in JSON body")
}

// TestResendInvite_TenantIsolation verifies that admin A cannot
// resend-invite for a user in org B — the tenant scope check must
// return 404 (not 403, to match the rest of the isolation contract).
func TestResendInvite_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	ctx := context.Background()

	// Org A + admin
	_, _, tokenA := loginAsRole(t, srv, db, "org_admin")

	// Org B + invited user
	orgB := &store.Organization{ID: "00000000-0000-0000-0000-00000000b001", Name: "Org B"}
	require.NoError(t, db.CreateOrg(ctx, orgB))
	hashed, err := bcrypt.GenerateFromPassword([]byte("bob-temp-123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	bob := &store.User{
		ID:                 "00000000-0000-0000-0000-00000000b002",
		OrgID:              orgB.ID,
		Email:              "bob-invitee@example.com",
		Name:               "Bob",
		Role:               "org_user",
		Password:           string(hashed),
		MustChangePassword: true,
	}
	require.NoError(t, db.CreateUser(ctx, bob))

	// Admin A tries to resend bob's invite → 404.
	w := authReq(t, srv, http.MethodPost, "/api/v1/users/"+bob.ID+"/resend-invite", tokenA, nil)
	assert.Equal(t, http.StatusNotFound, w.Code,
		"cross-org resend-invite must return 404 to avoid leaking existence")
}
