//go:build integration

package manageserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// seedExtraUser inserts an additional user directly via the store so
// the seat-cap test can reach the licence limit without having to drive
// through the HTTP handler (which itself is the subject under test).
func seedExtraUser(t *testing.T, store *managestore.PostgresStore, email, role string) {
	t.Helper()
	hash, err := manageserver.HashPassword("Password123!")
	require.NoError(t, err)
	u := &managestore.ManageUser{
		Email:        email,
		Name:         "seeded",
		Role:         role,
		PasswordHash: hash,
	}
	require.NoError(t, store.CreateUser(context.Background(), u))
}

// TestCreateUser_HappyPath exercises the successful admin-creates-user
// flow end-to-end. Asserts the 201 response carries the generated temp
// password and must_change_pw=true.
func TestCreateUser_HappyPath(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	body := map[string]string{
		"email": "engineer@example.com",
		"name":  "Net Eng",
		"role":  "network_engineer",
	}
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/users/", bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "engineer@example.com", out["email"])
	assert.Equal(t, "network_engineer", out["role"])
	assert.Equal(t, true, out["must_change_pw"])
	tempPW, ok := out["temp_password"].(string)
	require.True(t, ok && tempPW != "", "response must carry a non-empty temp_password")

	// Verify the user actually persisted and the generated password works.
	persisted, err := store.GetUserByEmail(context.Background(), "engineer@example.com")
	require.NoError(t, err)
	assert.True(t, persisted.MustChangePW)
	assert.NoError(t, manageserver.VerifyPassword(persisted.PasswordHash, tempPW))
}

// TestCreateUser_NonAdminRejected verifies that a logged-in
// network_engineer gets 403 from the RequireRole middleware — the
// handler body is never reached.
func TestCreateUser_NonAdminRejected(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Seed an admin so the store is consistent, plus a network_engineer
	// we'll actually log in as.
	_ = seedAdminUser(t, store)
	eng := "engineer-non-admin@example.com"
	seedExtraUser(t, store, eng, "network_engineer")
	token := loginViaHTTP(t, ts.URL, eng, "Password123!")

	body := map[string]string{"email": "another@example.com"}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/users/", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"network_engineer must be rejected by RequireRole(\"admin\")")
}

// TestCreateUser_SeatCapExceeded_Returns403 injects a fake licence guard
// that reports a seat cap of 3, seeds the store with 3 users already,
// and asserts that a fourth POST is rejected.
//
// Because Server.licenceGuard is an unexported *license.Guard field we
// can't swap in a fake; instead, this test reaches the cap via
// FakeGuardSeatsFromLicence — a helper mounted by WithFakeSeatGuard
// when such a hook is available. If the hook is not present the test
// skips rather than failing.
func TestCreateUser_SeatCapExceeded_Returns403(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	// Set a fake seat-cap guard of 3. Store currently has 0 users; we
	// seed the admin (1) + two engineers (3 total) so the 4th create
	// trips the cap.
	manageserver.SetSeatCapGuardForTest(srv, &fakeSeatCapGuard{caps: map[string]int64{"seats/total": 3}})
	defer manageserver.ClearSeatCapGuardForTest(srv)

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store) // 1 user
	for i := 0; i < 2; i++ {         // 2 more = 3 total
		seedExtraUser(t, store, fmt.Sprintf("user-%d@example.com", i), "network_engineer")
	}
	count, err := store.CountUsers(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(3), count)

	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	body := map[string]string{"email": "tipping-point@example.com"}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/users/", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"4th user must trip the seat cap (cap=3, current=3)")

	var out map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, out["error"], "seat cap")

	// Store must NOT have gained the fourth row.
	count, err = store.CountUsers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), count, "4th user must not have been persisted")
}

// fakeSeatCapGuard satisfies the seatCapGuard interface with a fixed
// map of "<metric>/<window>" -> cap. Values outside the map return -1
// (unlimited).
type fakeSeatCapGuard struct {
	caps map[string]int64
}

func (f *fakeSeatCapGuard) LimitCap(metric, window string) int64 {
	if v, ok := f.caps[metric+"/"+window]; ok {
		return v
	}
	return -1
}

// TestListUsers_ReturnsAllUsersWithoutPasswordHash exercises the happy
// path: admin GETs the user list, gets 200 + an array of users that
// does NOT include password hash material.
func TestListUsers_ReturnsAllUsersWithoutPasswordHash(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	seedExtraUser(t, store, "engineer1@example.com", "network_engineer")
	seedExtraUser(t, store, "engineer2@example.com", "network_engineer")
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/users/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Len(t, out, 3, "admin + 2 seeded engineers")

	for _, row := range out {
		_, has := row["password_hash"]
		assert.False(t, has, "response must not carry password_hash")
		_, has = row["password"]
		assert.False(t, has, "response must not carry password")
	}
}

// TestListUsers_NonAdminRejected verifies RequireRole("admin")
// middleware continues to gate the new GET endpoint.
func TestListUsers_NonAdminRejected(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	_ = seedAdminUser(t, store)
	engineer := "engineer-gate@example.com"
	seedExtraUser(t, store, engineer, "network_engineer")
	token := loginViaHTTP(t, ts.URL, engineer, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/users/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestDeleteUser_HappyPath_NonAdminTarget: admin deletes an engineer.
// Row is gone, session rows are cascaded.
func TestDeleteUser_HappyPath_NonAdminTarget(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	seedExtraUser(t, store, "deleteme@example.com", "network_engineer")
	eng, err := store.GetUserByEmail(context.Background(), "deleteme@example.com")
	require.NoError(t, err)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/users/"+eng.ID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, err = store.GetUserByID(context.Background(), eng.ID)
	var nf *managestore.ErrNotFound
	assert.ErrorAs(t, err, &nf, "user row should be deleted")
}

// TestDeleteUser_SelfDeletePrevented: admin cannot delete their own
// row. Self-check fires before any DB round-trip.
func TestDeleteUser_SelfDeletePrevented(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	// Seed a second admin so the last-admin guard won't fire.
	seedExtraUser(t, store, "admin2@example.com", "admin")
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/users/"+admin.ID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "cannot delete your own account")

	_, err = store.GetUserByID(context.Background(), admin.ID)
	require.NoError(t, err, "admin row should still be present")
}

// TestDeleteUser_LastAdminPrevented exercises the last-admin guard
// directly at the handler level, bypassing jwtAuth + RequireRole
// middleware. This is necessary because jwtAuth does a live DB lookup:
// any scenario that makes CountAdmins==1 while a non-self admin is the
// target also means the caller's role would be network_engineer in DB,
// which RequireRole("admin") would reject before the handler runs.
//
// We use ContextWithUserForTest to inject a caller with role=admin in
// context (simulating what jwtAuth would do if the caller's DB row
// still said admin), then seed only the target in the DB as the sole
// admin so CountAdmins returns 1.
func TestDeleteUser_LastAdminPrevented(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	// Seed the target admin (the only admin in the system).
	seedExtraUser(t, store, "target-admin@example.com", "admin")
	target, err := store.GetUserByEmail(context.Background(), "target-admin@example.com")
	require.NoError(t, err)

	// Verify: exactly 1 admin in DB right now.
	n, err := store.CountAdmins(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	// Build a caller whose ID differs from the target so self-delete
	// guard doesn't fire. We inject this user via ContextWithUserForTest
	// (bypassing jwtAuth) to simulate the post-login race where the
	// caller's DB row was demoted after their session was created.
	callerID := "aaaaaaaa-0000-0000-0000-000000000001"
	caller := &managestore.ManageUser{
		ID:    callerID,
		Email: "ghost-caller@example.com",
		Role:  "admin",
	}

	// Inject chi URL param via the route context so chi.URLParam works
	// without needing the full router stack.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", target.ID)

	req, err := http.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+target.ID, nil)
	require.NoError(t, err)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = manageserver.ContextWithUserForTest(req, caller)

	rec := httptest.NewRecorder()
	manageserver.HandleDeleteUserForTest(srv, rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Contains(t, string(body), "cannot delete the last admin")
}

// TestDeleteUser_UnknownIDReturns404
func TestDeleteUser_UnknownIDReturns404(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(
		http.MethodDelete,
		ts.URL+"/api/v1/admin/users/00000000-0000-0000-0000-000000000000",
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDeleteUser_BadUUIDReturns400
func TestDeleteUser_BadUUIDReturns400(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(
		http.MethodDelete,
		ts.URL+"/api/v1/admin/users/not-a-uuid",
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
