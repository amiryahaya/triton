//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
)

// withChiParam injects a chi URL parameter into the request context so
// handler tests can call handlers directly without going through the
// router (routes aren't wired until Task 11).
func withChiParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// seedPlatformAdmin inserts a platform_admin user directly into the store,
// bypassing the HTTP endpoint, so tests can exercise read/delete handlers
// without depending on the invite handler.
func seedPlatformAdmin(t *testing.T, db *store.PostgresStore, email string) *store.User {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.DefaultCost)
	require.NoError(t, err)
	now := time.Now().UTC()
	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              "",
		Email:              email,
		Name:               "Platform Admin",
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		InvitedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	require.NoError(t, db.CreateUser(context.Background(), user))
	return user
}

// platformAdminReq is a thin helper that calls a handler directly
// (bypassing the router) and returns the recorded response.
func platformAdminReq(t *testing.T, srv *Server, method string, body any, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, "/api/v1/platform/admins", &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// TestHandleListPlatformAdmins verifies that the list handler returns the
// seeded platform admin as the only entry.
func TestHandleListPlatformAdmins(t *testing.T) {
	srv, db := testServerWithJWT(t)
	seedPlatformAdmin(t, db, "pa1@example.com")

	rr := platformAdminReq(t, srv, http.MethodGet, nil, srv.handleListPlatformAdmins)

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var users []store.User
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&users))
	assert.Len(t, users, 1)
	assert.Equal(t, "pa1@example.com", users[0].Email)
	assert.Equal(t, "platform_admin", users[0].Role)
}

// TestHandleInvitePlatformAdmin verifies that the invite handler creates a
// platform admin and returns 201 with the new user's id and a tempPassword.
func TestHandleInvitePlatformAdmin(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	rr := platformAdminReq(t, srv, http.MethodPost, map[string]string{
		"name":  "Bob Platform",
		"email": "bob.platform@example.com",
	}, srv.handleInvitePlatformAdmin)

	require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotEmpty(t, resp["id"], "response must include the new user's id")
	assert.NotEmpty(t, resp["tempPassword"], "response must include the temp password")
	assert.GreaterOrEqual(t, len(resp["tempPassword"]), auth.MinPasswordLength,
		"generated temp password must satisfy policy length")
}

// TestHandleDeletePlatformAdmin_CannotDeleteSelf verifies that trying to
// delete your own ID returns 400.
func TestHandleDeletePlatformAdmin_CannotDeleteSelf(t *testing.T) {
	srv, db := testServerWithJWT(t)
	admin := seedPlatformAdmin(t, db, "self@example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/platform/admins/"+admin.ID, nil)
	// Inject chi URL param since we're calling the handler directly.
	req = withChiParam(req, "id", admin.ID)
	// Inject JWT claims so ClaimsFromContext returns the same user ID.
	claims := &auth.UserClaims{Sub: admin.ID, Role: "platform_admin"}
	req = req.WithContext(contextWithClaims(req.Context(), claims))

	rr := httptest.NewRecorder()
	srv.handleDeletePlatformAdmin(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code,
		"deleting yourself must return 400, body: %s", rr.Body.String())
}

// TestHandlePlatformAdmins_RequiresValidInput verifies that an empty email
// in the invite request returns 400.
func TestHandlePlatformAdmins_RequiresValidInput(t *testing.T) {
	srv, _ := testServerWithJWT(t)

	rr := platformAdminReq(t, srv, http.MethodPost, map[string]string{
		"name":  "No Email",
		"email": "", // missing
	}, srv.handleInvitePlatformAdmin)

	assert.Equal(t, http.StatusBadRequest, rr.Code,
		"empty email must return 400, body: %s", rr.Body.String())
}
