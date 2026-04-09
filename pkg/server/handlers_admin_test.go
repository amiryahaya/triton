//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// --- helpers ---

// validProvisionBody returns a body that should always pass validation.
func validProvisionBody() map[string]any {
	return map[string]any{
		"id":                  uuid.Must(uuid.NewV7()).String(),
		"name":                "Acme Corp",
		"admin_email":         uuid.Must(uuid.NewV7()).String() + "@acme.com",
		"admin_name":          "Alice Admin",
		"admin_temp_password": "correct-horse-battery-staple",
	}
}

// provisionReq sends a provisioning request with the service key.
func provisionReq(t *testing.T, srv *Server, serviceKey string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if serviceKey != "" {
		req.Header.Set("X-Triton-Service-Key", serviceKey)
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

// --- Auth tests ---

func TestProvisionOrg_MissingServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := provisionReq(t, srv, "", validProvisionBody())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProvisionOrg_WrongServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := provisionReq(t, srv, "wrong-key", validProvisionBody())
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestProvisionOrg_RouteDisabledWithoutServiceKey(t *testing.T) {
	// A server without ServiceKey configured should not expose the route at all.
	srv, _ := testServer(t)
	w := provisionReq(t, srv, "", validProvisionBody())
	// 404 (route doesn't exist) is the expected outcome.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Happy path ---

func TestProvisionOrg_Success(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	body := validProvisionBody()
	w := provisionReq(t, srv, key, body)

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	org, ok := resp["org"].(map[string]any)
	require.True(t, ok, "response must contain org object")
	assert.Equal(t, body["id"], org["id"])
	assert.Equal(t, body["name"], org["name"])

	adminID, ok := resp["admin_user_id"].(string)
	require.True(t, ok, "response must contain admin_user_id")
	assert.NotEmpty(t, adminID)

	// Should not echo the password back.
	_, hasPwd := resp["admin_temp_password"]
	assert.False(t, hasPwd, "temp password must not appear in response")
}

func TestProvisionOrg_AdminUserPersisted(t *testing.T) {
	srv, db, key := testServerWithServiceKey(t)
	body := validProvisionBody()
	w := provisionReq(t, srv, key, body)
	require.Equal(t, http.StatusCreated, w.Code)

	// Verify the user was actually created in the DB.
	user, err := db.GetUserByEmail(context.Background(), body["admin_email"].(string))
	require.NoError(t, err)
	assert.Equal(t, "org_admin", user.Role)
	assert.Equal(t, body["id"], user.OrgID)
	assert.True(t, user.MustChangePassword, "invited admin must have must_change_password=true")

	// Password must be bcrypt-hashed (not stored in plaintext).
	plaintext := body["admin_temp_password"].(string)
	assert.NotEqual(t, plaintext, user.Password)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plaintext)))
}

// --- Idempotency ---

func TestProvisionOrg_IdempotentOnSameOrgID(t *testing.T) {
	srv, db, key := testServerWithServiceKey(t)
	body := validProvisionBody()

	w1 := provisionReq(t, srv, key, body)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Second call with the SAME body — license server retried.
	// Should not error; should not create a duplicate user.
	w2 := provisionReq(t, srv, key, body)
	assert.Equal(t, http.StatusOK, w2.Code, "repeat call should be idempotent")

	// Only one user should exist for this org.
	count, err := db.CountUsersByOrg(context.Background(), body["id"].(string))
	require.NoError(t, err)
	assert.Equal(t, 1, count, "idempotent retry must not create a duplicate admin")
}

func TestProvisionOrg_OrgExistsDifferentName(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	body := validProvisionBody()
	w1 := provisionReq(t, srv, key, body)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Same ID, different name → conflict.
	body["name"] = "Different Name"
	body["admin_email"] = uuid.Must(uuid.NewV7()).String() + "@other.com"
	w2 := provisionReq(t, srv, key, body)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// --- Validation ---

func TestProvisionOrg_MissingFields(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)

	cases := map[string]string{
		"id":                  "id",
		"name":                "name",
		"admin_email":         "email",
		"admin_name":          "admin_name",
		"admin_temp_password": "password",
	}
	for field, errKeyword := range cases {
		t.Run("missing_"+field, func(t *testing.T) {
			body := validProvisionBody()
			delete(body, field)
			w := provisionReq(t, srv, key, body)
			require.Equal(t, http.StatusBadRequest, w.Code, "field=%s body=%s", field, w.Body.String())
			assert.Contains(t, strings.ToLower(w.Body.String()), errKeyword)
		})
	}
}

func TestProvisionOrg_InvalidEmail(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	body := validProvisionBody()
	body["admin_email"] = "notanemail"
	w := provisionReq(t, srv, key, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "email")
}

func TestProvisionOrg_WeakPassword(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	body := validProvisionBody()
	body["admin_temp_password"] = "short"
	w := provisionReq(t, srv, key, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "password")
}

func TestProvisionOrg_DuplicateEmailAcrossOrgs(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)

	// Provision org A with admin alice@example.com
	body1 := validProvisionBody()
	body1["admin_email"] = "alice@example.com"
	w1 := provisionReq(t, srv, key, body1)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Provision a DIFFERENT org with the SAME admin email
	body2 := validProvisionBody()
	body2["admin_email"] = "alice@example.com" // collision
	w2 := provisionReq(t, srv, key, body2)
	assert.Equal(t, http.StatusConflict, w2.Code, "email is unique across the report server")
}
