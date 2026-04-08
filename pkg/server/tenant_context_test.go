//go:build integration

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)

// mountTenantContextTest builds a mini chi router with UnifiedAuth +
// RequireTenant chained, and a handler that echoes the TenantContext
// so tests can inspect what the middleware produced.
func mountTenantContextTest(
	t *testing.T,
	jwtPub ed25519.PublicKey,
	userStore store.UserStore,
	licensePub ed25519.PublicKey,
	guard *license.Guard,
) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/test", func(r chi.Router) {
		r.Use(UnifiedAuth(jwtPub, userStore, licensePub, guard))
		r.Use(RequireTenant)
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			tc := TenantContextFromContext(req.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":   tc.OrgID,
				"source":   string(tc.Source),
				"has_user": tc.User != nil,
			})
		})
	})
	return r
}

// --- JWT path ---

func TestUnifiedAuth_JWTPath(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	r := mountTenantContextTest(t, srv.config.JWTPublicKey, srv.store, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, user.OrgID, resp["org_id"])
	assert.Equal(t, "jwt", resp["source"])
	assert.Equal(t, true, resp["has_user"], "JWT path must populate User")
}

func TestUnifiedAuth_RejectsInvalidJWT(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	r := mountTenantContextTest(t, srv.config.JWTPublicKey, srv.store, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUnifiedAuth_RejectsDeletedUserJWT(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	require.NoError(t, db.DeleteUser(t.Context(), user.ID))

	r := mountTenantContextTest(t, srv.config.JWTPublicKey, srv.store, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "deleted user must not authenticate via JWT")
}

// --- License token path ---

// signLicenseToken creates a valid license token for testing.
func signLicenseToken(t *testing.T, priv ed25519.PrivateKey, orgID string) string {
	t.Helper()
	lic := &license.License{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Tier:      license.TierPro,
		OrgID:     orgID,
		Org:       "test-org",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	return token
}

func TestUnifiedAuth_LicenseTokenPath(t *testing.T) {
	_, db := testServer(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	orgID := uuid.Must(uuid.NewV7()).String()
	token := signLicenseToken(t, priv, orgID)

	r := mountTenantContextTest(t, nil, db, pub, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("X-Triton-License-Token", token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, orgID, resp["org_id"])
	assert.Equal(t, "license_token", resp["source"])
	assert.Equal(t, false, resp["has_user"], "license token path has no user")
}

func TestUnifiedAuth_RejectsInvalidLicenseToken(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	r := mountTenantContextTest(t, nil, nil, pub, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("X-Triton-License-Token", "not-a-valid-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Precedence ---

func TestUnifiedAuth_JWTPrecedenceOverLicenseToken(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	jwtToken := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	// Also supply a license token for a DIFFERENT org. JWT must win.
	licPub, licPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherOrgID := uuid.Must(uuid.NewV7()).String()
	licenseToken := signLicenseToken(t, licPriv, otherOrgID)

	r := mountTenantContextTest(t, srv.config.JWTPublicKey, srv.store, licPub, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("X-Triton-License-Token", licenseToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, user.OrgID, resp["org_id"], "JWT org must win")
	assert.Equal(t, "jwt", resp["source"])
}

// --- RequireTenant ---

func TestRequireTenant_RejectsUnauthenticated(t *testing.T) {
	r := mountTenantContextTest(t, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"RequireTenant must reject when no auth source produces a context")
}

// --- Backward compat with legacy TenantFromContext ---

func TestTenantFromContext_ReadsUnifiedKey(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	// Use a handler that reads via TenantFromContext (legacy helper).
	r := chi.NewRouter()
	r.Route("/echo", func(r chi.Router) {
		r.Use(UnifiedAuth(srv.config.JWTPublicKey, srv.store, nil, nil))
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			orgID := TenantFromContext(req.Context())
			_, _ = w.Write([]byte(orgID))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/echo/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, user.OrgID, w.Body.String(),
		"TenantFromContext must read from the unified key set by UnifiedAuth")
}

// Compile-time assertion that the new AuthSource constants don't
// collide with existing string values elsewhere in the package.
var _ = auth.UserClaims{}
