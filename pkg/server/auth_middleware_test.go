//go:build integration

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopHandler is a 200-returning handler used to verify middleware
// allows a request through.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
})

// mountWithMiddleware builds a mini test server with JWTAuth + a custom
// middleware chained on a single GET route. Used to test middleware
// behavior in isolation.
func mountWithMiddleware(t *testing.T, srv *Server, middleware func(http.Handler) http.Handler) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/test", func(r chi.Router) {
		r.Use(JWTAuth(srv.config.JWTPublicKey, srv.store, srv.sessionCache))
		r.Use(middleware)
		r.Get("/", noopHandler)
	})
	return r
}

// --- RequireAnyOrgRole ---

func TestRequireAnyOrgRole_AcceptsOrgAdmin(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	r := mountWithMiddleware(t, srv, RequireAnyOrgRole)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAnyOrgRole_AcceptsOrgUser(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_user")

	r := mountWithMiddleware(t, srv, RequireAnyOrgRole)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAnyOrgRole_RejectsMissingAuth(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	r := mountWithMiddleware(t, srv, RequireAnyOrgRole)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- RequireOrgAdmin ---

func TestRequireOrgAdmin_AcceptsOrgAdmin(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	r := mountWithMiddleware(t, srv, RequireOrgAdmin)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireOrgAdmin_RejectsOrgUser(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_user")

	r := mountWithMiddleware(t, srv, RequireOrgAdmin)
	req := httptest.NewRequest(http.MethodGet, "/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}
