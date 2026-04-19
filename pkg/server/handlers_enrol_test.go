//go:build integration

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrolReq POSTs to /api/v1/admin/enrol/manage with the given service key.
// Empty serviceKey omits the header (used to test the 401 path).
func enrolReq(t *testing.T, srv *Server, serviceKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/manage", nil)
	if serviceKey != "" {
		req.Header.Set("X-Triton-Service-Key", serviceKey)
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

// TestEnrolManage_Stub501 — with a valid service key the stub returns 501
// with the B2 landing-pad message. PR B2 replaces this handler with the
// real mTLS enrolment flow.
func TestEnrolManage_Stub501(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	w := enrolReq(t, srv, key)

	require.Equal(t, http.StatusNotImplemented, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, strings.ToLower(w.Body.String()), "b2")
	assert.Contains(t, strings.ToLower(w.Body.String()), "enrol")
}

// TestEnrolManage_MissingServiceKey — without a service key the route
// returns 401 via the ServiceKeyAuth middleware (same as /api/v1/admin/orgs).
func TestEnrolManage_MissingServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := enrolReq(t, srv, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestEnrolManage_WrongServiceKey — a mismatched service key returns 403.
func TestEnrolManage_WrongServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := enrolReq(t, srv, "wrong-key")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestEnrolManage_RouteDisabledWithoutServiceKey — when ServiceKey is not
// configured on the server, the admin subgroup is never mounted, so the
// route returns 404 like the other admin endpoints.
func TestEnrolManage_RouteDisabledWithoutServiceKey(t *testing.T) {
	srv, _ := testServer(t)
	w := enrolReq(t, srv, "")
	assert.Equal(t, http.StatusNotFound, w.Code)
}
