//go:build integration

package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrolReq POSTs to /api/v1/admin/enrol/manage with the given service key.
// When body is nil, the request is sent without a body (used to exercise
// the auth-gate paths only).
func enrolReq(t *testing.T, srv *Server, serviceKey string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rdr := bytes.NewReader(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/manage", rdr)
	req.Header.Set("Content-Type", "application/json")
	if serviceKey != "" {
		req.Header.Set("X-Triton-Service-Key", serviceKey)
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

// TestEnrolManage_StubWhenNotConfigured — with a valid service key but no
// ManageEnrolHandlers wired, the route returns 501 with a descriptive
// message. Preserves the "not configured" escape hatch for Report-only
// deployments that don't run Manage.
func TestEnrolManage_StubWhenNotConfigured(t *testing.T) {
	srv, _, key := testServerWithServiceKey(t)
	w := enrolReq(t, srv, key, nil)

	require.Equal(t, http.StatusNotImplemented, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, strings.ToLower(w.Body.String()), "not configured")
}

// TestEnrolManage_MissingServiceKey — without a service key the route
// returns 401 via the ServiceKeyAuth middleware (same as /api/v1/admin/orgs).
func TestEnrolManage_MissingServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := enrolReq(t, srv, "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestEnrolManage_WrongServiceKey — a mismatched service key returns 403.
func TestEnrolManage_WrongServiceKey(t *testing.T) {
	srv, _, _ := testServerWithServiceKey(t)
	w := enrolReq(t, srv, "wrong-key", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestEnrolManage_RouteDisabledWithoutServiceKey — when ServiceKey is not
// configured on the server, the admin subgroup is never mounted, so the
// route returns 404 like the other admin endpoints.
func TestEnrolManage_RouteDisabledWithoutServiceKey(t *testing.T) {
	srv, _ := testServer(t)
	w := enrolReq(t, srv, "", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
