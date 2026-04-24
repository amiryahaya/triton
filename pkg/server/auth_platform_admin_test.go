package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/stretchr/testify/require"
)

func TestRequirePlatformAdmin_AcceptsPlatformAdmin(t *testing.T) {
	claims := &auth.UserClaims{Role: "platform_admin"}
	ctx := server.ContextWithClaimsForTesting(context.Background(), claims)
	called := false
	h := server.RequirePlatformAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	require.True(t, called)
	require.Equal(t, 200, rr.Code)
}

func TestRequirePlatformAdmin_RejectsOrgAdmin(t *testing.T) {
	claims := &auth.UserClaims{Role: "org_admin"}
	ctx := server.ContextWithClaimsForTesting(context.Background(), claims)
	h := server.RequirePlatformAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	require.Equal(t, 403, rr.Code)
}

func TestRequirePlatformAdmin_RejectsNoClaims(t *testing.T) {
	h := server.RequirePlatformAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	require.Equal(t, 401, rr.Code)
}
