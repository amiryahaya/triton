package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amiryahaya/triton/internal/auth"
)

func TestRequireRole_AllowsExactMatch(t *testing.T) {
	h := RequireRole(RoleEngineer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(contextWithClaims(req.Context(), &auth.UserClaims{Role: RoleEngineer}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole_AllowsHigherRole(t *testing.T) {
	h := RequireRole(RoleEngineer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(contextWithClaims(req.Context(), &auth.UserClaims{Role: RoleOwner}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (owner satisfies engineer), got %d", rec.Code)
	}
}

func TestRequireRole_RejectsLowerRole(t *testing.T) {
	h := RequireRole(RoleEngineer)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(contextWithClaims(req.Context(), &auth.UserClaims{Role: RoleOfficer}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsMissingClaims(t *testing.T) {
	h := RequireRole(RoleOfficer)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsEmptyStringRole(t *testing.T) {
	// Empty-role JWT (malformed token shape, or a legacy row with
	// NULL/'' role) must be rejected — roleRank[""] is 0, which is
	// below every positive minRank.
	h := RequireRole(RoleOfficer)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(contextWithClaims(req.Context(), &auth.UserClaims{Role: ""}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireRole_PanicsOnUnknownMinRole(t *testing.T) {
	// Construction-time guard: a typo like RequireRole("org_offcer")
	// previously produced a middleware that silently admitted every
	// caller (minRank was 0, and every role rank is >= 0). Panic at
	// construction so the misconfiguration surfaces during boot.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unknown minRole")
		}
	}()
	_ = RequireRole("bogus-role")
}

func TestRequireRole_RejectsUnknownRole(t *testing.T) {
	// Defense in depth: a JWT with a role string not in roleRank
	// (e.g., leftover "platform_admin" from a license-server token)
	// must be rejected rather than silently treated as rank 0 pass.
	h := RequireRole(RoleOfficer)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(contextWithClaims(req.Context(), &auth.UserClaims{Role: "platform_admin"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown role, got %d", rec.Code)
	}
}
