package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amiryahaya/triton/internal/license"
)

// okHandler is a trivial next handler for LicenceGate tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestIsDiffTrendPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/v1/diff", true},
		{"/api/v1/diff/", true},
		{"/api/v1/diff/compare", true},
		{"/api/v1/trend", true},
		{"/api/v1/trend/", true},
		{"/api/v1/trend/hosts", true},
		{"/api/v1/scans", false},
		{"/api/v1/inventory", false},
		{"/api/v1/diff-export", false}, // prefix must be exact
	}
	for _, tc := range cases {
		got := isDiffTrendPath(tc.path)
		if got != tc.want {
			t.Errorf("isDiffTrendPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestLicenceGate_NilGuard_PassesAll(t *testing.T) {
	handler := LicenceGate(nil)(okHandler)

	for _, path := range []string{"/api/v1/diff", "/api/v1/trend", "/api/v1/scans"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("nil guard: path %q got %d, want 200", path, w.Code)
		}
	}
}

func TestLicenceGate_FreeTier_BlocksDiffTrend(t *testing.T) {
	guard := license.NewGuardFromToken("", nil) // free tier, no diff_trend
	handler := LicenceGate(guard)(okHandler)

	for _, path := range []string{"/api/v1/diff", "/api/v1/trend", "/api/v1/trend/results"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("free tier: path %q got %d, want 403", path, w.Code)
		}
	}
}

func TestLicenceGate_FreeTier_AllowsOtherPaths(t *testing.T) {
	guard := license.NewGuardFromToken("", nil) // free tier
	handler := LicenceGate(guard)(okHandler)

	for _, path := range []string{"/api/v1/scans", "/api/v1/inventory", "/api/v1/health"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("free tier: non-gated path %q got %d, want 200", path, w.Code)
		}
	}
}
