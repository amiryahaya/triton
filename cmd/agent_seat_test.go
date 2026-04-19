package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/internal/license"
)

func TestActivateWithLicenseServer_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/license/activate", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "server-issued-token",
			"activationID": "act-123",
			"tier":         "pro",
			"seats":        5,
			"seatsUsed":    2,
			"expiresAt":    "2027-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	resolved := &resolvedAgentConfig{
		licenseServer: srv.URL,
		licenseID:     "lic-uuid",
		licenseToken:  "old-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.True(t, seat.activated)
	assert.Equal(t, "server-issued-token", seat.token)
	assert.Equal(t, "server-issued-token", resolved.licenseToken,
		"resolved.licenseToken should be overwritten with server-issued token")
}

func TestActivateWithLicenseServer_SeatsFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "all seats are occupied"})
	}))
	defer srv.Close()

	resolved := &resolvedAgentConfig{
		licenseServer: srv.URL,
		licenseID:     "lic-uuid",
		licenseToken:  "existing-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.False(t, seat.activated, "should not be activated when seats are full")
	assert.Equal(t, "existing-token", resolved.licenseToken,
		"existing token should be preserved on failure")
}

func TestActivateWithLicenseServer_NetworkError(t *testing.T) {
	resolved := &resolvedAgentConfig{
		licenseServer: "http://localhost:1", // unreachable
		licenseID:     "lic-uuid",
		licenseToken:  "existing-token",
	}
	seat := activateWithLicenseServer(resolved)

	assert.False(t, seat.activated)
	assert.Equal(t, "existing-token", resolved.licenseToken)
}

func TestActivateWithLicenseServer_NotConfigured(t *testing.T) {
	resolved := &resolvedAgentConfig{
		licenseServer: "",
		licenseID:     "",
	}
	seat := activateWithLicenseServer(resolved)
	assert.False(t, seat.activated)
	assert.Nil(t, seat.client)
}

func TestHeartbeat_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "tier": "pro",
		})
	}))
	defer srv.Close()

	guard := license.NewGuard("")
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result, override, err := heartbeat(seat, guard)
	assert.NoError(t, err)
	assert.Nil(t, override, "no schedule override from server")
	assert.True(t, seat.activated, "should remain activated")
	// Tier changes take effect on next restart — guard is unchanged
	assert.Equal(t, guard, result, "guard should be unchanged (tier changes need restart)")
}

func TestHeartbeat_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": false, "reason": "license revoked",
		})
	}))
	defer srv.Close()

	guard := license.NewGuard("")
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result, override, err := heartbeat(seat, guard)
	assert.NoError(t, err)
	assert.Nil(t, override)
	assert.False(t, seat.activated, "should stop heartbeating after invalid response")
	assert.Equal(t, license.TierFree, result.Tier())
}

func TestHeartbeat_NetworkError(t *testing.T) {
	guard := license.NewGuard("")
	seat := &seatState{
		activated: true,
		client:    license.NewServerClient("http://localhost:1"),
		licenseID: "lic-uuid",
		token:     "tok",
	}

	result, override, err := heartbeat(seat, guard)
	assert.NoError(t, err)
	assert.Nil(t, override)
	assert.True(t, seat.activated, "should remain activated on network error")
	assert.Equal(t, guard, result, "should return original guard on network error")
}

func TestHeartbeat_NotActivated(t *testing.T) {
	guard := license.NewGuard("")
	seat := &seatState{activated: false}
	result, override, err := heartbeat(seat, guard)
	assert.NoError(t, err)
	assert.Nil(t, override)
	assert.Equal(t, guard, result)
}

func TestDeactivateOnShutdown_Activated(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "/api/v1/license/deactivate", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deactivated"})
	}))
	defer srv.Close()

	seat := &seatState{
		activated: true,
		client:    license.NewServerClient(srv.URL),
		licenseID: "lic-uuid",
	}
	deactivateOnShutdown(seat)
	assert.True(t, called, "should call deactivate endpoint")
}

func TestDeactivateOnShutdown_NotActivated(t *testing.T) {
	seat := &seatState{activated: false}
	deactivateOnShutdown(seat) // should not panic or make any calls
}
