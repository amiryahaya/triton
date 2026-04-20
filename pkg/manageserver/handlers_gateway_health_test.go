//go:build integration

package manageserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
)

// TestGatewayHealth_PendingSetup exercises the pre-Batch-C path where
// Server.Run() hasn't fired (so runGateway + bootstrapCA never ran) and
// the atomic gatewayState is still at its zero value (pending_setup).
// openOperationalServer seeds admin + license directly via the store,
// bypassing handlers_setup.go's Bootstrap call, so the CA row is absent.
func TestGatewayHealth_PendingSetup(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	user := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/gateway-health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body manageserver.GatewayHealthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.False(t, body.CABootstrapped)
	assert.Equal(t, "pending_setup", body.ListenerState)
	assert.Nil(t, body.CertExpiresAt)
	assert.Equal(t, 0, body.CertDaysRemaining)
}

// TestGatewayHealth_Up exercises the post-Batch-C happy path: the CA
// is bootstrapped and a server leaf has been minted + cached, so
// /admin/gateway-health reports listener_state=up with a valid
// cert_expires_at + cert_days_remaining in the server leaf's 90-day
// lifetime window.
//
// Uses BootstrapGatewayForTest rather than Server.Run to avoid a port
// conflict between the real :8443 listener and the httptest.Server
// that wraps srv.Router(). The test-only helper flips gatewayState +
// publishes the leaf synchronously without spawning the real listener.
func TestGatewayHealth_Up(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	// Bootstrap CA + mint leaf + flip gatewayState to up — mirrors
	// what bootstrapGatewayListener does, minus the real TLS bind.
	require.NoError(t, srv.BootstrapGatewayForTest(context.Background()))

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	user := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/admin/gateway-health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body manageserver.GatewayHealthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.CABootstrapped)
	assert.Equal(t, "up", body.ListenerState)
	require.NotNil(t, body.CertExpiresAt)
	// Server leaf lifetime is 90 days; expiry should land in the
	// [80, 91] day window accounting for integer truncation + test
	// clock skew.
	assert.Greater(t, body.CertDaysRemaining, 80)
	assert.LessOrEqual(t, body.CertDaysRemaining, 91)
}
