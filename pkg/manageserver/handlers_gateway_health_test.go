//go:build integration

package manageserver_test

import (
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
