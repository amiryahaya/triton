//go:build integration

package manageserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
)

// TestLicence_Active activates a real signed token (Features.Manage=true),
// injects the resulting Guard on the running Server, and asserts that
// GET /api/v1/admin/licence returns 200 with tier + features +
// instance_id populated.
//
// We synthesise the Guard via NewGuardFromToken rather than going
// through startLicence because openOperationalServer seeds a bogus
// token string — sufficient to clear setup mode but not parseable.
// SetLicenceGuardForTest swaps the guard under the same mutex that
// handleLicenceSummary reads, matching the production wiring path.
func TestLicence_Active(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	// Sign a valid licence token with Manage feature enabled.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	lic := &license.License{
		ID:        "test-lic-admin-licence",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	guard := license.NewGuardFromToken(signed, pub)
	require.NotNil(t, guard)
	require.True(t, guard.HasFeature("manage"), "guard must report manage feature")

	srv.SetLicenceGuardForTest(guard)

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Seed admin + login using the existing helper pattern.
	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest("GET", ts.URL+"/api/v1/admin/licence", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body manageserver.LicenceSummary
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.Tier, "tier must be populated")
	assert.NotEmpty(t, body.InstanceID, "instance_id must be populated from setup state")
	assert.True(t, body.Features["manage"], "features.manage must be true for a pro licence")
}

// TestLicence_Inactive asserts the handler returns 503 when no licence
// guard is wired — the default state produced by openOperationalServer
// (bogus "tok" token, empty PublicKey). SetLicenceGuardForTest(nil) is
// a belt-and-braces no-op that documents the precondition.
func TestLicence_Inactive(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	srv.SetLicenceGuardForTest(nil)

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest("GET", ts.URL+"/api/v1/admin/licence", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
