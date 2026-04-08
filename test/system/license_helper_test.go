//go:build system

package system_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
)

// mintLicenseHelper constructs a valid enterprise license token
// signed with the given ephemeral private key. Uses the real
// internal/license.Encode path so the token survives the same
// Parse/VerifyJWT round trip the production CLI would run.
//
// The token intentionally has NO machine binding so the report
// server binary running on the test host accepts it regardless
// of hostname/GOOS/GOARCH.
func mintLicenseHelper(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	lic := &license.License{
		ID:        "system-test-license",
		Tier:      license.TierEnterprise,
		Org:       "SystemTestOrg",
		OrgID:     "00000000-0000-0000-0000-000000000999",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	tok, err := license.Encode(lic, priv)
	require.NoError(t, err)
	return tok
}
