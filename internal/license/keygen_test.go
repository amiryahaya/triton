package license

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	require.NoError(t, err)
	assert.Len(t, pub, 32, "Ed25519 public key should be 32 bytes")
	assert.Len(t, priv, 64, "Ed25519 private key should be 64 bytes")
}

func TestIssueToken(t *testing.T) {
	_, priv, err := GenerateKeypair()
	require.NoError(t, err)

	token, err := IssueToken(priv, TierPro, "NACSA", 10, 365)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Contains(t, token, ".", "token should contain dot separator")
}

func TestIssueToken_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	require.NoError(t, err)

	token, err := IssueToken(priv, TierEnterprise, "Test Corp", 25, 30)
	require.NoError(t, err)

	lic, err := Parse(token, pub)
	require.NoError(t, err)

	assert.Equal(t, TierEnterprise, lic.Tier)
	assert.Equal(t, "Test Corp", lic.Org)
	assert.Equal(t, 25, lic.Seats)
	assert.NotEmpty(t, lic.ID)

	// Token should expire roughly 30 days from now
	expectedExp := time.Now().Add(30 * 24 * time.Hour)
	actualExp := time.Unix(lic.ExpiresAt, 0)
	assert.WithinDuration(t, expectedExp, actualExp, time.Minute)
}

func TestIssueToken_IncludesMachineID(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	require.NoError(t, err)

	token, err := IssueToken(priv, TierPro, "Bound Corp", 1, 30)
	require.NoError(t, err)

	lic, err := Parse(token, pub)
	require.NoError(t, err)
	assert.Equal(t, MachineFingerprint(), lic.MachineID, "IssueToken should include machine fingerprint")
}

func TestIssueTokenWithOptions_NoBind(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	require.NoError(t, err)

	token, err := IssueTokenWithOptions(priv, TierPro, "Unbound Corp", 1, 30, false)
	require.NoError(t, err)

	lic, err := Parse(token, pub)
	require.NoError(t, err)
	assert.Empty(t, lic.MachineID, "NoBind should produce empty MachineID")
}
