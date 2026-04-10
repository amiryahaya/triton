package licenseserver

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return priv
}

func TestInstallToken_RoundTrip(t *testing.T) {
	key := testSigningKey(t)
	secret := key.Seed()
	licenseID := "test-license-id"

	token, err := GenerateInstallToken(secret, licenseID, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := ValidateInstallToken(secret, token)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, licenseID, claims.LicenseID)
	assert.Greater(t, claims.ExpiresAt, time.Now().Unix())
}

func TestInstallToken_Expired(t *testing.T) {
	key := testSigningKey(t)
	secret := key.Seed()

	token, err := GenerateInstallToken(secret, "some-license", -time.Hour)
	require.NoError(t, err)

	_, err = ValidateInstallToken(secret, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestInstallToken_Tampered(t *testing.T) {
	key := testSigningKey(t)
	secret := key.Seed()

	token, err := GenerateInstallToken(secret, "some-license", time.Hour)
	require.NoError(t, err)

	// Flip the last character of the token to simulate tampering.
	runes := []rune(token)
	if runes[len(runes)-1] == 'a' {
		runes[len(runes)-1] = 'b'
	} else {
		runes[len(runes)-1] = 'a'
	}
	tampered := string(runes)

	_, err = ValidateInstallToken(secret, tampered)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestInstallToken_WrongKey(t *testing.T) {
	key1 := testSigningKey(t)
	key2 := testSigningKey(t)

	token, err := GenerateInstallToken(key1.Seed(), "some-license", time.Hour)
	require.NoError(t, err)

	_, err = ValidateInstallToken(key2.Seed(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestInstallToken_EmptyLicenseID(t *testing.T) {
	key := testSigningKey(t)
	secret := key.Seed()

	_, err := GenerateInstallToken(secret, "", time.Hour)
	require.Error(t, err)
}
