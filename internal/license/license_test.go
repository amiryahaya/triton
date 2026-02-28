package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func testToken(t *testing.T, tier Tier, priv ed25519.PrivateKey) string {
	t.Helper()
	lic := &License{
		ID:        "test-license-id",
		Tier:      tier,
		Org:       "Test Org",
		Seats:     5,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := Encode(lic, priv)
	require.NoError(t, err)
	return token
}

func TestParse_ValidToken(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)

	lic, err := Parse(token, pub)
	require.NoError(t, err)
	assert.Equal(t, "test-license-id", lic.ID)
	assert.Equal(t, TierPro, lic.Tier)
	assert.Equal(t, "Test Org", lic.Org)
	assert.Equal(t, 5, lic.Seats)
	assert.False(t, lic.IsExpired())
}

func TestParse_InvalidSignature(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)

	// Tamper with the claims portion
	parts := strings.SplitN(token, ".", 2)
	require.Len(t, parts, 2)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"lid":"tampered","tier":"enterprise"}`))
	badToken := tampered + "." + parts[1]

	_, err := Parse(badToken, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestParse_ExpiredLicense(t *testing.T) {
	pub, priv := testKeypair(t)
	lic := &License{
		ID:        "expired-lic",
		Tier:      TierPro,
		Org:       "Expired Org",
		Seats:     1,
		IssuedAt:  time.Now().Add(-48 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(), // Expired yesterday
	}
	token, err := Encode(lic, priv)
	require.NoError(t, err)

	_, err = Parse(token, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestParse_MalformedToken(t *testing.T) {
	pub, _ := testKeypair(t)

	// No dot separator
	_, err := Parse("nodothere", pub)
	assert.Error(t, err)

	// Bad base64 in claims
	_, err = Parse("!!!bad.base64", pub)
	assert.Error(t, err)

	// Bad base64 in signature
	_, err = Parse(base64.RawURLEncoding.EncodeToString([]byte("{}"))+".!!!bad", pub)
	assert.Error(t, err)
}

func TestParse_EmptyToken(t *testing.T) {
	pub, _ := testKeypair(t)
	_, err := Parse("", pub)
	assert.Error(t, err)
}

func TestParse_WrongKey(t *testing.T) {
	_, priv := testKeypair(t)
	otherPub, _ := testKeypair(t)

	token := testToken(t, TierPro, priv)

	_, err := Parse(token, otherPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestParse_MissingRequiredFields(t *testing.T) {
	pub, priv := testKeypair(t)

	// Missing lid
	lic := &License{
		Tier:      TierPro,
		Org:       "No ID",
		Seats:     1,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := Encode(lic, priv)
	require.NoError(t, err)
	_, err = Parse(token, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lid")

	// Missing tier
	lic2 := &License{
		ID:        "has-id",
		Org:       "No Tier",
		Seats:     1,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token2, err := Encode(lic2, priv)
	require.NoError(t, err)
	_, err = Parse(token2, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tier")
}

func TestEncode_RoundTrip(t *testing.T) {
	pub, priv := testKeypair(t)
	original := &License{
		ID:        "round-trip-id",
		Tier:      TierEnterprise,
		Org:       "Round Trip Corp",
		Seats:     50,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}

	token, err := Encode(original, priv)
	require.NoError(t, err)

	parsed, err := Parse(token, pub)
	require.NoError(t, err)

	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.Tier, parsed.Tier)
	assert.Equal(t, original.Org, parsed.Org)
	assert.Equal(t, original.Seats, parsed.Seats)
	assert.Equal(t, original.IssuedAt, parsed.IssuedAt)
	assert.Equal(t, original.ExpiresAt, parsed.ExpiresAt)
}

func TestIsExpired(t *testing.T) {
	// Expired
	expired := &License{ExpiresAt: time.Now().Add(-1 * time.Hour).Unix()}
	assert.True(t, expired.IsExpired())

	// Not expired
	valid := &License{ExpiresAt: time.Now().Add(1 * time.Hour).Unix()}
	assert.False(t, valid.IsExpired())

	// Within 5-minute grace period (expired 3 minutes ago)
	grace := &License{ExpiresAt: time.Now().Add(-3 * time.Minute).Unix()}
	assert.False(t, grace.IsExpired(), "should be within grace period")

	// Past grace period (expired 6 minutes ago)
	pastGrace := &License{ExpiresAt: time.Now().Add(-6 * time.Minute).Unix()}
	assert.True(t, pastGrace.IsExpired(), "should be past grace period")
}

func TestParse_TamperedTier(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)

	// Decode claims, change tier, re-encode claims, keep original signature
	parts := strings.SplitN(token, ".", 2)
	require.Len(t, parts, 2)

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	claims["tier"] = "enterprise"

	newClaims, err := json.Marshal(claims)
	require.NoError(t, err)

	tamperedToken := base64.RawURLEncoding.EncodeToString(newClaims) + "." + parts[1]

	_, err = Parse(tamperedToken, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}
