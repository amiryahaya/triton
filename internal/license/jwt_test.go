package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{
		Sub:  "user-123",
		Org:  "org-456",
		Role: "org_admin",
		Name: "Alice",
	}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)

	got, err := VerifyJWT(token, pub)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.Sub)
	assert.Equal(t, "org-456", got.Org)
	assert.Equal(t, "org_admin", got.Role)
	assert.Equal(t, "Alice", got.Name)
	assert.NotZero(t, got.Iat)
	assert.NotZero(t, got.Exp)
}

func TestJWTExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Org: "o1", Role: "org_user", Name: "Bob"}
	token, err := SignJWT(claims, priv, -1*time.Hour)
	require.NoError(t, err)
	_, err = VerifyJWT(token, pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestJWTWrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Org: "o1", Role: "org_user", Name: "X"}
	token, _ := SignJWT(claims, priv1, 1*time.Hour)
	_, err := VerifyJWT(token, pub2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestJWTPlatformAdminEmptyOrg(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "admin-1", Org: "", Role: "platform_admin", Name: "Root"}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)
	got, err := VerifyJWT(token, pub)
	require.NoError(t, err)
	assert.Empty(t, got.Org)
	assert.Equal(t, "platform_admin", got.Role)
}

func TestJWTInvalidFormat(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := VerifyJWT("not-a-jwt", pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token format")
}
