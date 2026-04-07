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

// TestSignJWTDoesNotMutateCallerClaims verifies that SignJWT is a pure
// operation from the caller's perspective — the passed-in struct's Iat
// and Exp fields must not be modified. Callers should be able to log or
// compare their claims struct after signing without surprise.
func TestSignJWTDoesNotMutateCallerClaims(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Role: "platform_admin", Name: "Root"}
	require.Equal(t, int64(0), claims.Iat)
	require.Equal(t, int64(0), claims.Exp)

	_, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)

	// After signing, the caller's struct must be unchanged.
	assert.Equal(t, int64(0), claims.Iat, "Iat must not be mutated on caller's struct")
	assert.Equal(t, int64(0), claims.Exp, "Exp must not be mutated on caller's struct")
}

// TestJWTStandardFormat verifies the emitted token has three dot-separated
// parts (header.payload.signature) matching the standard JWT format, so it
// can be parsed by off-the-shelf JWT libraries and debugging tools.
func TestJWTStandardFormat(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Role: "platform_admin", Name: "Root"}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "standard JWT must have 3 dot-separated parts")

	// Header must be base64url-decodable JSON with alg=EdDSA, typ=JWT.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "EdDSA", header["alg"])
	assert.Equal(t, "JWT", header["typ"])
}
