package auth

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

func TestSignJWTDoesNotMutateCallerClaims(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Role: "platform_admin", Name: "Root"}
	require.Equal(t, int64(0), claims.Iat)
	require.Equal(t, int64(0), claims.Exp)

	_, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)

	assert.Equal(t, int64(0), claims.Iat, "Iat must not be mutated on caller's struct")
	assert.Equal(t, int64(0), claims.Exp, "Exp must not be mutated on caller's struct")
}

func TestJWTRejectsUnknownTyp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWS"})
	b64Header := base64.RawURLEncoding.EncodeToString(header)
	claims := UserClaims{Sub: "u1", Role: "platform_admin", Exp: time.Now().Add(1 * time.Hour).Unix()}
	payload, _ := json.Marshal(&claims)
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := b64Header + "." + b64Payload
	sig := ed25519.Sign(priv, []byte(signingInput))
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)
	token := signingInput + "." + b64Sig

	_, err := VerifyJWT(token, pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typ")
}

func TestJWTStandardFormat(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &UserClaims{Sub: "u1", Role: "platform_admin", Name: "Root"}
	token, err := SignJWT(claims, priv, 1*time.Hour)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "standard JWT must have 3 dot-separated parts")

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "EdDSA", header["alg"])
	assert.Equal(t, "JWT", header["typ"])
}

// TestJWTMustChangePasswordClaim verifies the new MustChangePassword field
// (Phase 1.5c) round-trips correctly through the JWT.
func TestJWTMustChangePasswordClaim(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Set true
	mcpToken, err := SignJWT(&UserClaims{
		Sub: "u1", Org: "o1", Role: "org_admin", Name: "Alice",
		MustChangePassword: true,
	}, priv, 1*time.Hour)
	require.NoError(t, err)
	mcpClaims, err := VerifyJWT(mcpToken, pub)
	require.NoError(t, err)
	assert.True(t, mcpClaims.MustChangePassword)

	// Default false (omitempty)
	defaultToken, err := SignJWT(&UserClaims{
		Sub: "u2", Org: "o1", Role: "org_admin", Name: "Bob",
	}, priv, 1*time.Hour)
	require.NoError(t, err)
	defaultClaims, err := VerifyJWT(defaultToken, pub)
	require.NoError(t, err)
	assert.False(t, defaultClaims.MustChangePassword)
}
