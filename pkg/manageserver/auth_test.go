package manageserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey32 is a fixed 32-byte key for deterministic tests.
var testKey32 = []byte("test-jwt-key-for-unit-tests-32b!")

func TestSignParseRoundtrip(t *testing.T) {
	claims := JWTClaims{
		Sub:  "user-123",
		Role: "admin",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}
	token, err := signJWT(claims, testKey32)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	got, err := parseJWT(token, testKey32)
	require.NoError(t, err)
	assert.Equal(t, claims.Sub, got.Sub)
	assert.Equal(t, claims.Role, got.Role)
}

func TestParseJWT_RejectsExpired(t *testing.T) {
	claims := JWTClaims{
		Sub:  "user-123",
		Role: "admin",
		Iat:  time.Now().Add(-2 * time.Hour).Unix(),
		Exp:  time.Now().Add(-time.Hour).Unix(), // already expired
	}
	token, err := signJWT(claims, testKey32)
	require.NoError(t, err)

	_, err = parseJWT(token, testKey32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestParseJWT_RejectsTamperedSignature(t *testing.T) {
	claims := JWTClaims{
		Sub:  "user-123",
		Role: "admin",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}
	token, err := signJWT(claims, testKey32)
	require.NoError(t, err)

	// Tamper the last character of the signature.
	tampered := token[:len(token)-1] + "X"
	if tampered[len(tampered)-1] == token[len(token)-1] {
		tampered = token[:len(token)-1] + "Y"
	}

	_, err = parseJWT(tampered, testKey32)
	require.Error(t, err)
}

func TestParseJWT_RejectsMalformed(t *testing.T) {
	_, err := parseJWT("not.a.jwt.with.too.many.parts", testKey32)
	require.Error(t, err)

	_, err = parseJWT("onlytwoparts", testKey32)
	require.Error(t, err)

	_, err = parseJWT("", testKey32)
	require.Error(t, err)
}

func TestHashPassword_VerifyPasswordRoundtrip(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	hash, err := HashPassword(pw)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	err = VerifyPassword(hash, pw)
	require.NoError(t, err)
}

func TestVerifyPassword_WrongPasswordFails(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	hash, err := HashPassword(pw)
	require.NoError(t, err)

	err = VerifyPassword(hash, "wrong-password")
	require.Error(t, err)
}

func TestJWT_McpRoundTrip(t *testing.T) {
	in := JWTClaims{
		Sub:  "u1",
		Role: "admin",
		Iat:  100,
		Exp:  9999999999,
		Mcp:  true,
	}
	token, err := signJWT(in, testKey32)
	require.NoError(t, err)
	out, err := parseJWT(token, testKey32)
	require.NoError(t, err)
	assert.True(t, out.Mcp, "Mcp lost in round trip")
}

func TestHashToken_DeterministicAndHex(t *testing.T) {
	const token = "test.jwt.token"
	h1 := hashToken(token)
	h2 := hashToken(token)
	assert.Equal(t, h1, h2, "hashToken must be deterministic")
	assert.Len(t, h1, 64, "SHA-256 hex is 64 chars")
	// Must be lowercase hex
	for _, c := range h1 {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"expected hex char, got %c", c)
	}
}
