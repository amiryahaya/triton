package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeEd25519PrivateKey_SeedForm verifies a 32-byte seed
// produces a valid Ed25519 private key (the NewKeyFromSeed path).
func TestDecodeEd25519PrivateKey_SeedForm(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	require.NoError(t, err)

	priv, err := decodeEd25519PrivateKey(hex.EncodeToString(seed))
	require.NoError(t, err)
	assert.Len(t, priv, ed25519.PrivateKeySize,
		"NewKeyFromSeed expands the 32-byte seed to the full 64-byte key")

	// Sanity: the key signs a message and verifies with its public part.
	msg := []byte("triton sprint3")
	sig := ed25519.Sign(priv, msg)
	assert.True(t, ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig))
}

// TestDecodeEd25519PrivateKey_FullKeyForm verifies the 64-byte key
// form (output of ed25519.GenerateKey) round-trips correctly.
func TestDecodeEd25519PrivateKey_FullKeyForm(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	decoded, err := decodeEd25519PrivateKey(hex.EncodeToString(priv))
	require.NoError(t, err)
	assert.Equal(t, priv, decoded)
}

// TestDecodeEd25519PrivateKey_InvalidHex rejects non-hex input.
func TestDecodeEd25519PrivateKey_InvalidHex(t *testing.T) {
	_, err := decodeEd25519PrivateKey("not-hex")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex")
}

// TestDecodeEd25519PrivateKey_WrongLength rejects hex of the wrong size.
func TestDecodeEd25519PrivateKey_WrongLength(t *testing.T) {
	_, err := decodeEd25519PrivateKey("deadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

// TestParseRateLimitEnv_AllUnsetReturnsNil verifies that the env-less
// case returns nil so the server falls back to defaults.
func TestParseRateLimitEnv_AllUnsetReturnsNil(t *testing.T) {
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "")

	assert.Nil(t, parseRateLimitEnv())
}

// TestParseRateLimitEnv_PartialOverride verifies that setting one
// env var returns a non-nil config with ONLY that field overridden;
// the other two use the default values.
func TestParseRateLimitEnv_PartialOverride(t *testing.T) {
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "10")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "")

	cfg := parseRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 10, cfg.MaxAttempts)
	// The unset fields must inherit from the default.
	assert.Equal(t, 15*time.Minute, cfg.Window)
	assert.Equal(t, 15*time.Minute, cfg.LockoutDuration)
}

// TestParseRateLimitEnv_FullOverride verifies all three fields can
// be tuned together.
func TestParseRateLimitEnv_FullOverride(t *testing.T) {
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "3")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "1m")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "30s")

	cfg := parseRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 1*time.Minute, cfg.Window)
	assert.Equal(t, 30*time.Second, cfg.LockoutDuration)
}

// TestParseRateLimitEnv_InvalidAttemptsIgnored verifies that a
// non-integer / non-positive MAX_ATTEMPTS is silently ignored and
// the default applies — we never want a malformed env var to
// weaken the rate limit.
func TestParseRateLimitEnv_InvalidAttemptsIgnored(t *testing.T) {
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "-5")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "")

	cfg := parseRateLimitEnv()
	require.NotNil(t, cfg, "any non-empty value should still return a config")
	assert.Equal(t, 5, cfg.MaxAttempts, "invalid value must fall back to the default 5")
}

// TestParseRateLimitEnv_InvalidDurationIgnored likewise falls back
// on unparseable Window / Lockout values.
func TestParseRateLimitEnv_InvalidDurationIgnored(t *testing.T) {
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "not-a-duration")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "")

	cfg := parseRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 15*time.Minute, cfg.Window, "invalid window must fall back to the default")
}
