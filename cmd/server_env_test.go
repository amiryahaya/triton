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

// clearRateLimitEnv resets every legacy and canonical rate-limit
// env var so a test case starts from a clean slate regardless of
// the host shell's environment.
func clearRateLimitEnv(t *testing.T) {
	for _, k := range []string{
		"REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS",
		"REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW",
		"REPORT_SERVER_LOGIN_RATE_LIMIT_LOCKOUT",
		"REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS",
		"REPORT_SERVER_REQUEST_RATE_LIMIT_WINDOW",
		"REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS",
		"REPORT_SERVER_RATE_LIMIT_WINDOW",
		"REPORT_SERVER_RATE_LIMIT_LOCKOUT",
	} {
		t.Setenv(k, "")
	}
}

// TestParseLoginRateLimitEnv_AllUnsetReturnsNil verifies that the
// env-less case returns nil so the server falls back to defaults.
func TestParseLoginRateLimitEnv_AllUnsetReturnsNil(t *testing.T) {
	clearRateLimitEnv(t)
	assert.Nil(t, parseLoginRateLimitEnv())
}

// TestParseLoginRateLimitEnv_FullOverride verifies all three fields
// can be tuned together via the canonical names.
func TestParseLoginRateLimitEnv_FullOverride(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "3")
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW", "1m")
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_LOCKOUT", "30s")

	cfg := parseLoginRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 1*time.Minute, cfg.Window)
	assert.Equal(t, 30*time.Second, cfg.LockoutDuration)
}

// TestParseLoginRateLimitEnv_LegacyNamesStillWork verifies the
// backward-compat path from Sprint 3 Round 1 — the old
// REPORT_SERVER_RATE_LIMIT_* names still produce a config with a
// deprecation log (log not asserted on).
func TestParseLoginRateLimitEnv_LegacyNamesStillWork(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS", "3")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_WINDOW", "1m")
	t.Setenv("REPORT_SERVER_RATE_LIMIT_LOCKOUT", "30s")

	cfg := parseLoginRateLimitEnv()
	require.NotNil(t, cfg, "legacy env var names must still populate the config for backward compat")
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 1*time.Minute, cfg.Window)
	assert.Equal(t, 30*time.Second, cfg.LockoutDuration)
}

// TestParseLoginRateLimitEnv_PartialOverride verifies unset fields
// inherit the default values.
func TestParseLoginRateLimitEnv_PartialOverride(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "10")

	cfg := parseLoginRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 10, cfg.MaxAttempts)
	assert.Equal(t, 15*time.Minute, cfg.Window)
	assert.Equal(t, 15*time.Minute, cfg.LockoutDuration)
}

// TestParseLoginRateLimitEnv_InvalidValuesIgnored covers the
// negative-int, non-duration, and zero cases. Invalid values must
// NEVER weaken the rate limit — they fall back to the default.
func TestParseLoginRateLimitEnv_InvalidValuesIgnored(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "-5")
	t.Setenv("REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW", "not-a-duration")

	cfg := parseLoginRateLimitEnv()
	require.NotNil(t, cfg, "any non-empty value should still return a config")
	assert.Equal(t, 5, cfg.MaxAttempts, "invalid value must fall back to the default 5")
	assert.Equal(t, 15*time.Minute, cfg.Window, "invalid window must fall back to the default")
}

// TestParseRequestRateLimitEnv_UnsetReturnsNil verifies nil fallback
// for the request limiter env path.
func TestParseRequestRateLimitEnv_UnsetReturnsNil(t *testing.T) {
	clearRateLimitEnv(t)
	assert.Nil(t, parseRequestRateLimitEnv())
}

// TestParseRequestRateLimitEnv_FullOverride verifies both fields
// for the per-tenant request limiter.
func TestParseRequestRateLimitEnv_FullOverride(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS", "200")
	t.Setenv("REPORT_SERVER_REQUEST_RATE_LIMIT_WINDOW", "30s")

	cfg := parseRequestRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 200, cfg.MaxRequests)
	assert.Equal(t, 30*time.Second, cfg.Window)
}

// TestParseRequestRateLimitEnv_InvalidValuesIgnored ensures a
// malformed value never weakens the limit.
func TestParseRequestRateLimitEnv_InvalidValuesIgnored(t *testing.T) {
	clearRateLimitEnv(t)
	t.Setenv("REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS", "-10")

	cfg := parseRequestRateLimitEnv()
	require.NotNil(t, cfg)
	assert.Equal(t, 600, cfg.MaxRequests, "invalid value must fall back to the default 600")
}
