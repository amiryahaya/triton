package license

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
)

func TestNewGuard_NoLicense(t *testing.T) {
	// No flag, no env, no file → free tier
	t.Setenv("TRITON_LICENSE_KEY", "")
	g := NewGuardFromToken("", nil)
	assert.Equal(t, TierFree, g.Tier())
}

func TestNewGuard_FromFlag(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)

	g := NewGuardFromToken(token, pub)
	assert.Equal(t, TierPro, g.Tier())
}

func TestNewGuard_FromEnv(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierEnterprise, priv)

	t.Setenv("TRITON_LICENSE_KEY", token)
	g := newGuardWithKey("", pub)
	assert.Equal(t, TierEnterprise, g.Tier())
}

func TestNewGuard_FromFile(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "license.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(token), 0600))

	t.Setenv("TRITON_LICENSE_KEY", "")
	g := newGuardWithKeyAndPath("", pub, keyFile)
	assert.Equal(t, TierPro, g.Tier())
}

func TestNewGuard_FlagPrecedence(t *testing.T) {
	pub, priv := testKeypair(t)
	proToken := testToken(t, TierPro, priv)
	entToken := testTokenWithOrg(t, TierEnterprise, "Env Org", priv)

	t.Setenv("TRITON_LICENSE_KEY", entToken)

	// Flag takes precedence over env
	g := newGuardWithKey(proToken, pub)
	assert.Equal(t, TierPro, g.Tier())
}

func TestNewGuard_InvalidToken(t *testing.T) {
	pub, _ := testKeypair(t)
	g := NewGuardFromToken("invalid-garbage-token", pub)
	assert.Equal(t, TierFree, g.Tier(), "invalid token should degrade to free")
}

func TestGuard_Allowed_FreeTier(t *testing.T) {
	g := NewGuardFromToken("", nil) // free tier
	assert.True(t, g.Allowed(FeatureProfileQuick))
	assert.True(t, g.Allowed(FeatureFormatJSON))
	assert.False(t, g.Allowed(FeatureProfileStandard))
	assert.False(t, g.Allowed(FeatureServerMode))
}

func TestGuard_Allowed_ProTier(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)
	g := NewGuardFromToken(token, pub)

	assert.True(t, g.Allowed(FeatureProfileStandard))
	assert.True(t, g.Allowed(FeatureFormatCDX))
	assert.True(t, g.Allowed(FeatureMetrics))
	assert.False(t, g.Allowed(FeatureServerMode))
}

func TestGuard_EnforceProfile_Blocked(t *testing.T) {
	g := NewGuardFromToken("", nil) // free
	err := g.EnforceProfile("standard")
	require.Error(t, err)

	var gated *ErrFeatureGated
	assert.ErrorAs(t, err, &gated)
	assert.Equal(t, FeatureProfileStandard, gated.Feature)
	assert.Equal(t, TierFree, gated.Tier)
}

func TestGuard_EnforceProfile_Allowed(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)
	g := NewGuardFromToken(token, pub)

	assert.NoError(t, g.EnforceProfile("standard"))
	assert.NoError(t, g.EnforceProfile("quick"))
}

func TestGuard_EnforceFormat_Blocked(t *testing.T) {
	g := NewGuardFromToken("", nil)
	err := g.EnforceFormat("cdx")
	require.Error(t, err)

	var gated *ErrFeatureGated
	assert.ErrorAs(t, err, &gated)
}

func TestGuard_EnforceFormat_Allowed(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)
	g := NewGuardFromToken(token, pub)

	assert.NoError(t, g.EnforceFormat("json"))
	assert.NoError(t, g.EnforceFormat("cdx"))
	assert.NoError(t, g.EnforceFormat("html"))
}

func TestGuard_FilterConfig_FreeTier(t *testing.T) {
	g := NewGuardFromToken("", nil) // free

	cfg := &config.Config{
		Profile: "standard",
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries"},
	}

	g.FilterConfig(cfg)

	assert.Equal(t, "quick", cfg.Profile)
	assert.Equal(t, []string{"certificates", "keys", "packages"}, cfg.Modules)
}

func TestGuard_FilterConfig_ProTier(t *testing.T) {
	pub, priv := testKeypair(t)
	token := testToken(t, TierPro, priv)
	g := NewGuardFromToken(token, pub)

	cfg := &config.Config{
		Profile: "comprehensive",
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries"},
	}

	g.FilterConfig(cfg)

	// Pro allows all profiles and modules
	assert.Equal(t, "comprehensive", cfg.Profile)
	assert.Equal(t, []string{"certificates", "keys", "packages", "libraries", "binaries"}, cfg.Modules)
}

func TestGuard_Seats(t *testing.T) {
	// Free tier defaults to 1 seat
	g := NewGuardFromToken("", nil)
	assert.Equal(t, 1, g.Seats())

	// Paid tier uses configured seats
	pub, priv := testKeypair(t)
	lic := &License{
		ID:        "seat-test",
		Tier:      TierPro,
		Org:       "Seats Corp",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := Encode(lic, priv)
	require.NoError(t, err)

	g2 := NewGuardFromToken(token, pub)
	assert.Equal(t, 10, g2.Seats())
}

func TestErrFeatureGated_Message(t *testing.T) {
	err := &ErrFeatureGated{
		Feature: FeatureServerMode,
		Tier:    TierFree,
	}
	msg := err.Error()
	assert.Contains(t, msg, "server")
	assert.Contains(t, msg, "free")
	assert.Contains(t, msg, "Upgrade", "should mention upgrade")
}

// testTokenWithOrg creates a token with a specific org name.
func testTokenWithOrg(t *testing.T, tier Tier, org string, priv ed25519.PrivateKey) string {
	t.Helper()
	lic := &License{
		ID:        "test-org-id",
		Tier:      tier,
		Org:       org,
		Seats:     5,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := Encode(lic, priv)
	require.NoError(t, err)
	return token
}
