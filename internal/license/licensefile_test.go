package license

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveLicenseFilePath_FlagWins verifies that a non-empty flag
// value takes precedence over the env var and the default path.
func TestResolveLicenseFilePath_FlagWins(t *testing.T) {
	t.Setenv("TRITON_LICENSE_FILE", "/from/env")
	got := ResolveLicenseFilePath("/from/flag")
	assert.Equal(t, "/from/flag", got)
}

// TestResolveLicenseFilePath_EnvFallback verifies that with no flag,
// the TRITON_LICENSE_FILE env var takes precedence over the default.
func TestResolveLicenseFilePath_EnvFallback(t *testing.T) {
	t.Setenv("TRITON_LICENSE_FILE", "/from/env")
	got := ResolveLicenseFilePath("")
	assert.Equal(t, "/from/env", got)
}

// TestResolveLicenseFilePath_DefaultFallback verifies that with no flag
// and no env, the default ~/.triton/license.key path is returned.
func TestResolveLicenseFilePath_DefaultFallback(t *testing.T) {
	t.Setenv("TRITON_LICENSE_FILE", "")
	got := ResolveLicenseFilePath("")
	// DefaultLicensePath returns an absolute path ending in
	// .triton/license.key — don't hard-code the home directory.
	assert.Contains(t, got, ".triton")
	assert.Contains(t, got, "license.key")
}

// TestLoadTokenFromFile_Happy verifies that a file containing a
// whitespace-padded token is read and trimmed correctly.
func TestLoadTokenFromFile_Happy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.key")
	require.NoError(t, os.WriteFile(path, []byte("  eyJs.some.token  \n"), 0600))

	got := LoadTokenFromFile(path)
	assert.Equal(t, "eyJs.some.token", got)
}

// TestLoadTokenFromFile_MissingFileReturnsEmpty verifies the no-panic
// contract: a missing file becomes an empty string, not an error.
// Callers treat empty as "no token" and fall through.
func TestLoadTokenFromFile_MissingFileReturnsEmpty(t *testing.T) {
	got := LoadTokenFromFile("/nonexistent/path/license.key")
	assert.Equal(t, "", got)
}

// TestLoadTokenFromFile_EmptyPath verifies the zero-input case.
func TestLoadTokenFromFile_EmptyPath(t *testing.T) {
	assert.Equal(t, "", LoadTokenFromFile(""))
}

// TestNewGuardFromFlags_FileFlagOverridesDefault walks the full CLI
// entry point: a custom --license-file path should be preferred over
// the default ~/.triton/license.key even when no --license-key is set.
func TestNewGuardFromFlags_FileFlagOverridesDefault(t *testing.T) {
	// Create an ephemeral keypair and a valid token for it.
	pub, priv, err := GenerateKeypair()
	require.NoError(t, err)
	tokenStr := testTokenWithOrg(t, TierPro, "TestOrg", priv)

	// Write the token to a custom path.
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom-license.key")
	require.NoError(t, os.WriteFile(custom, []byte(tokenStr), 0600))

	// Build a guard that uses the custom path AND the ephemeral
	// pubkey. We have to bypass NewGuardFromFlags (which uses the
	// embedded default pubkey) and construct via the same resolver.
	path := ResolveLicenseFilePath(custom)
	assert.Equal(t, custom, path)

	token := resolveToken("", path)
	g := NewGuardFromToken(token, pub)
	assert.Equal(t, TierPro, g.Tier(),
		"custom license-file path must produce a valid guard")
}

// TestResolveToken_FlagBeatsFile verifies the precedence: a literal
// --license-key value wins over any file path, matching the
// documented resolution order.
func TestResolveToken_FlagBeatsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.key")
	require.NoError(t, os.WriteFile(path, []byte("from-file"), 0600))

	t.Setenv("TRITON_LICENSE_KEY", "")
	got := resolveToken("from-flag", path)
	assert.Equal(t, "from-flag", got)
}
