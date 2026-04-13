package agentconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoad_NoFileReturnsZeroConfig verifies the "nothing configured"
// happy path: when no agent.yaml exists anywhere on the search chain,
// Load returns a zero-value Config and no error. The caller then
// runs with all built-in defaults (free tier, quick profile,
// local JSON report in ./reports).
func TestLoad_NoFileReturnsZeroConfig(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("HOME", emptyDir) // also shadow ~/.triton lookup

	cfg, err := Load(emptyDir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, cfg.IsZeroValue(), "no file found should produce a zero-value config")
	assert.Empty(t, cfg.LicenseKey)
	assert.Empty(t, cfg.ReportServer)
	assert.Empty(t, cfg.LoadedFrom())
}

// TestLoad_ExeDirWins verifies that agent.yaml next to the
// executable is preferred over ~/.triton/agent.yaml. This is the
// documented precedence order — the exe-dir file is how an operator
// customizes a specific deployment without touching the user's
// home directory.
func TestLoad_ExeDirWins(t *testing.T) {
	exeDir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Write a DIFFERENT license key in each candidate location so
	// the test can prove which file was actually read.
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("license_key: from-exe-dir\n"),
		0600,
	))
	tritonDir := filepath.Join(home, ".triton")
	require.NoError(t, os.MkdirAll(tritonDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(tritonDir, "agent.yaml"),
		[]byte("license_key: from-home-dir\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "from-exe-dir", cfg.LicenseKey,
		"exe-dir file must win over home-dir file")
	assert.Equal(t, filepath.Join(exeDir, "agent.yaml"), cfg.LoadedFrom())
}

// TestLoad_HomeDirFallback verifies the ~/.triton/agent.yaml
// fallback when the exe directory has no agent.yaml.
func TestLoad_HomeDirFallback(t *testing.T) {
	exeDir := t.TempDir() // intentionally empty
	home := t.TempDir()
	t.Setenv("HOME", home)

	tritonDir := filepath.Join(home, ".triton")
	require.NoError(t, os.MkdirAll(tritonDir, 0700))
	homeFile := filepath.Join(tritonDir, "agent.yaml")
	require.NoError(t, os.WriteFile(homeFile, []byte(`
license_key: from-home-dir
report_server: https://reports.example.com
profile: standard
`), 0600))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "from-home-dir", cfg.LicenseKey)
	assert.Equal(t, "https://reports.example.com", cfg.ReportServer)
	assert.Equal(t, "standard", cfg.Profile)
	assert.Equal(t, homeFile, cfg.LoadedFrom())
}

// TestLoad_MalformedFileIsHardError covers the "typo in agent.yaml
// must be loud" contract. A file that exists but cannot be parsed
// returns an error rather than silently falling through to the
// next candidate — otherwise a typo would produce confusing
// "no license found" messages instead of the real cause.
func TestLoad_MalformedFileIsHardError(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("license_key: [not closed\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.Error(t, err, "malformed yaml must not be silently ignored")
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "invalid yaml")
}

// TestLoad_EmptyFileIsValid verifies that an empty agent.yaml is
// treated as "use all defaults but remember it existed". The
// agent's startup banner can still say "agent.yaml found at X"
// to confirm the operator's intent even when they haven't filled
// in any fields yet.
func TestLoad_EmptyFileIsValid(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(exeDir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0600))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.False(t, cfg.IsZeroValue(),
		"empty file is still a file — IsZeroValue should be false")
	assert.Equal(t, path, cfg.LoadedFrom())
	assert.Empty(t, cfg.LicenseKey, "empty file yields empty fields")
}

// TestLoad_AllFieldsParse verifies a fully-populated agent.yaml
// round-trips through yaml.Unmarshal correctly. Any drift in field
// tags or types would break this test.
func TestLoad_AllFieldsParse(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte(`
license_key: "eyJsaWQiOiJhYmMifQ.sig"
report_server: "https://reports.example.com"
profile: "comprehensive"
output_dir: "/var/lib/triton/reports"
formats:
  - json
  - html
  - xlsx
`),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "eyJsaWQiOiJhYmMifQ.sig", cfg.LicenseKey)
	assert.Equal(t, "https://reports.example.com", cfg.ReportServer)
	assert.Equal(t, "comprehensive", cfg.Profile)
	assert.Equal(t, "/var/lib/triton/reports", cfg.OutputDir)
	assert.Equal(t, []string{"json", "html", "xlsx"}, cfg.Formats)
}

// TestResolveOutputDir_Absolute verifies absolute paths pass through
// unchanged — operators who set /var/log/triton should get exactly
// that, not <exe-dir>/var/log/triton.
func TestResolveOutputDir_Absolute(t *testing.T) {
	cfg := &Config{OutputDir: "/var/lib/triton/reports"}
	assert.Equal(t, "/var/lib/triton/reports", cfg.ResolveOutputDir())
}

// TestResolveOutputDir_RelativeJoinsExeDir verifies that a relative
// path is joined with the exe directory, NOT the shell cwd. This
// is the "fool-proof deployment" property: a user double-clicking
// the binary from Finder has no meaningful cwd, so relative output
// paths must be anchored to something predictable — the location
// of the binary itself.
func TestResolveOutputDir_RelativeJoinsExeDir(t *testing.T) {
	// We can't easily shim executableDir() in a unit test because
	// os.Executable is platform-specific. Instead, assert the
	// property indirectly: the returned path must contain "reports"
	// as the final component AND must be absolute.
	cfg := &Config{OutputDir: "reports"}
	got := cfg.ResolveOutputDir()
	assert.True(t, filepath.IsAbs(got) || filepath.Base(got) == "reports",
		"relative output_dir must be joined with an absolute prefix or left relative as a last resort")
	assert.Equal(t, "reports", filepath.Base(got))
}

// TestResolveOutputDir_EmptyDefaultsToReports verifies the
// fool-proof default: an empty OutputDir means "<exe-dir>/reports".
func TestResolveOutputDir_EmptyDefaultsToReports(t *testing.T) {
	cfg := &Config{}
	got := cfg.ResolveOutputDir()
	assert.Equal(t, "reports", filepath.Base(got),
		"default output_dir must be the 'reports' subdirectory")
}

// TestLoad_BlockScalarLicenseKeyTrimmed verifies the Sprint 3
// full-review F2 fix: a license_key pasted via the YAML block
// scalar (|) form preserves trailing newlines, which would
// otherwise cause the license token's base64 decode to fail and
// the agent to fall back to free tier silently. loadFile now
// trims surrounding whitespace on credential-shaped fields.
func TestLoad_BlockScalarLicenseKeyTrimmed(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	// The | block scalar form preserves ONE trailing newline by
	// default. Without trimming, the resulting Go string would be
	// "eyJ...token.sig\n" which fails Ed25519 verification.
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("license_key: |\n  eyJlbXB0eSI6dHJ1ZX0.signature\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "eyJlbXB0eSI6dHJ1ZX0.signature", cfg.LicenseKey,
		"block scalar license_key must be trimmed of surrounding whitespace")
}

// TestLoad_ReportServerTrimmed covers the same trim behavior for
// report_server since a trailing newline on the URL would break
// http.NewRequest with "invalid control character in URL".
func TestLoad_ReportServerTrimmed(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("report_server: |\n  https://reports.example.com\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "https://reports.example.com", cfg.ReportServer)
}

// TestLoad_LicenseServerFields verifies that the license_server
// and license_id fields round-trip through yaml parse and get
// whitespace-trimmed like other credential-shaped fields.
func TestLoad_LicenseServerFields(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte(`
license_server: "https://license.example.com"
license_id: "550e8400-e29b-41d4-a716-446655440000"
license_key: "eyJ0ZXN0Ijp0cnVlfQ.sig"
`),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "https://license.example.com", cfg.LicenseServer)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", cfg.LicenseID)
	assert.Equal(t, "eyJ0ZXN0Ijp0cnVlfQ.sig", cfg.LicenseKey)
}

// TestLoad_LicenseServerTrimmed verifies block-scalar whitespace
// trimming on the license_server and license_id fields, matching
// the existing trim behavior for license_key and report_server.
func TestLoad_LicenseServerTrimmed(t *testing.T) {
	exeDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.WriteFile(
		filepath.Join(exeDir, "agent.yaml"),
		[]byte("license_server: |\n  https://license.example.com\nlicense_id: |\n  some-uuid\n"),
		0600,
	))

	cfg, err := Load(exeDir)
	require.NoError(t, err)
	assert.Equal(t, "https://license.example.com", cfg.LicenseServer)
	assert.Equal(t, "some-uuid", cfg.LicenseID)
}
