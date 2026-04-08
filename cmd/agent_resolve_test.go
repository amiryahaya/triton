package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveAgentConfig_InvalidProfileErrors verifies the
// Sprint 3 full-review F3 fix: a typo in the profile field
// (e.g. "standdard") must surface as a hard error rather than
// silently being rewritten to comprehensive by applyTierFiltering's
// fallback loop. The error message must point at the exact source
// so the operator can fix the typo.
func TestResolveAgentConfig_InvalidProfileErrors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "agent.yaml"),
		[]byte("profile: standdard\n"),
		0600,
	))
	t.Setenv("HOME", t.TempDir())

	// Use the test hook to point agentconfig at the fake exe dir.
	agentConfigDir = dir
	t.Cleanup(func() { agentConfigDir = "" })
	agentProfile = "" // flag unset → yaml value is the source

	_, err := resolveAgentConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown profile "standdard"`)
	assert.Contains(t, err.Error(),
		filepath.Join(dir, "agent.yaml"),
		"error must identify which file carries the bad value")
	assert.Contains(t, err.Error(), "quick, standard, comprehensive",
		"error must enumerate valid profile names for a quick fix")
}

// TestResolveAgentConfig_InvalidFlagProfileErrors verifies that
// the error attribution works for the CLI flag path too — not just
// for agent.yaml. An operator running `triton agent --profile bla`
// should see "--profile flag" in the error, not the path to a
// potentially irrelevant agent.yaml.
func TestResolveAgentConfig_InvalidFlagProfileErrors(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = emptyDir
	t.Cleanup(func() { agentConfigDir = "" })
	agentProfile = "bla"
	t.Cleanup(func() { agentProfile = "" })

	_, err := resolveAgentConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown profile "bla"`)
	assert.Contains(t, err.Error(), "--profile flag",
		"CLI-flag path must attribute the error to the flag, not a yaml file")
}

// TestResolveAgentConfig_ValidProfilesAllAccepted enumerates the
// closed set to catch any drift in the validProfiles map vs
// config.Load's profile handling.
func TestResolveAgentConfig_ValidProfilesAllAccepted(t *testing.T) {
	for _, p := range []string{"quick", "standard", "comprehensive"} {
		t.Run(p, func(t *testing.T) {
			emptyDir := t.TempDir()
			t.Setenv("HOME", t.TempDir())
			agentConfigDir = emptyDir
			t.Cleanup(func() { agentConfigDir = "" })
			agentProfile = p
			t.Cleanup(func() { agentProfile = "" })

			r, err := resolveAgentConfig()
			require.NoError(t, err, "profile %q must be accepted", p)
			assert.Equal(t, p, r.requestedProfile)
		})
	}
}

// TestProfileDowngradeChain_NeverUpgrades is a pure-function
// regression test for the walk order in applyTierFiltering. A
// request for "standard" on a free tier that only allows "quick"
// must land on "quick", NOT jump to "comprehensive" because it
// happened to be listed first. This is the Sprint 3 full-review
// F3 / architect note about silent upgrades.
func TestProfileDowngradeChain_NeverUpgrades(t *testing.T) {
	cases := []struct {
		requested string
		want      []string
	}{
		{"comprehensive", []string{"comprehensive", "standard", "quick"}},
		{"standard", []string{"standard", "quick"}},
		{"quick", []string{"quick"}},
	}
	for _, c := range cases {
		t.Run(c.requested, func(t *testing.T) {
			got := profileDowngradeChain(c.requested)
			assert.Equal(t, c.want, got,
				"downgrade walk from %q must never step up the tier ladder",
				c.requested)
		})
	}
}

// TestProfileSource_AttributionMatrix covers every combination of
// "yaml path present / absent" × "CLI flag set / unset" so error
// messages point at the right location.
func TestProfileSource_AttributionMatrix(t *testing.T) {
	assert.Equal(t, "--profile flag", profileSource("", true))
	assert.Equal(t, "--profile flag", profileSource("/some/agent.yaml", true),
		"CLI flag attribution wins over yaml when both are present")
	assert.Equal(t, "/some/agent.yaml", profileSource("/some/agent.yaml", false))
	assert.Equal(t, "built-in default", profileSource("", false))
}
