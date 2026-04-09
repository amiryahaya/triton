package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/agent"
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

	_, err := resolveAgentConfig(nil)
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

	_, err := resolveAgentConfig(nil)
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

			r, err := resolveAgentConfig(nil)
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

// TestLicenseExpiryWarning enumerates the bands the banner should
// react to. The helper is pure — we construct License values with
// specific ExpiresAt offsets from a fixed "now" so the test is
// insensitive to wall-clock time.
func TestLicenseExpiryWarning(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		expiresAt time.Time
		wantEmpty bool
		wantSub   string
	}{
		{
			name:      "nil license → no warning",
			expiresAt: time.Time{}, // sentinel — see special case below
			wantEmpty: true,
		},
		{
			name:      "plenty of runway (60 days) → no warning",
			expiresAt: now.Add(60 * 24 * time.Hour),
			wantEmpty: true,
		},
		{
			name:      "exactly 31 days → no warning (just outside the notice band)",
			expiresAt: now.Add(31 * 24 * time.Hour),
			wantEmpty: true,
		},
		{
			name:      "29 days → notice band",
			expiresAt: now.Add(29 * 24 * time.Hour),
			wantSub:   "notice: license expires in 29 days",
		},
		{
			name:      "6 days → urgent WARNING band",
			expiresAt: now.Add(6 * 24 * time.Hour),
			wantSub:   "WARNING: license expires in",
		},
		{
			name:      "already expired → EXPIRED warning",
			expiresAt: now.Add(-2 * time.Hour),
			wantSub:   "WARNING: license EXPIRED on",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var lic *license.License
			if c.name != "nil license → no warning" {
				lic = &license.License{ExpiresAt: c.expiresAt.Unix()}
			}
			got := licenseExpiryWarning(lic, now)
			if c.wantEmpty {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, c.wantSub)
			}
		})
	}
}

// TestDefaultIntervalJitter_StaysWithinBounds asserts the ±10%
// envelope over many draws. Uses a bounded loop rather than a
// property-based library to keep the test fast and dependency-free.
func TestDefaultIntervalJitter_StaysWithinBounds(t *testing.T) {
	const base = 10 * time.Minute
	maxAbs := base / 10 // ±10%
	for i := 0; i < 200; i++ {
		got := defaultIntervalJitter(base)
		assert.GreaterOrEqual(t, got, -maxAbs,
			"jitter %v below lower bound", got)
		assert.LessOrEqual(t, got, maxAbs,
			"jitter %v above upper bound", got)
	}
}

// TestDefaultIntervalJitter_ZeroBase returns zero for zero input
// so a one-shot agent (no --interval) never computes a jitter.
func TestDefaultIntervalJitter_ZeroBase(t *testing.T) {
	assert.Equal(t, time.Duration(0), defaultIntervalJitter(0))
	assert.Equal(t, time.Duration(0), defaultIntervalJitter(-1*time.Second))
}

// TestWaitForServerReady_SucceedsOnFirstAttempt is the happy path.
func TestWaitForServerReady_SucceedsOnFirstAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := agent.New(server.URL)
	err := waitForServerReady(context.Background(), client, 3)
	assert.NoError(t, err)
}

// TestWaitForServerReady_RetriesTransientFailure flaps the server
// between 503 and 200 to confirm the retry loop absorbs a brief
// outage rather than exiting immediately.
func TestWaitForServerReady_RetriesTransientFailure(t *testing.T) {
	// Collapse the backoff so this test doesn't sleep for 6+ seconds.
	orig := healthCheckBackoff
	healthCheckBackoff = 5 * time.Millisecond
	t.Cleanup(func() { healthCheckBackoff = orig })

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := agent.New(server.URL)
	err := waitForServerReady(context.Background(), client, 5)
	assert.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

// TestWaitForServerReady_GivesUpAfterMaxAttempts confirms the loop
// bounds — an indefinitely-down server must not loop forever.
func TestWaitForServerReady_GivesUpAfterMaxAttempts(t *testing.T) {
	orig := healthCheckBackoff
	healthCheckBackoff = 5 * time.Millisecond
	t.Cleanup(func() { healthCheckBackoff = orig })

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := agent.New(server.URL)
	err := waitForServerReady(context.Background(), client, 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "after 3 attempts")
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

// TestWaitForServerReady_ContextCancellation stops early on cancel.
func TestWaitForServerReady_ContextCancellation(t *testing.T) {
	orig := healthCheckBackoff
	healthCheckBackoff = 100 * time.Millisecond
	t.Cleanup(func() { healthCheckBackoff = orig })

	ctx, cancel := context.WithCancel(context.Background())
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := agent.New(server.URL)
	err := waitForServerReady(ctx, client, 10)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.LessOrEqual(t, atomic.LoadInt32(&attempts), int32(2))
}
