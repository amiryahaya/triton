package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateTempPassword_Uniqueness asserts that 100 successive
// calls produce 100 distinct passwords. The birthday-probability of
// a collision at ~144 bits of entropy is astronomically small, so
// any collision indicates a broken RNG wiring.
func TestGenerateTempPassword_Uniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := GenerateTempPassword(24)
		require.NoError(t, err)
		assert.False(t, seen[p], "generated passwords must be unique")
		seen[p] = true
	}
}

// TestGenerateTempPassword_MeetsMinLength verifies the default (24)
// call always produces a password satisfying MinPasswordLength.
// This is the guarantee provisioning code relies on.
func TestGenerateTempPassword_MeetsMinLength(t *testing.T) {
	for i := 0; i < 10; i++ {
		p, err := GenerateTempPassword(24)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(p), MinPasswordLength,
			"temp password must satisfy the policy minimum")
	}
}

// TestGenerateTempPassword_URLSafe verifies the output contains only
// base64url characters. No +, /, or = — the three chars that distinguish
// RawURLEncoding from StdEncoding. Critical because the password ends
// up in URLs (invite links), JSON bodies, and shell copy-paste.
func TestGenerateTempPassword_URLSafe(t *testing.T) {
	p, err := GenerateTempPassword(24)
	require.NoError(t, err)
	assert.False(t, strings.ContainsAny(p, "+/="),
		"temp password must be base64url (no +, /, =)")
}

// TestGenerateTempPassword_ClampsNonPositiveLength verifies that
// length <= 0 is clamped to the default of 24 rather than crashing
// or returning an empty string.
func TestGenerateTempPassword_ClampsNonPositiveLength(t *testing.T) {
	for _, bad := range []int{0, -1, -100} {
		p, err := GenerateTempPassword(bad)
		require.NoError(t, err, "length=%d should not error", bad)
		assert.Equal(t, 24, len(p),
			"length=%d should be clamped to default 24, got %d", bad, len(p))
	}
}

// TestGenerateTempPassword_LengthHonored verifies that for positive
// lengths, the output has AT LEAST the requested length. The exact
// length may be slightly larger because base64url rounds up to the
// next multiple of 4, which the godoc documents as acceptable.
func TestGenerateTempPassword_LengthHonored(t *testing.T) {
	for _, want := range []int{12, 16, 20, 24, 32} {
		p, err := GenerateTempPassword(want)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(p), want,
			"length=%d got %d", want, len(p))
	}
}
