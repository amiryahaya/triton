package license

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/amiryahaya/triton/internal/config"
)

// Guard enforces feature gating based on the resolved licence tier.
type Guard struct {
	license *License // nil → free tier
	tier    Tier
}

// NewGuard creates a Guard by resolving the licence token from (in order):
// flag value, TRITON_LICENSE_KEY env, ~/.triton/license.key file.
func NewGuard(flagKey string) *Guard {
	return newGuardWithKey(flagKey, loadPublicKey())
}

// NewGuardFromToken creates a Guard from an explicit token and public key.
// Intended for testing with ephemeral keypairs.
func NewGuardFromToken(token string, pubKey ed25519.PublicKey) *Guard {
	if token == "" {
		return &Guard{tier: TierFree}
	}
	if pubKey == nil {
		return &Guard{tier: TierFree}
	}

	lic, err := Parse(token, pubKey)
	if err != nil {
		log.Printf("warning: licence validation failed: %v (falling back to free tier)", err)
		return &Guard{tier: TierFree}
	}
	return &Guard{license: lic, tier: lic.Tier}
}

// newGuardWithKey resolves the token from flag → env → file, then validates.
func newGuardWithKey(flagKey string, pubKey ed25519.PublicKey) *Guard {
	token := resolveToken(flagKey, defaultLicensePath())
	return NewGuardFromToken(token, pubKey)
}

// newGuardWithKeyAndPath allows overriding the file path (for testing).
func newGuardWithKeyAndPath(flagKey string, pubKey ed25519.PublicKey, filePath string) *Guard {
	token := resolveToken(flagKey, filePath)
	return NewGuardFromToken(token, pubKey)
}

// resolveToken checks flag → env → file and returns the first non-empty token.
func resolveToken(flagKey, filePath string) string {
	if flagKey != "" {
		return flagKey
	}
	if env := os.Getenv("TRITON_LICENSE_KEY"); env != "" {
		return env
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			token := strings.TrimSpace(string(data))
			if token != "" {
				return token
			}
		}
	}
	return ""
}

// defaultLicensePath returns ~/.triton/license.key.
func defaultLicensePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".triton", "license.key")
}

// Tier returns the resolved licence tier.
func (g *Guard) Tier() Tier {
	return g.tier
}

// Allowed reports whether the given feature is permitted.
func (g *Guard) Allowed(f Feature) bool {
	return TierAllows(g.tier, f)
}

// Seats returns the number of seats. Free tier always returns 1.
func (g *Guard) Seats() int {
	if g.license == nil || g.license.Seats < 1 {
		return 1
	}
	return g.license.Seats
}

// License returns the parsed licence, or nil for free tier.
func (g *Guard) License() *License {
	return g.license
}

// EnforceProfile returns an error if the profile is not allowed.
func (g *Guard) EnforceProfile(profile string) error {
	f, ok := profileFeature[profile]
	if !ok {
		return nil // unknown profiles are handled elsewhere
	}
	return g.EnforceFeature(f)
}

// EnforceFormat returns an error if the output format is not allowed.
func (g *Guard) EnforceFormat(format string) error {
	if format == "all" {
		// "all" requires the highest format the tier allows; check each
		for _, f := range []Feature{FeatureFormatCDX, FeatureFormatHTML, FeatureFormatXLSX, FeatureFormatSARIF} {
			if !g.Allowed(f) {
				return g.EnforceFeature(f)
			}
		}
		return nil
	}
	f, ok := formatFeature[format]
	if !ok {
		return nil // unknown formats are handled elsewhere
	}
	return g.EnforceFeature(f)
}

// EnforceFeature returns an ErrFeatureGated error if the feature is not allowed.
func (g *Guard) EnforceFeature(f Feature) error {
	if g.Allowed(f) {
		return nil
	}
	return &ErrFeatureGated{Feature: f, Tier: g.tier}
}

// FilterConfig adjusts the config in-place to match the tier's allowed features.
// This is the primary enforcement point — the scanner engine never knows about licensing.
func (g *Guard) FilterConfig(cfg *config.Config) {
	// Downgrade profile if not allowed
	if !g.Allowed(profileFeature[cfg.Profile]) {
		allowed := AllowedProfiles(g.tier)
		if len(allowed) > 0 {
			cfg.Profile = allowed[len(allowed)-1] // highest allowed
		}
	}

	// Restrict modules for free tier
	allowedMods := AllowedModules(g.tier)
	if allowedMods != nil {
		allowed := make(map[string]bool, len(allowedMods))
		for _, m := range allowedMods {
			allowed[m] = true
		}
		var filtered []string
		for _, m := range cfg.Modules {
			if allowed[m] {
				filtered = append(filtered, m)
			}
		}
		cfg.Modules = filtered
	}
}

// ErrFeatureGated is returned when a feature requires a higher licence tier.
type ErrFeatureGated struct {
	Feature Feature
	Tier    Tier
}

func (e *ErrFeatureGated) Error() string {
	return fmt.Sprintf(
		"feature %q requires a higher licence tier (current: %s). Upgrade at https://triton.dev/pricing",
		e.Feature, e.Tier,
	)
}
