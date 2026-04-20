package license

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Guard enforces feature gating based on the resolved licence tier.
//
// The usage map is populated by RecordUsage (called by the
// UsagePusher's OnPushSuccess hook when the LS response includes
// remaining-cap info). CurrentUsage reads it. Pre-Batch-H call sites
// that never wire the hook see an empty map and a 0 read, which is
// correct behaviour for soft-buffer checks that haven't been
// primed yet.
type Guard struct {
	license *License // nil → free tier
	tier    Tier

	usageMu sync.RWMutex
	usage   map[string]int64 // key: "<metric>/<window>"
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
	token := resolveToken(flagKey, DefaultLicensePath())
	return NewGuardFromToken(token, pubKey)
}

// newGuardWithKeyAndPath allows overriding the file path (for testing).
func newGuardWithKeyAndPath(flagKey string, pubKey ed25519.PublicKey, filePath string) *Guard {
	token := resolveToken(flagKey, filePath)
	return NewGuardFromToken(token, pubKey)
}

// resolveToken checks flag → env → file and returns the first non-empty
// token, where `filePath` is the fallback path to try when neither the
// flag nor the env var is set.
//
// Resolution order (first non-empty wins):
//  1. --license-key CLI flag (literal token)
//  2. TRITON_LICENSE_KEY env var (literal token)
//  3. --license-file CLI flag (file path; caller resolves and passes here)
//  4. TRITON_LICENSE_FILE env var (file path)
//  5. The supplied filePath fallback (typically DefaultLicensePath())
//
// Steps 3–5 are handled by the caller pre-computing the effective
// filePath via ResolveLicenseFilePath before calling resolveToken.
// This keeps the precedence explicit without threading a half-dozen
// parameters through every internal call site.
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

// ResolveLicenseFilePath picks the effective license-file path for
// loading a token. The first non-empty argument wins, falling back
// to the TRITON_LICENSE_FILE env var, and finally to the default
// ~/.triton/license.key path.
//
// Phase 5 Sprint 3 addition — callers that want to override the
// default path (e.g., `triton agent --license-file /etc/triton/license`)
// pass the flag value here; when empty the standard fallbacks kick in.
func ResolveLicenseFilePath(flagFile string) string {
	if flagFile != "" {
		return flagFile
	}
	if env := os.Getenv("TRITON_LICENSE_FILE"); env != "" {
		return env
	}
	return DefaultLicensePath()
}

// ResolveToken is the canonical public helper for CLI callers that
// need to resolve a licence token from the full --license-key /
// TRITON_LICENSE_KEY / --license-file / TRITON_LICENSE_FILE / default
// precedence without constructing a Guard. Returns an empty string
// when no source is set — callers treat empty as "free tier".
//
// Phase 5 Sprint 3 D4 — exported so cmd/root.go's tenant-pubkey
// override branch can reuse the same precedence the default branch
// uses, instead of hand-rolling a subset that forgot to check
// TRITON_LICENSE_KEY.
func ResolveToken(flagKey, flagFile string) string {
	filePath := ResolveLicenseFilePath(flagFile)
	return resolveToken(flagKey, filePath)
}

// NewGuardFromFlags is the canonical constructor for CLI callers who
// have both a --license-key and --license-file flag in hand. It
// resolves the effective file path via ResolveLicenseFilePath and
// then runs the standard resolveToken precedence.
func NewGuardFromFlags(flagKey, flagFile string) *Guard {
	pubKey := loadPublicKey()
	filePath := ResolveLicenseFilePath(flagFile)
	token := resolveToken(flagKey, filePath)
	return NewGuardFromToken(token, pubKey)
}

// LoadTokenFromFile reads a token string from the given file path,
// trimming surrounding whitespace. Returns empty string on any error
// (missing file, permission denied, empty content) — callers treat
// empty as "no token" and let the normal resolution fall through.
//
// Used by cmd/root.go's online-validation path to pre-resolve the
// --license-file content before handing off to NewGuardWithServer.
func LoadTokenFromFile(filePath string) string {
	if filePath == "" {
		return ""
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// DefaultLicensePath returns ~/.triton/license.key.
func DefaultLicensePath() string {
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

// OrgID returns the organization ID from the licence, or empty string.
func (g *Guard) OrgID() string {
	if g.license == nil {
		return ""
	}
	return g.license.OrgID
}

// OrgName returns the organization name from the licence, or empty string.
func (g *Guard) OrgName() string {
	if g.license == nil {
		return ""
	}
	return g.license.Org
}

// EnforceProfile returns an error if the profile is not allowed.
//
// When the licence carries v2 features (featuresAnySet), the v2
// comprehensive_profile flag takes precedence over the legacy tier map.
// quick and standard always pass in the v2 path — only comprehensive is
// gated. Pre-v2 tokens fall through to the legacy tier enforcement
// unchanged, so existing deployments are unaffected.
func (g *Guard) EnforceProfile(profile string) error {
	// v2 path: consult features if any v2 flag is set.
	if g != nil && g.license != nil && featuresAnySet(g.license.Features) {
		if profile == "comprehensive" && !g.license.Features.ComprehensiveProfile {
			return &ErrFeatureGated{Feature: FeatureProfileComprehensive, Tier: g.tier}
		}
		return nil // quick/standard always allowed; unknown profiles pass through
	}
	// Legacy tier path — unchanged.
	f, ok := profileFeature[profile]
	if !ok {
		return nil // unknown profiles are handled elsewhere
	}
	return g.EnforceFeature(f)
}

// EnforceFormat returns an error if the output format is not allowed.
// For "all", this always succeeds — the caller should use AllowedFormats
// to determine which formats to generate for the tier.
//
// When the licence carries v2 features with a non-empty ExportFormats
// allowlist, that list takes precedence over the legacy tier map so
// operators can grant or restrict individual formats independently of
// tier. Pre-v2 tokens fall through to the legacy tier enforcement.
func (g *Guard) EnforceFormat(format string) error {
	if format == "all" {
		return nil // "all" means "generate all my tier allows"
	}
	// v2 path: use AllowsFormat which already handles the compat fallback.
	// Only enter this branch when v2 features are set AND an explicit
	// ExportFormats list is present, so that a v2 token with no
	// ExportFormats doesn't silently block all formats.
	if g != nil && g.license != nil && featuresAnySet(g.license.Features) && len(g.license.Features.ExportFormats) > 0 {
		if !g.AllowsFormat(format) {
			f := formatFeature[format] // may be zero-value Feature; ErrFeatureGated still meaningful
			return &ErrFeatureGated{Feature: f, Tier: g.tier}
		}
		return nil
	}
	// Legacy tier path — unchanged.
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
func (g *Guard) FilterConfig(cfg *scannerconfig.Config) {
	// Downgrade profile if not allowed
	if !g.Allowed(profileFeature[cfg.Profile]) {
		allowed := AllowedProfiles(g.tier)
		if len(allowed) > 0 {
			cfg.Profile = allowed[len(allowed)-1] // highest allowed
		}
	}

	// Clear DB URL if tier does not allow DB feature
	if !g.Allowed(FeatureDB) {
		cfg.DBUrl = ""
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

	// Drop target types for modules not allowed at this tier. Primary
	// enforcement point for the OCI image and Kubernetes scanners — if
	// the gated module was already filtered out of cfg.Modules above,
	// we also strip its targets so the engine dispatch never considers
	// them.
	var filteredTargets []model.ScanTarget
	var droppedImage, droppedK8s bool
	for _, t := range cfg.ScanTargets {
		switch t.Type {
		case model.TargetOCIImage:
			if containsString(cfg.Modules, "oci_image") {
				filteredTargets = append(filteredTargets, t)
			} else {
				droppedImage = true
			}
		case model.TargetKubernetesCluster:
			if containsString(cfg.Modules, "k8s_live") {
				filteredTargets = append(filteredTargets, t)
			} else {
				droppedK8s = true
			}
		default:
			filteredTargets = append(filteredTargets, t)
		}
	}
	cfg.ScanTargets = filteredTargets

	if droppedImage {
		log.Printf("warning: --image targets dropped; OCI image scanning requires pro tier or higher (current: %s)", g.tier)
	}
	if droppedK8s {
		log.Printf("warning: --kubeconfig target dropped; live Kubernetes scanning requires enterprise tier (current: %s)", g.tier)
	}
}

// NewGuardWithServer creates a Guard that validates tokens online against a
// license server, with offline cache fallback. If the server is unreachable
// and the cached token is fresh (< GracePeriodDays), the cached tier is used.
// Otherwise, it falls back to free tier.
func NewGuardWithServer(flagKey, serverURL, lid string) *Guard {
	pubKey := loadPublicKey()
	token := resolveToken(flagKey, DefaultLicensePath())

	// If no server URL, fall back to standard offline validation
	if serverURL == "" {
		return NewGuardFromToken(token, pubKey)
	}

	// Read license ID from flag or cache
	if lid == "" {
		if meta, err := LoadCacheMeta(DefaultCacheMetaPath()); err == nil {
			lid = meta.LicenseID
		}
	}

	// If we have no license ID, fall back to offline
	if lid == "" {
		return NewGuardFromToken(token, pubKey)
	}

	// Try online validation
	client := NewServerClient(serverURL)
	resp, err := client.Validate(lid, token)
	if err == nil {
		if resp.Valid {
			// Server says valid — update cache, use server tier
			meta := &CacheMeta{
				ServerURL:     serverURL,
				LicenseID:     lid,
				Tier:          resp.Tier,
				Seats:         resp.Seats,
				SeatsUsed:     resp.SeatsUsed,
				ExpiresAt:     resp.ExpiresAt,
				LastValidated: timeNow(),
			}
			_ = meta.Save(DefaultCacheMetaPath())

			// Parse token for full Guard (signature already verified by server).
			// Trust the server tier directly — the token signature is valid.
			g := NewGuardFromToken(token, pubKey)
			if g.license != nil && resp.Tier != "" {
				if t := Tier(resp.Tier); t == TierFree || t == TierPro || t == TierEnterprise {
					g.tier = t
				}
			}
			return g
		}
		// Server says invalid
		log.Printf("warning: license server says token is invalid: %s (falling back to free tier)", resp.Reason)
		return &Guard{tier: TierFree}
	}

	// Server unreachable — try offline cache
	log.Printf("warning: license server unreachable: %v (checking offline cache)", err)
	if meta, err := LoadCacheMeta(DefaultCacheMetaPath()); err == nil && meta.IsFresh() {
		log.Printf("warning: using cached licence tier %s (last validated %s)", meta.Tier, meta.LastValidated.Format("2006-01-02"))
		g := NewGuardFromToken(token, pubKey)
		if g.license != nil && meta.Tier != "" {
			if t := Tier(meta.Tier); t == TierFree || t == TierPro || t == TierEnterprise {
				g.tier = t
			}
		}
		return g
	}

	// Stale or no cache — fall back to free tier
	log.Printf("warning: offline cache stale or missing, falling back to free tier")
	return NewGuardFromToken(token, pubKey)
}

// timeNow is a function variable for testing.
var timeNow = func() time.Time {
	return time.Now().UTC()
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

// containsString reports whether needle is present in haystack.
func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
