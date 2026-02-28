package license

// Tier represents a licence level.
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// Feature represents a gated capability.
type Feature string

const (
	FeatureProfileQuick         Feature = "profile:quick"
	FeatureProfileStandard      Feature = "profile:standard"
	FeatureProfileComprehensive Feature = "profile:comprehensive"

	FeatureFormatJSON  Feature = "format:json"
	FeatureFormatCDX   Feature = "format:cdx"
	FeatureFormatHTML  Feature = "format:html"
	FeatureFormatXLSX  Feature = "format:xlsx"
	FeatureFormatSARIF Feature = "format:sarif"

	FeatureServerMode Feature = "server"
	FeatureAgentMode  Feature = "agent"

	FeatureMetrics       Feature = "metrics"
	FeatureIncremental   Feature = "incremental"
	FeatureDiff          Feature = "diff"
	FeatureTrend         Feature = "trend"
	FeatureDB            Feature = "db"
	FeaturePolicyBuiltin Feature = "policy:builtin"
	FeaturePolicyCustom  Feature = "policy:custom"
)

var tierFeatures = map[Tier]map[Feature]bool{
	TierFree: {
		FeatureProfileQuick: true,
		FeatureFormatJSON:   true,
	},
	TierPro: {
		FeatureProfileQuick:         true,
		FeatureProfileStandard:      true,
		FeatureProfileComprehensive: true,
		FeatureFormatJSON:           true,
		FeatureFormatCDX:            true,
		FeatureFormatHTML:           true,
		FeatureFormatXLSX:           true,
		FeatureMetrics:              true,
		FeatureIncremental:          true,
		FeatureDiff:                 true,
		FeatureTrend:                true,
		FeatureDB:                   true,
		FeaturePolicyBuiltin:        true,
	},
	TierEnterprise: {
		FeatureProfileQuick:         true,
		FeatureProfileStandard:      true,
		FeatureProfileComprehensive: true,
		FeatureFormatJSON:           true,
		FeatureFormatCDX:            true,
		FeatureFormatHTML:           true,
		FeatureFormatXLSX:           true,
		FeatureFormatSARIF:          true,
		FeatureServerMode:           true,
		FeatureAgentMode:            true,
		FeatureMetrics:              true,
		FeatureIncremental:          true,
		FeatureDiff:                 true,
		FeatureTrend:                true,
		FeatureDB:                   true,
		FeaturePolicyBuiltin:        true,
		FeaturePolicyCustom:         true,
	},
}

// TierAllows reports whether the given tier permits the given feature.
func TierAllows(t Tier, f Feature) bool {
	features, ok := tierFeatures[t]
	if !ok {
		return false
	}
	return features[f]
}

// profileFeature maps profile names to their feature constant.
var profileFeature = map[string]Feature{
	"quick":         FeatureProfileQuick,
	"standard":      FeatureProfileStandard,
	"comprehensive": FeatureProfileComprehensive,
}

// formatFeature maps format names to their feature constant.
var formatFeature = map[string]Feature{
	"json":  FeatureFormatJSON,
	"cdx":   FeatureFormatCDX,
	"html":  FeatureFormatHTML,
	"xlsx":  FeatureFormatXLSX,
	"sarif": FeatureFormatSARIF,
}

// AllowedProfiles returns the list of profile names the tier can use.
func AllowedProfiles(t Tier) []string {
	order := []string{"quick", "standard", "comprehensive"}
	var out []string
	for _, p := range order {
		if TierAllows(t, profileFeature[p]) {
			out = append(out, p)
		}
	}
	return out
}

// AllowedFormats returns the list of format names the tier can use.
func AllowedFormats(t Tier) []string {
	order := []string{"json", "cdx", "html", "xlsx", "sarif"}
	var out []string
	for _, f := range order {
		if TierAllows(t, formatFeature[f]) {
			out = append(out, f)
		}
	}
	return out
}

// freeModules is the restricted set for the free tier.
var freeModules = []string{"certificates", "keys", "packages"}

// AllowedModules returns the module list for the tier.
// Returns nil for paid tiers (all modules allowed).
func AllowedModules(t Tier) []string {
	if t == TierFree {
		out := make([]string, len(freeModules))
		copy(out, freeModules)
		return out
	}
	return nil
}
