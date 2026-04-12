package license

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTierAllows_FreeTier(t *testing.T) {
	// Free tier allows only quick profile and json format
	assert.True(t, TierAllows(TierFree, FeatureProfileQuick))
	assert.True(t, TierAllows(TierFree, FeatureFormatJSON))

	// Free tier does NOT allow pro/enterprise features
	assert.False(t, TierAllows(TierFree, FeatureProfileStandard))
	assert.False(t, TierAllows(TierFree, FeatureProfileComprehensive))
	assert.False(t, TierAllows(TierFree, FeatureFormatCDX))
	assert.False(t, TierAllows(TierFree, FeatureFormatHTML))
	assert.False(t, TierAllows(TierFree, FeatureFormatXLSX))
	assert.False(t, TierAllows(TierFree, FeatureFormatSARIF))
	assert.False(t, TierAllows(TierFree, FeatureServerMode))
	assert.False(t, TierAllows(TierFree, FeatureAgentMode))
	assert.False(t, TierAllows(TierFree, FeatureMetrics))
	assert.False(t, TierAllows(TierFree, FeatureIncremental))
	assert.False(t, TierAllows(TierFree, FeatureDiff))
	assert.False(t, TierAllows(TierFree, FeatureTrend))
	assert.False(t, TierAllows(TierFree, FeatureDB))
	assert.False(t, TierAllows(TierFree, FeaturePolicyBuiltin))
	assert.False(t, TierAllows(TierFree, FeaturePolicyCustom))
}

func TestTierAllows_ProTier(t *testing.T) {
	// Pro allows all profiles
	assert.True(t, TierAllows(TierPro, FeatureProfileQuick))
	assert.True(t, TierAllows(TierPro, FeatureProfileStandard))
	assert.True(t, TierAllows(TierPro, FeatureProfileComprehensive))

	// Pro allows most formats
	assert.True(t, TierAllows(TierPro, FeatureFormatJSON))
	assert.True(t, TierAllows(TierPro, FeatureFormatCDX))
	assert.True(t, TierAllows(TierPro, FeatureFormatHTML))
	assert.True(t, TierAllows(TierPro, FeatureFormatXLSX))

	// Pro allows analytics features
	assert.True(t, TierAllows(TierPro, FeatureMetrics))
	assert.True(t, TierAllows(TierPro, FeatureIncremental))
	assert.True(t, TierAllows(TierPro, FeatureDiff))
	assert.True(t, TierAllows(TierPro, FeatureTrend))
	assert.True(t, TierAllows(TierPro, FeatureDB))
	assert.True(t, TierAllows(TierPro, FeaturePolicyBuiltin))

	// Pro does NOT allow enterprise features
	assert.False(t, TierAllows(TierPro, FeatureFormatSARIF))
	assert.False(t, TierAllows(TierPro, FeatureServerMode))
	assert.False(t, TierAllows(TierPro, FeatureAgentMode))
	assert.False(t, TierAllows(TierPro, FeaturePolicyCustom))
}

func TestTierAllows_EnterpriseTier(t *testing.T) {
	// Enterprise allows everything
	allFeatures := []Feature{
		FeatureProfileQuick, FeatureProfileStandard, FeatureProfileComprehensive,
		FeatureFormatJSON, FeatureFormatCDX, FeatureFormatHTML, FeatureFormatXLSX, FeatureFormatSARIF,
		FeatureServerMode, FeatureAgentMode,
		FeatureMetrics, FeatureIncremental, FeatureDiff, FeatureTrend, FeatureDB,
		FeaturePolicyBuiltin, FeaturePolicyCustom,
	}
	for _, f := range allFeatures {
		assert.True(t, TierAllows(TierEnterprise, f), "enterprise should allow %s", f)
	}
}

func TestTierAllows_UnknownTier(t *testing.T) {
	assert.False(t, TierAllows(Tier("bogus"), FeatureProfileQuick))
	assert.False(t, TierAllows(Tier(""), FeatureFormatJSON))
}

func TestAllowedProfiles(t *testing.T) {
	free := AllowedProfiles(TierFree)
	require.Equal(t, []string{"quick"}, free)

	pro := AllowedProfiles(TierPro)
	assert.Contains(t, pro, "quick")
	assert.Contains(t, pro, "standard")
	assert.Contains(t, pro, "comprehensive")

	ent := AllowedProfiles(TierEnterprise)
	assert.Contains(t, ent, "quick")
	assert.Contains(t, ent, "standard")
	assert.Contains(t, ent, "comprehensive")
}

func TestAllowedFormats(t *testing.T) {
	free := AllowedFormats(TierFree)
	require.Equal(t, []string{"json"}, free)

	pro := AllowedFormats(TierPro)
	assert.Contains(t, pro, "json")
	assert.Contains(t, pro, "cdx")
	assert.Contains(t, pro, "html")
	assert.Contains(t, pro, "xlsx")
	assert.NotContains(t, pro, "sarif")

	ent := AllowedFormats(TierEnterprise)
	assert.Contains(t, ent, "sarif")
}

func TestAllowedModules(t *testing.T) {
	free := AllowedModules(TierFree)
	require.Equal(t, []string{"certificates", "keys", "packages"}, free)

	// Pro returns an explicit whitelist that includes oci_image but not k8s_live
	pro := AllowedModules(TierPro)
	require.NotNil(t, pro, "pro tier must return a non-nil whitelist")
	assert.Contains(t, pro, "certificates")
	assert.Contains(t, pro, "oci_image")
	assert.NotContains(t, pro, "k8s_live", "k8s_live is enterprise-only")

	// Enterprise returns nil (all modules allowed)
	assert.Nil(t, AllowedModules(TierEnterprise))
}

func TestFreeTierCannotAccessPro(t *testing.T) {
	proFeatures := []Feature{
		FeatureProfileStandard, FeatureProfileComprehensive,
		FeatureFormatCDX, FeatureFormatHTML, FeatureFormatXLSX,
		FeatureMetrics, FeatureIncremental, FeatureDiff, FeatureTrend, FeatureDB,
		FeaturePolicyBuiltin,
	}
	for _, f := range proFeatures {
		assert.False(t, TierAllows(TierFree, f), "free should not allow %s", f)
	}
}

func TestProTierCannotAccessEnterprise(t *testing.T) {
	entOnly := []Feature{
		FeatureFormatSARIF, FeatureServerMode, FeatureAgentMode, FeaturePolicyCustom,
	}
	for _, f := range entOnly {
		assert.False(t, TierAllows(TierPro, f), "pro should not allow %s", f)
	}
}
