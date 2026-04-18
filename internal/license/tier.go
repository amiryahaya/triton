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

	FeatureServerMode  Feature = "server"
	FeatureAgentMode   Feature = "agent"
	FeatureNetworkScan Feature = "network-scan"

	// FeatureFleetScan gates `triton fleet-scan` (SSH fan-out of detached
	// scans). Binary distribution + sudo is higher-trust than read-only
	// network probes, so this is a separate feature from FeatureNetworkScan.
	FeatureFleetScan Feature = "fleet-scan"

	// FeatureDeviceScan is the canonical name for the SSH/NETCONF network-
	// device scanner (formerly `triton network-scan`). Aliased to
	// FeatureNetworkScan for backcompat — both string values map to the
	// same tier enforcement.
	FeatureDeviceScan Feature = FeatureNetworkScan

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
		FeatureFleetScan:            true,
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
		FeatureNetworkScan:          true,
		FeatureFleetScan:            true,
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
var freeModules = []string{"certificates", "keys", "packages", "ldif"}

// AllowedModules returns the module list for the tier.
// Returns nil for the enterprise tier (all modules allowed).
// Pro tier returns a whitelist that excludes enterprise-only modules.
func AllowedModules(t Tier) []string {
	switch t {
	case TierFree:
		out := make([]string, len(freeModules))
		copy(out, freeModules)
		return out
	case TierPro:
		return proModules()
	case TierEnterprise:
		return nil
	}
	return freeModules
}

// proModules is maintained explicitly rather than via exclusion to keep
// the list greppable. Add new modules here when they land.
func proModules() []string {
	return []string{
		"certificates", "keys", "packages", "libraries", "binaries",
		"kernel", "scripts", "webapp", "configs", "processes",
		"network", "protocol", "containers", "certstore", "database",
		"hsm", "ldap", "codesign", "deps", "web_server", "vpn",
		"container_signatures", "password_hash", "auth_material",
		"deps_ecosystems", "service_mesh", "xml_dsig", "mail_server",
		"oci_image",
		"oidc_probe",
		"dnssec",
		"vpn_runtime",
		"netinfra",
		"firmware",
		"messaging",
		"db_atrest",
		"supply_chain",
		"enrollment",
		"fido2",
		"blockchain",
		"helm_chart",
		"asn1_oid",
		"java_bytecode",
		"dotnet_il",
		"ebpf_trace",
		"tpm",
		"uefi",
		"tls_observer",
		"ftps",
		"ssh_cert",
		"ldif",
		"python_ast",
		// k8s_live, secrets_mgr, kerberos_runtime are enterprise-only — do NOT add.
	}
}
