package agility

import (
	"sort"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

const (
	threshLow         = 40
	threshProtocolLow = 50
	recsPerDimension  = 3
)

type rule struct {
	dim       string
	threshold int
	applies   func(findings []model.Finding) bool
	rec       Recommendation
}

var recommendationRules = []rule{
	// PQC Coverage
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasModule("java_bytecode"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Enable BouncyCastle PQC provider in Java apps (add bcprov-jdk18on + register in java.security).",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasModule("web_server"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Add hybrid PQC group to nginx/Apache (ssl_ecdh_curve X25519MLKEM768:X25519). Requires OpenSSL 3.5+.",
			Effort:    EffortMedium, Impact: 20,
		},
	},
	{
		dim: DimPQCCoverage, threshold: threshLow,
		applies: hasLibrary("openssl"),
		rec: Recommendation{
			Dimension: DimPQCCoverage,
			Action:    "Upgrade to OpenSSL 3.5+ to unlock hybrid ML-KEM groups.",
			Effort:    EffortLarge, Impact: 15,
		},
	},
	// Protocol Agility
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: hasAlgorithm("TLS 1.0", "TLS 1.1"),
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Disable TLS 1.0/1.1 at the proxy edge; enforce TLS 1.2 minimum.",
			Effort:    EffortSmall, Impact: 20,
		},
	},
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: noHybridGroups,
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Add at least one hybrid named group (X25519MLKEM768) to cipher preference list.",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimProtocolAgility, threshold: threshProtocolLow,
		applies: lowGroupDiversity,
		rec: Recommendation{
			Dimension: DimProtocolAgility,
			Action:    "Broaden named-group list to include X25519, secp256r1, secp384r1 for client compatibility.",
			Effort:    EffortSmall, Impact: 15,
		},
	},
	// Config Flexibility
	{
		dim: DimConfigFlexibility, threshold: threshLow,
		applies: moduleDominates("java_bytecode"),
		rec: Recommendation{
			Dimension: DimConfigFlexibility,
			Action:    "Move JCE provider config to java.security instead of compile-time pinning.",
			Effort:    EffortMedium, Impact: 20,
		},
	},
	{
		dim: DimConfigFlexibility, threshold: threshLow,
		applies: hasModule("binaries"),
		rec: Recommendation{
			Dimension: DimConfigFlexibility,
			Action:    "Switch compile-time-pinned crypto to runtime-configurable provider (EVP-style) where possible.",
			Effort:    EffortLarge, Impact: 25,
		},
	},
	// Operational Readiness
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: certRotationBelow50,
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Shorten cert validity to <=180d and enable cert-manager/certbot auto-renewal.",
			Effort:    EffortMedium, Impact: 30,
		},
	},
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: noAutomationTool,
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Deploy cert-manager (Kubernetes) or certbot (systemd) for automated cert rotation.",
			Effort:    EffortMedium, Impact: 25,
		},
	},
	{
		dim: DimOperationalReady, threshold: threshLow,
		applies: noHSM,
		rec: Recommendation{
			Dimension: DimOperationalReady,
			Action:    "Evaluate HSM/KMS adoption for root-of-trust key material (AWS KMS, HashiCorp Vault).",
			Effort:    EffortLarge, Impact: 10,
		},
	},
}

func generateRecommendations(s Score, findings []model.Finding) []Recommendation {
	dimScore := make(map[string]int, len(s.Dimensions))
	for _, d := range s.Dimensions {
		dimScore[d.Name] = d.Score
	}

	byDim := make(map[string][]Recommendation)
	for _, r := range recommendationRules {
		if score, ok := dimScore[r.dim]; !ok || score >= r.threshold {
			continue
		}
		if !r.applies(findings) {
			continue
		}
		byDim[r.dim] = append(byDim[r.dim], r.rec)
	}

	out := make([]Recommendation, 0, len(recommendationRules))
	// Stable dimension order: declaration order of dim constants.
	for _, dim := range []string{DimPQCCoverage, DimProtocolAgility, DimConfigFlexibility, DimOperationalReady} {
		recs := byDim[dim]
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Impact > recs[j].Impact })
		if len(recs) > recsPerDimension {
			recs = recs[:recsPerDimension]
		}
		out = append(out, recs...)
	}
	return out
}

// --- predicate helpers ---

func hasModule(module string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].Module == module {
				return true
			}
		}
		return false
	}
}

func hasLibrary(sub string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].CryptoAsset != nil && strings.Contains(strings.ToLower(fs[i].CryptoAsset.Library), sub) {
				return true
			}
		}
		return false
	}
}

func hasAlgorithm(algos ...string) func([]model.Finding) bool {
	want := make(map[string]bool, len(algos))
	for _, a := range algos {
		want[a] = true
	}
	return func(fs []model.Finding) bool {
		for i := range fs {
			if fs[i].CryptoAsset != nil && want[fs[i].CryptoAsset.Algorithm] {
				return true
			}
		}
		return false
	}
}

func noHybridGroups(fs []model.Finding) bool {
	for i := range fs {
		if fs[i].CryptoAsset != nil && fs[i].CryptoAsset.IsHybrid {
			return false
		}
	}
	return true
}

func lowGroupDiversity(fs []model.Finding) bool {
	groups := make(map[string]bool)
	for i := range fs {
		if !protocolModules[fs[i].Module] || fs[i].CryptoAsset == nil {
			continue
		}
		if isNamedGroup(fs[i].CryptoAsset.Algorithm) {
			groups[fs[i].CryptoAsset.Algorithm] = true
		}
	}
	return len(groups) <= 1
}

func moduleDominates(module string) func([]model.Finding) bool {
	return func(fs []model.Finding) bool {
		var target, total int
		for i := range fs {
			total++
			if fs[i].Module == module {
				target++
			}
		}
		return total > 0 && (target*2) > total
	}
}

// certRotationBelow50 fires when the median cert rotation cadence scores below
// 50 (i.e. median expiry > 365 days). Reuses certRotationScore from
// dim_operational.go so thresholds stay in one place.
func certRotationBelow50(fs []model.Finding) bool {
	score, fired := certRotationScore(fs, time.Now().UTC())
	return fired && score < 50
}

func noAutomationTool(fs []model.Finding) bool {
	for i := range fs {
		hay := strings.ToLower(fs[i].Source.Path + " " + fs[i].Source.Evidence)
		for _, n := range automationNeedles {
			if strings.Contains(hay, n) {
				return false
			}
		}
	}
	return true
}

func noHSM(fs []model.Finding) bool {
	for i := range fs {
		if fs[i].Module == "hsm" {
			return false
		}
	}
	return true
}
