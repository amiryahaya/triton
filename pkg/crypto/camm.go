package crypto

import (
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// CAMM (Cryptographic Agility Maturity Model) levels 0-4.
const (
	CAMMLevel0 = 0 // No crypto-agility capability
	CAMMLevel1 = 1 // Basic: crypto inventory exists
	CAMMLevel2 = 2 // Managed: algorithm diversity + extensibility
	CAMMLevel3 = 3 // Advanced: automated rotation (manual assessment)
	CAMMLevel4 = 4 // Optimized: full PQC readiness (manual assessment)
)

// CAMMResult holds the assessed CAMM maturity level.
type CAMMResult struct {
	Level      int      // 0-4 (auto-assessed up to Level 2)
	Confidence string   // "Auto-assessed" or "Partial"
	Indicators []string // Which CAMM requirements were detected
	Manual     []string // Which CAMM requirements need manual assessment
}

// CAMMIndicator describes a testable CAMM requirement.
type CAMMIndicator struct {
	ID          string // e.g. "1.2", "2.1"
	Name        string
	AutoAssess  bool
	Description string
}

// cammIndicators defines the CAMM requirements Triton can auto-assess.
var cammIndicators = []CAMMIndicator{
	{ID: "1.2", Name: "Extensibility", AutoAssess: true, Description: "System supports algorithm extensibility (TLS 1.3, PQC-capable libraries)"},
	{ID: "1.4", Name: "Crypto Inventory", AutoAssess: true, Description: "Cryptographic asset inventory maintained (Triton provides this)"},
	{ID: "2.1", Name: "Algorithm IDs", AutoAssess: true, Description: "Multiple algorithms configured per subsystem"},
	{ID: "2.2", Name: "Algorithm Intersection", AutoAssess: true, Description: "Algorithm diversity across subsystems"},
	{ID: "2.3", Name: "Algorithm Exclusion", AutoAssess: true, Description: "Disabled algorithms configured (sshd_config, crypto-policies)"},
	{ID: "2.4", Name: "Opportunistic Security", AutoAssess: true, Description: "Strongest cipher ordered first"},
	{ID: "3.1", Name: "Automated Rotation", AutoAssess: false, Description: "Automated key/certificate rotation capability"},
	{ID: "3.2", Name: "Testing Framework", AutoAssess: false, Description: "Cryptographic algorithm testing framework"},
	{ID: "4.1", Name: "Full PQC Migration", AutoAssess: false, Description: "Complete PQC migration plan and execution"},
	{ID: "4.2", Name: "Continuous Monitoring", AutoAssess: false, Description: "Continuous cryptographic compliance monitoring"},
}

// AssessCAMM evaluates the CAMM maturity level from scan results.
// Auto-assesses up to Level 2. Levels 3-4 require manual assessment.
func AssessCAMM(systems []model.System, findings []model.Finding) CAMMResult {
	result := CAMMResult{
		Confidence: "Auto-assessed",
	}

	if len(systems) == 0 && len(findings) == 0 {
		result.Level = CAMMLevel0
		result.Manual = manualIndicators()
		return result
	}

	// Collect all crypto assets
	var allAssets []model.CryptoAsset
	for i := range systems {
		allAssets = append(allAssets, systems[i].CryptoAssets...)
	}

	// Check Level 1 indicators
	level1Met := checkLevel1(allAssets, findings, &result)

	// Check Level 2 indicators
	level2Met := false
	if level1Met {
		level2Met = checkLevel2(allAssets, findings, &result)
	}

	// Determine level
	switch {
	case level2Met:
		result.Level = CAMMLevel2
	case level1Met:
		result.Level = CAMMLevel1
	default:
		result.Level = CAMMLevel0
	}

	// Add manual assessment requirements for Level 3+4
	result.Manual = manualIndicators()

	return result
}

// checkLevel1 checks CAMM Level 1 requirements (basic crypto-agility).
func checkLevel1(assets []model.CryptoAsset, _ []model.Finding, result *CAMMResult) bool {
	indicators := 0

	// 1.2 Extensibility: TLS 1.3 present or PQC-capable library detected
	hasTLS13 := false
	hasPQCLib := false
	for i := range assets {
		alg := strings.ToUpper(assets[i].Algorithm)
		if strings.Contains(alg, "TLS 1.3") || strings.Contains(alg, "TLS1.3") {
			hasTLS13 = true
		}
		for _, lib := range assets[i].CryptoLibraries {
			libLower := strings.ToLower(lib)
			if strings.Contains(libLower, "openssl 3") || strings.Contains(libLower, "boringssl") ||
				strings.Contains(libLower, "liboqs") {
				hasPQCLib = true
			}
		}
	}
	if hasTLS13 || hasPQCLib {
		result.Indicators = append(result.Indicators, "1.2 Extensibility: TLS 1.3 or PQC library detected")
		indicators++
	}

	// 1.4 Crypto Inventory: Triton itself provides this — always true when we have findings
	if len(assets) > 0 {
		result.Indicators = append(result.Indicators, "1.4 Crypto Inventory: Maintained by Triton scan")
		indicators++
	}

	return indicators >= 1
}

// checkLevel2 checks CAMM Level 2 requirements (managed crypto-agility).
func checkLevel2(assets []model.CryptoAsset, findings []model.Finding, result *CAMMResult) bool {
	indicators := 0

	// 2.1 Algorithm IDs: Multiple algorithms configured
	uniqueAlgos := make(map[string]bool)
	for i := range assets {
		uniqueAlgos[assets[i].Algorithm] = true
	}
	if len(uniqueAlgos) >= 3 {
		result.Indicators = append(result.Indicators, "2.1 Algorithm IDs: Multiple algorithms configured")
		indicators++
	}

	// 2.2 Algorithm Intersection: Algorithm diversity across families
	families := make(map[string]bool)
	for i := range assets {
		info := ClassifyAlgorithm(assets[i].Algorithm, assets[i].KeySize)
		families[info.Family] = true
	}
	if len(families) >= 3 {
		result.Indicators = append(result.Indicators, "2.2 Algorithm Intersection: Diversity across algorithm families")
		indicators++
	}

	// 2.3 Algorithm Exclusion: Config scanner shows disabled algorithms
	hasExclusion := false
	for i := range findings {
		if findings[i].Module == "configs" && findings[i].CryptoAsset != nil {
			fn := strings.ToLower(findings[i].CryptoAsset.Function)
			if strings.Contains(fn, "disabled") || strings.Contains(fn, "legacy") ||
				strings.Contains(fn, "crypto policy") {
				hasExclusion = true
				break
			}
		}
	}
	if hasExclusion {
		result.Indicators = append(result.Indicators, "2.3 Algorithm Exclusion: Disabled/legacy algorithms configured")
		indicators++
	}

	// 2.4 Opportunistic Security: Check if any PQC-safe algorithms are present
	hasPQCSafe := false
	for i := range assets {
		info := ClassifyAlgorithm(assets[i].Algorithm, assets[i].KeySize)
		if isPQCFamily(info.Family) {
			hasPQCSafe = true
			break
		}
	}
	if hasPQCSafe {
		result.Indicators = append(result.Indicators, "2.4 Opportunistic Security: PQC-safe algorithms present")
		indicators++
	}

	return indicators >= 2
}

// manualIndicators returns the list of CAMM requirements that need manual assessment.
func manualIndicators() []string {
	var manual []string
	for _, ind := range cammIndicators {
		if !ind.AutoAssess {
			manual = append(manual, ind.ID+" "+ind.Name+": "+ind.Description)
		}
	}
	return manual
}

// CAMMLevelLabel returns a human-readable label for a CAMM level.
func CAMMLevelLabel(level int) string {
	switch level {
	case CAMMLevel0:
		return "Level 0 - No Crypto-Agility"
	case CAMMLevel1:
		return "Level 1 - Basic"
	case CAMMLevel2:
		return "Level 2 - Managed"
	case CAMMLevel3:
		return "Level 3 - Advanced"
	case CAMMLevel4:
		return "Level 4 - Optimized"
	default:
		return "Unknown"
	}
}
