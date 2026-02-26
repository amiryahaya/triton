package crypto

import (
	"fmt"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// AgilityLevel represents crypto-agility capability.
type AgilityLevel int

const (
	AgilityUnknown       AgilityLevel = iota
	AgilitySevereLimited              // Single algorithm, no diversity
	AgilityLimited                    // Multiple classical algorithms, no PQC
	AgilitySupported                  // PQC-safe algorithms present or hybrid support
)

// String returns the Malay-language label for the agility level.
func (a AgilityLevel) String() string {
	switch a {
	case AgilitySupported:
		return "Ya"
	case AgilityLimited, AgilitySevereLimited:
		return "Terhad"
	default:
		return "Tidak dapat dinilai"
	}
}

// AgilityResult holds the assessment result for a group of crypto assets.
type AgilityResult struct {
	Level AgilityLevel
	Text  string // Malay description for report output
}

// AssessCryptoAgility evaluates the crypto-agility of a set of crypto assets.
// It considers: algorithm diversity, presence of PQC-safe algorithms, and overall status mix.
func AssessCryptoAgility(assets []model.CryptoAsset) AgilityResult {
	if len(assets) == 0 {
		return AgilityResult{
			Level: AgilityUnknown,
			Text:  "Tidak dapat dinilai (tiada aset kriptografi dikesan)",
		}
	}

	// Classify each asset
	var hasPQCSafe bool
	var hasTransitional bool
	var hasUnsafe bool
	families := make(map[string]bool)
	uniqueAlgos := make(map[string]bool)

	for _, a := range assets {
		info := ClassifyAlgorithm(a.Algorithm, a.KeySize)
		uniqueAlgos[a.Algorithm] = true
		families[info.Family] = true

		switch info.Status {
		case SAFE:
			// Check if it's a PQC-specific algorithm (lattice, hash-based, etc.)
			if isPQCFamily(info.Family) {
				hasPQCSafe = true
			}
		case TRANSITIONAL:
			hasTransitional = true
		case DEPRECATED, UNSAFE:
			hasUnsafe = true
		}
	}

	algoCount := len(uniqueAlgos)
	familyCount := len(families)

	// Decision tree
	if hasPQCSafe {
		return AgilityResult{
			Level: AgilitySupported,
			Text:  "Ya (algoritma PQC-safe dikesan; sokongan hibrid tersedia)",
		}
	}

	if hasUnsafe && !hasTransitional && algoCount <= 2 {
		return AgilityResult{
			Level: AgilitySevereLimited,
			Text:  "Terhad (algoritma usang/tidak selamat sahaja; migrasi segera diperlukan)",
		}
	}

	if algoCount == 1 {
		return AgilityResult{
			Level: AgilitySevereLimited,
			Text:  fmt.Sprintf("Terhad (satu algoritma sahaja: %s; tiada kepelbagaian)", firstKey(uniqueAlgos)),
		}
	}

	if familyCount >= 2 {
		return AgilityResult{
			Level: AgilityLimited,
			Text:  fmt.Sprintf("Terhad (algoritma klasik; tiada hibrid PQC dikesan; %d keluarga algoritma)", familyCount),
		}
	}

	return AgilityResult{
		Level: AgilityLimited,
		Text:  "Terhad (algoritma klasik sahaja; tiada hibrid PQC dikesan)",
	}
}

// AssessAssetAgility returns a Malay-language crypto-agility text for a single asset.
// Used to populate the "Sokongan Crypto-Agility" column in Jadual 2.
func AssessAssetAgility(asset *model.CryptoAsset) string {
	if asset == nil {
		return "Tidak dapat dinilai"
	}

	info := ClassifyAlgorithm(asset.Algorithm, asset.KeySize)

	if isPQCFamily(info.Family) {
		return "Ya (algoritma PQC-safe)"
	}

	switch info.Status {
	case SAFE:
		return "Ya (algoritma selamat kuantum untuk simetri)"
	case TRANSITIONAL:
		return "Terhad (algoritma klasik; perlu rancangan migrasi PQC)"
	case DEPRECATED:
		return "Terhad (algoritma usang; gantian segera diperlukan)"
	case UNSAFE:
		return "Terhad (algoritma tidak selamat; gantian kritikal)"
	default:
		return "Tidak dapat dinilai"
	}
}

// isPQCFamily checks if an algorithm family is a post-quantum cryptography family.
func isPQCFamily(family string) bool {
	switch strings.ToLower(family) {
	case "lattice", "hash-based", "code-based", "multivariate", "isogeny":
		return true
	}
	return false
}

// FormatKeySize formats a key size integer to the government report format (e.g., "4096-bit").
func FormatKeySize(keySize int) string {
	if keySize <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%d-bit", keySize)
}

func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}
