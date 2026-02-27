package crypto

import "github.com/amiryahaya/triton/pkg/model"

// NACSALabel represents the NACSA PQC compliance classification (Malay).
type NACSALabel string

const (
	NACSAPatuh          NACSALabel = "Patuh"                 // Compliant
	NACSAPeralihan      NACSALabel = "Dalam Peralihan"       // In Transition
	NACSATidakPatuh     NACSALabel = "Tidak Patuh"           // Non-Compliant
	NACSATindakanSegera NACSALabel = "Perlu Tindakan Segera" // Immediate Action Required
)

// NACSAResult holds the NACSA compliance assessment for a crypto asset.
type NACSAResult struct {
	Label       NACSALabel
	Description string // Malay description for report
}

// AssessNACSA determines the NACSA compliance label for a crypto asset.
// Logic:
//   - SAFE + CNSA 2.0 Approved → Patuh
//   - SAFE (PQC, not CNSA 2.0) or TRANSITIONAL → Dalam Peralihan
//   - DEPRECATED → Tidak Patuh
//   - UNSAFE → Perlu Tindakan Segera
func AssessNACSA(asset *model.CryptoAsset) NACSAResult {
	if asset == nil {
		return NACSAResult{
			Label:       NACSATidakPatuh,
			Description: "Tiada maklumat aset kriptografi",
		}
	}

	ci := GetCompliance(asset.Algorithm)

	switch PQCStatus(asset.PQCStatus) {
	case SAFE:
		if ci.CNSA2Approved {
			return NACSAResult{
				Label:       NACSAPatuh,
				Description: "Algoritma selamat kuantum dan diluluskan CNSA 2.0",
			}
		}
		return NACSAResult{
			Label:       NACSAPeralihan,
			Description: "Algoritma selamat tetapi belum diluluskan CNSA 2.0",
		}

	case TRANSITIONAL:
		return NACSAResult{
			Label:       NACSAPeralihan,
			Description: "Algoritma klasik; peralihan kepada PQC diperlukan sebelum 2030",
		}

	case DEPRECATED:
		return NACSAResult{
			Label:       NACSATidakPatuh,
			Description: "Algoritma usang; perlu digantikan segera",
		}

	case UNSAFE:
		return NACSAResult{
			Label:       NACSATindakanSegera,
			Description: "Algoritma tidak selamat; tindakan segera diperlukan",
		}

	default:
		return NACSAResult{
			Label:       NACSAPeralihan,
			Description: "Status kriptografi tidak dapat ditentukan; penilaian manual diperlukan",
		}
	}
}

// NACSAComplianceSummary calculates overall NACSA readiness for a set of assets.
type NACSAComplianceSummary struct {
	TotalAssets      int
	Patuh            int     // Compliant count
	DalamPeralihan   int     // In Transition count
	TidakPatuh       int     // Non-Compliant count
	TindakanSegera   int     // Immediate Action Required count
	ReadinessPercent float64 // Overall readiness (0-100)
	CNSA2Compliant   int     // CNSA 2.0 approved count
}

// ComputeNACSASummary calculates aggregate NACSA compliance from systems.
func ComputeNACSASummary(systems []model.System) NACSAComplianceSummary {
	var summary NACSAComplianceSummary

	for i := range systems {
		for j := range systems[i].CryptoAssets {
			asset := &systems[i].CryptoAssets[j]
			summary.TotalAssets++

			result := AssessNACSA(asset)
			switch result.Label {
			case NACSAPatuh:
				summary.Patuh++
			case NACSAPeralihan:
				summary.DalamPeralihan++
			case NACSATidakPatuh:
				summary.TidakPatuh++
			case NACSATindakanSegera:
				summary.TindakanSegera++
			}

			ci := GetCompliance(asset.Algorithm)
			if ci.CNSA2Approved {
				summary.CNSA2Compliant++
			}
		}
	}

	if summary.TotalAssets > 0 {
		summary.ReadinessPercent = float64(summary.Patuh) / float64(summary.TotalAssets) * 100
	}

	return summary
}
