package agility

import (
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightPQCCoverage = 0.35

func scorePQCCoverage(findings []model.Finding) Dimension {
	var total, covered int
	for i := range findings {
		a := findings[i].CryptoAsset
		if a == nil || a.PQCStatus == "" {
			continue
		}
		total++
		if a.IsHybrid || a.PQCStatus == model.PQCStatusSafe {
			covered++
		}
	}

	d := Dimension{
		Name:   DimPQCCoverage,
		Weight: weightPQCCoverage,
	}
	if total == 0 {
		d.Score = 50
		d.Explanation = "No classified crypto assets; cannot assess PQC coverage."
		return d
	}
	d.Score = (covered * 100) / total
	d.Signals = []Signal{
		{Name: "total_assets", Value: fmt.Sprintf("%d", total), Contributes: 0},
		{Name: "pqc_safe_or_hybrid", Value: fmt.Sprintf("%d", covered), Contributes: d.Score},
	}
	d.Explanation = fmt.Sprintf("%d of %d assets are PQC-safe or hybrid.", covered, total)
	return d
}
