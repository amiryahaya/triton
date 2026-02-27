package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessCAMM_Empty(t *testing.T) {
	result := AssessCAMM(nil, nil)
	assert.Equal(t, CAMMLevel0, result.Level)
	assert.NotEmpty(t, result.Manual)
}

func TestAssessCAMM_Level1_CryptoInventory(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel1)
	assert.Contains(t, indicatorIDs(result.Indicators), "1.4")
}

func TestAssessCAMM_Level1_TLS13(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "TLS 1.3"},
				{Algorithm: "AES-256-GCM"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel1)
	assert.Contains(t, indicatorIDs(result.Indicators), "1.2")
}

func TestAssessCAMM_Level2_Diversity(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "ECDSA-P256"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-384"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.1")
	assert.Contains(t, indicatorIDs(result.Indicators), "2.2")
}

func TestAssessCAMM_Level2_WithExclusion(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-512"},
			},
		},
	}
	findings := []model.Finding{
		{
			Module: "configs",
			CryptoAsset: &model.CryptoAsset{
				Function:  "TLS disabled algorithms",
				Algorithm: "DES",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.3")
}

func TestAssessCAMM_Level2_WithPQC(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "ML-KEM-1024"},
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-512"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.4")
}

func TestAssessCAMM_ManualIndicators(t *testing.T) {
	result := AssessCAMM(nil, nil)
	// Should always have manual indicators for Level 3+4
	assert.NotEmpty(t, result.Manual)
	assert.GreaterOrEqual(t, len(result.Manual), 4)
}

func TestCAMMLevelLabel(t *testing.T) {
	tests := []struct {
		level int
		label string
	}{
		{0, "Level 0 - No Crypto-Agility"},
		{1, "Level 1 - Basic"},
		{2, "Level 2 - Managed"},
		{3, "Level 3 - Advanced"},
		{4, "Level 4 - Optimized"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.label, CAMMLevelLabel(tt.level))
	}
}

// indicatorIDs extracts the indicator IDs (e.g., "1.2") from indicator strings.
func indicatorIDs(indicators []string) []string {
	var ids []string
	for _, ind := range indicators {
		if len(ind) >= 3 {
			ids = append(ids, ind[:3])
		}
	}
	return ids
}
