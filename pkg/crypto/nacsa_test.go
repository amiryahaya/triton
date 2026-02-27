package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessNACSA_SafeCNSA2(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "AES-256-GCM",
		PQCStatus: "SAFE",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSAPatuh, result.Label)
	assert.Contains(t, result.Description, "CNSA 2.0")
}

func TestAssessNACSA_SafePQCNotCNSA2(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "ML-KEM-512",
		PQCStatus: "SAFE",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSAPeralihan, result.Label)
}

func TestAssessNACSA_SafeCNSA2PQC(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "ML-KEM-1024",
		PQCStatus: "SAFE",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSAPatuh, result.Label)
}

func TestAssessNACSA_Transitional(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "RSA-2048",
		PQCStatus: "TRANSITIONAL",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSAPeralihan, result.Label)
	assert.Contains(t, result.Description, "2030")
}

func TestAssessNACSA_Deprecated(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "MD5",
		PQCStatus: "DEPRECATED",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSATidakPatuh, result.Label)
}

func TestAssessNACSA_Unsafe(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "DES",
		PQCStatus: "UNSAFE",
	}
	result := AssessNACSA(asset)
	assert.Equal(t, NACSATindakanSegera, result.Label)
	assert.Contains(t, result.Description, "tindakan segera")
}

func TestAssessNACSA_Nil(t *testing.T) {
	result := AssessNACSA(nil)
	assert.Equal(t, NACSATidakPatuh, result.Label)
}

func TestComputeNACSASummary(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "AES-256-GCM", PQCStatus: "SAFE"},      // Patuh (CNSA 2.0 approved)
				{Algorithm: "ML-KEM-1024", PQCStatus: "SAFE"},      // Patuh
				{Algorithm: "RSA-2048", PQCStatus: "TRANSITIONAL"}, // Dalam Peralihan
				{Algorithm: "DES", PQCStatus: "UNSAFE"},            // Tindakan Segera
			},
		},
	}

	summary := ComputeNACSASummary(systems)
	assert.Equal(t, 4, summary.TotalAssets)
	assert.Equal(t, 2, summary.Patuh)
	assert.Equal(t, 1, summary.DalamPeralihan)
	assert.Equal(t, 0, summary.TidakPatuh)
	assert.Equal(t, 1, summary.TindakanSegera)
	assert.Equal(t, 50.0, summary.ReadinessPercent)
	assert.Equal(t, 2, summary.CNSA2Compliant)
}

func TestComputeNACSASummary_Empty(t *testing.T) {
	summary := ComputeNACSASummary(nil)
	assert.Equal(t, 0, summary.TotalAssets)
	assert.Equal(t, 0.0, summary.ReadinessPercent)
}
