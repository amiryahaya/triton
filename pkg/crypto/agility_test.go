package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessCryptoAgilitySingleAlgorithm(t *testing.T) {
	assets := []model.CryptoAsset{
		{Algorithm: "RSA-2048", Function: "TLS server certificate"},
	}

	result := AssessCryptoAgility(assets)
	assert.Equal(t, AgilitySevereLimited, result.Level)
	assert.Contains(t, result.Text, "Terhad")
}

func TestAssessCryptoAgilityMultipleClassicalAlgorithms(t *testing.T) {
	assets := []model.CryptoAsset{
		{Algorithm: "RSA-2048", Function: "Key exchange"},
		{Algorithm: "ECDSA-P256", Function: "Digital signature"},
		{Algorithm: "AES-256-GCM", Function: "Symmetric encryption"},
	}

	result := AssessCryptoAgility(assets)
	assert.Equal(t, AgilityLimited, result.Level)
	assert.Contains(t, result.Text, "Terhad")
}

func TestAssessCryptoAgilityWithPQCSafe(t *testing.T) {
	assets := []model.CryptoAsset{
		{Algorithm: "ML-KEM", Function: "Key encapsulation"},
		{Algorithm: "AES-256-GCM", Function: "Symmetric encryption"},
	}

	result := AssessCryptoAgility(assets)
	assert.Equal(t, AgilitySupported, result.Level)
	assert.Contains(t, result.Text, "Ya")
}

func TestAssessCryptoAgilityMixedAlgorithms(t *testing.T) {
	// Multiple diverse algorithms including some safe → partial support
	assets := []model.CryptoAsset{
		{Algorithm: "RSA-4096", Function: "Digital signature"},
		{Algorithm: "ECDSA-P256", Function: "Key exchange"},
		{Algorithm: "AES-256-GCM", Function: "Symmetric encryption"},
		{Algorithm: "SHA-256", Function: "Hash"},
	}

	result := AssessCryptoAgility(assets)
	// Multiple diverse algorithms = at least limited agility
	assert.True(t, result.Level >= AgilityLimited)
}

func TestAssessCryptoAgilityEmpty(t *testing.T) {
	result := AssessCryptoAgility(nil)
	assert.Equal(t, AgilityUnknown, result.Level)
	assert.Contains(t, result.Text, "Tidak dapat dinilai")
}

func TestAssessCryptoAgilityUnsafeOnly(t *testing.T) {
	assets := []model.CryptoAsset{
		{Algorithm: "DES", Function: "Symmetric encryption"},
		{Algorithm: "RC4", Function: "Stream cipher"},
	}

	result := AssessCryptoAgility(assets)
	assert.Equal(t, AgilitySevereLimited, result.Level)
}

func TestAssessCryptoAgilityPerAsset(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "AES-256-GCM",
		Function:  "Symmetric encryption",
	}

	text := AssessAssetAgility(&asset)
	assert.NotEmpty(t, text)
}

func TestAssessCryptoAgilityPerAssetPQC(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "ML-KEM",
		Function:  "Key encapsulation",
	}

	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Ya")
}

func TestAssessCryptoAgilityPerAssetClassical(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "RSA-2048",
		Function:  "Key exchange",
	}

	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Terhad")
}

func TestAgilityLevelString(t *testing.T) {
	assert.Equal(t, "Ya", AgilitySupported.String())
	assert.Equal(t, "Terhad", AgilityLimited.String())
	assert.Equal(t, "Terhad", AgilitySevereLimited.String())
	assert.Equal(t, "Tidak dapat dinilai", AgilityUnknown.String())
}

func TestAssessAssetAgility_Nil(t *testing.T) {
	text := AssessAssetAgility(nil)
	assert.Equal(t, "Tidak dapat dinilai", text)
}

func TestAssessAssetAgility_SAFESymmetric(t *testing.T) {
	// AES-256 is SAFE but not PQC family (it's "AES") → "Ya (algoritma selamat kuantum untuk simetri)"
	asset := model.CryptoAsset{
		Algorithm: "AES-256-GCM",
		KeySize:   256,
	}
	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Ya")
	assert.Contains(t, text, "selamat kuantum")
}

func TestAssessAssetAgility_DEPRECATED(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "MD5",
		KeySize:   128,
	}
	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Terhad")
	assert.Contains(t, text, "usang")
}

func TestAssessAssetAgility_UNSAFE(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "DES",
		KeySize:   56,
	}
	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Terhad")
	assert.Contains(t, text, "tidak selamat")
}

func TestAssessAssetAgility_TRANSITIONAL(t *testing.T) {
	asset := model.CryptoAsset{
		Algorithm: "RSA-2048",
		KeySize:   2048,
	}
	text := AssessAssetAgility(&asset)
	assert.Contains(t, text, "Terhad")
	assert.Contains(t, text, "klasik")
}

func TestFormatKeySize(t *testing.T) {
	tests := []struct {
		keySize int
		want    string
	}{
		{4096, "4096-bit"},
		{256, "256-bit"},
		{0, "N/A"},
		{128, "128-bit"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatKeySize(tt.keySize))
		})
	}
}
