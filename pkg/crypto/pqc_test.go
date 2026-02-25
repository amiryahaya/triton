package crypto

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestClassifyKnownAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm string
		keySize   int
		expected  PQCStatus
	}{
		{"RSA-2048", 2048, TRANSITIONAL},
		{"AES-256-GCM", 256, SAFE},
		{"DES", 56, UNSAFE},
		{"SHA-1", 160, DEPRECATED},
		{"RSA-4096", 4096, SAFE},
		{"ECDSA-P256", 256, TRANSITIONAL},
		{"Ed25519", 256, TRANSITIONAL},
		{"RC4", 0, UNSAFE},
		{"ML-KEM", 0, SAFE},
		{"3DES", 168, DEPRECATED},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.algorithm, tt.keySize)
			assert.Equal(t, tt.expected, info.Status, "algorithm %s should be %s", tt.algorithm, tt.expected)
		})
	}
}

func TestClassifyUnknownAlgorithm(t *testing.T) {
	info := ClassifyAlgorithm("SOME-FUTURE-ALGO", 0)
	assert.Equal(t, TRANSITIONAL, info.Status)
}

func TestClassifyNormalizedMatch(t *testing.T) {
	// Verify that variant formatting still matches
	tests := []struct {
		input    string
		expected PQCStatus
	}{
		{"aes_256_gcm", SAFE}, // underscores + lowercase
		{"AES256GCM", SAFE},   // no separators
		{"rsa_2048", TRANSITIONAL},
		{"sha256", TRANSITIONAL},
		{"ecdsa_p256", TRANSITIONAL},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.input, 0)
			assert.Equal(t, tt.expected, info.Status, "normalized match for %s", tt.input)
		})
	}
}

func TestClassifyDeterministic(t *testing.T) {
	// Run the same classification many times to verify deterministic results
	// (previously map iteration order could cause different matches)
	for i := 0; i < 50; i++ {
		info := ClassifyAlgorithm("RSA-2048", 2048)
		assert.Equal(t, TRANSITIONAL, info.Status)
		assert.Equal(t, "RSA-2048", info.Name)

		info2 := ClassifyAlgorithm("AES-256-GCM", 256)
		assert.Equal(t, SAFE, info2.Status)
	}
}

func TestClassifyLongestMatchWins(t *testing.T) {
	// "AES-256-GCM" should match AES-256-GCM (SAFE), not AES-128-GCM
	info := ClassifyAlgorithm("AES-256-GCM", 256)
	assert.Equal(t, SAFE, info.Status)
	assert.Equal(t, "AES-256-GCM", info.Name)
}

func TestGetMigrationPriority(t *testing.T) {
	tests := []struct {
		status   PQCStatus
		expected int
	}{
		{UNSAFE, 100},
		{DEPRECATED, 75},
		{TRANSITIONAL, 50},
		{SAFE, 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			info := AlgorithmInfo{Status: tt.status}
			assert.Equal(t, tt.expected, GetMigrationPriority(info))
		})
	}
}

func TestClassifyCryptoAsset(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm: "RSA-2048",
		KeySize:   2048,
	}

	ClassifyCryptoAsset(asset)

	assert.Equal(t, "TRANSITIONAL", asset.PQCStatus)
	assert.Equal(t, 50, asset.MigrationPriority)
	assert.Equal(t, 2035, asset.BreakYear)
}
