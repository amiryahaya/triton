package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestClassifyKnownAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm string
		keySize   int
		expected  PQCStatus
	}{
		// SAFE
		{"AES-256-GCM", 256, SAFE},
		{"AES-256-CBC", 256, SAFE},
		{"AES-256-CTR", 256, SAFE},
		{"AES-256-CCM", 256, SAFE},
		{"AES-192-GCM", 192, SAFE},
		{"AES-192-CBC", 192, SAFE},
		{"ChaCha20-Poly1305", 256, SAFE},
		{"Camellia-256", 256, SAFE},
		{"Twofish", 256, SAFE},
		{"Serpent", 256, SAFE},
		{"ARIA-256", 256, SAFE},
		{"SHA-384", 384, SAFE},
		{"SHA-512", 512, SAFE},
		{"SHA3-256", 256, SAFE},
		{"SHA3-384", 384, SAFE},
		{"SHA3-512", 512, SAFE},
		{"BLAKE2b", 512, SAFE},
		{"BLAKE2s", 256, SAFE},
		{"HMAC-SHA256", 256, SAFE},
		{"HMAC-SHA512", 512, SAFE},
		{"Poly1305", 256, SAFE},
		{"Bcrypt", 0, SAFE},
		{"scrypt", 0, SAFE},
		{"Argon2", 0, SAFE},
		{"PBKDF2", 0, SAFE},
		{"HKDF", 0, SAFE},
		{"ML-KEM", 0, SAFE},
		{"ML-DSA", 0, SAFE},
		{"SLH-DSA", 0, SAFE},
		{"SPHINCS+", 0, SAFE},
		{"FALCON", 0, SAFE}, // FALCON normalizes to FN-DSA
		{"FrodoKEM", 0, SAFE},
		{"BIKE", 0, SAFE},
		{"HQC", 0, SAFE},
		{"Classic McEliece", 0, SAFE},
		{"NTRU", 0, SAFE},
		{"SABER", 0, SAFE},
		{"TLS 1.3", 0, SAFE},
		{"WireGuard", 0, SAFE},
		{"QUIC", 0, SAFE},

		// TRANSITIONAL
		{"AES-128-GCM", 128, TRANSITIONAL},
		{"AES-128-CBC", 128, TRANSITIONAL},
		{"AES-128-CTR", 128, TRANSITIONAL},
		{"AES-128-CCM", 128, TRANSITIONAL},
		{"SHA-256", 256, TRANSITIONAL},
		{"SHA-224", 224, TRANSITIONAL},
		{"SHA3-224", 224, TRANSITIONAL},
		{"HMAC-SHA1", 160, TRANSITIONAL},
		{"CMAC", 128, TRANSITIONAL},
		{"SipHash", 128, TRANSITIONAL},
		{"RSA-2048", 2048, TRANSITIONAL},
		{"RSA-3072", 3072, TRANSITIONAL},
		{"RSA-4096", 4096, TRANSITIONAL}, // Reclassified: SAFE → TRANSITIONAL per CNSA 2.0
		{"RSA-8192", 8192, TRANSITIONAL},
		{"ECDSA-P256", 256, TRANSITIONAL},
		{"ECDSA-P384", 384, TRANSITIONAL},
		{"ECDSA-P521", 521, TRANSITIONAL},
		{"Ed25519", 256, TRANSITIONAL},
		{"Ed448", 448, TRANSITIONAL},
		{"X25519", 256, TRANSITIONAL},
		{"X448", 448, TRANSITIONAL},
		{"DH", 0, TRANSITIONAL},
		{"ElGamal", 0, TRANSITIONAL},
		{"Camellia-128", 128, TRANSITIONAL},
		{"ARIA-128", 128, TRANSITIONAL},
		{"SM4", 128, TRANSITIONAL},
		{"SEED", 128, TRANSITIONAL},
		{"Salsa20", 256, TRANSITIONAL},
		{"TLS 1.2", 0, TRANSITIONAL},
		{"SSH", 0, TRANSITIONAL},
		{"DTLS", 0, TRANSITIONAL},
		{"IPsec", 0, TRANSITIONAL},
		{"SM3", 256, TRANSITIONAL},

		// DEPRECATED
		{"RSA-1024", 1024, DEPRECATED},
		{"DSA", 0, DEPRECATED},
		{"ECDSA-P192", 192, DEPRECATED},
		{"SHA-1", 160, DEPRECATED},
		{"3DES", 168, DEPRECATED},
		{"Blowfish", 128, DEPRECATED},
		{"CAST5", 128, DEPRECATED},
		{"IDEA", 128, DEPRECATED},
		{"RIPEMD-160", 160, DEPRECATED},
		{"Whirlpool", 512, DEPRECATED},
		{"Tiger", 192, DEPRECATED},
		{"HMAC-MD5", 128, DEPRECATED},
		{"TLS 1.1", 0, DEPRECATED},
		{"TLS 1.0", 0, DEPRECATED},

		// UNSAFE
		{"DES", 56, UNSAFE},
		{"RC4", 0, UNSAFE},
		{"RC2", 0, UNSAFE},
		{"MD4", 128, UNSAFE},
		{"MD5", 128, UNSAFE},
		{"NULL", 0, UNSAFE},
		{"SSL 2.0", 0, UNSAFE},
		{"SSL 3.0", 0, UNSAFE},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.algorithm, tt.keySize)
			assert.Equal(t, tt.expected, info.Status, "algorithm %s should be %s", tt.algorithm, tt.expected)
		})
	}
}

func TestClassifyRSA4096Reclassified(t *testing.T) {
	// RSA-4096 was SAFE, now TRANSITIONAL per CNSA 2.0 (all RSA is Shor-vulnerable)
	info := ClassifyAlgorithm("RSA-4096", 4096)
	assert.Equal(t, TRANSITIONAL, info.Status, "RSA-4096 should be TRANSITIONAL (Shor-vulnerable)")
	assert.Equal(t, 2045, info.BreakYear)
}

func TestClassifyUnknownAlgorithm(t *testing.T) {
	info := ClassifyAlgorithm("SOME-FUTURE-ALGO", 0)
	assert.Equal(t, TRANSITIONAL, info.Status)
}

func TestClassifyNormalizedMatch(t *testing.T) {
	tests := []struct {
		input    string
		expected PQCStatus
	}{
		{"aes_256_gcm", SAFE},        // underscores + lowercase
		{"AES256GCM", SAFE},          // no separators
		{"rsa_2048", TRANSITIONAL},   // underscores
		{"sha256", TRANSITIONAL},     // no separators
		{"ecdsa_p256", TRANSITIONAL}, // underscores
		{"blake2b", SAFE},            // lowercase
		{"HMAC_SHA512", SAFE},        // underscores
		{"tls_1.3", SAFE},            // mixed
		{"chacha20_poly1305", SAFE},  // underscores + lowercase
		{"sphincs+", SAFE},           // lowercase
		{"argon2", SAFE},             // lowercase
		{"ssl 2.0", UNSAFE},          // space
		{"hmac-md5", DEPRECATED},     // lowercase + hyphens
		{"slh_dsa", SAFE},            // underscores
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.input, 0)
			assert.Equal(t, tt.expected, info.Status, "normalized match for %s", tt.input)
		})
	}
}

func TestClassifyFamilyPrefixRules(t *testing.T) {
	tests := []struct {
		input    string
		expected PQCStatus
		name     string
	}{
		// AES-256 variants caught by prefix
		{"AES-256-WRAP", SAFE, "AES-256 wrap variant"},
		{"AES-256-XTS", SAFE, "AES-256 XTS variant"},

		// AES-128 variants caught by prefix
		{"AES-128-WRAP", TRANSITIONAL, "AES-128 wrap variant"},

		// RSA variants caught by prefix
		{"RSA-4096-OAEP", TRANSITIONAL, "RSA-4096 with OAEP"},
		{"RSA-2048-PSS", TRANSITIONAL, "RSA-2048 with PSS"},

		// ECDSA variants caught by prefix
		{"ECDSA-P384-SHA384", TRANSITIONAL, "ECDSA-P384 with SHA384"},

		// SHA variants caught by prefix
		{"SHA512-RSA", SAFE, "SHA-512 prefix variant"},

		// HMAC variants caught by prefix
		{"HMAC-SHA256-TAG128", SAFE, "HMAC-SHA256 tag variant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.input, 0)
			assert.Equal(t, tt.expected, info.Status, "%s (%s)", tt.name, tt.input)
		})
	}
}

func TestClassifyDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		info := ClassifyAlgorithm("RSA-2048", 2048)
		assert.Equal(t, TRANSITIONAL, info.Status)
		assert.Equal(t, "RSA-2048", info.Name)

		info2 := ClassifyAlgorithm("AES-256-GCM", 256)
		assert.Equal(t, SAFE, info2.Status)
	}
}

func TestClassifyLongestMatchWins(t *testing.T) {
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

func TestRegistryEntryCount(t *testing.T) {
	// Ensure we have >= 90 entries (expanded from ~30)
	assert.GreaterOrEqual(t, len(algorithmRegistry), 90, "registry should have at least 90 entries")
}

func TestNormalizedMapConsistency(t *testing.T) {
	// Every entry in algorithmRegistry should be in normalizedMap
	for name := range algorithmRegistry {
		norm := normalizeAlgo(name)
		_, ok := normalizedMap[norm]
		assert.True(t, ok, "normalizedMap should contain %s (normalized: %s)", name, norm)
	}
}

func TestClassifyCryptoAsset_Normalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAlgo string
		wantSafe string
	}{
		{"SHA256 normalized", "SHA256", "SHA-256", "TRANSITIONAL"},
		{"AES128-GCM normalized", "AES128-GCM", "AES-128-GCM", "TRANSITIONAL"},
		{"RSA4096 normalized", "RSA4096", "RSA-4096", "TRANSITIONAL"},
		{"aes_256_gcm normalized", "aes_256_gcm", "AES-256-GCM", "SAFE"},
		{"Unknown not normalized", "SOME-FUTURE-ALGO", "SOME-FUTURE-ALGO", "TRANSITIONAL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{Algorithm: tt.input}
			ClassifyCryptoAsset(asset)
			assert.Equal(t, tt.wantAlgo, asset.Algorithm, "algorithm should be normalized")
			assert.Equal(t, tt.wantSafe, asset.PQCStatus, "PQC status")
		})
	}
}

func TestClassifyNewRegistryEntries(t *testing.T) {
	tests := []struct {
		algorithm string
		keySize   int
		expected  PQCStatus
	}{
		{"MD2", 128, UNSAFE},
		{"RSA-512", 512, UNSAFE},
		{"RSA-768", 768, UNSAFE},
		{"RSA-1000", 1000, DEPRECATED},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.algorithm, tt.keySize)
			assert.Equal(t, tt.expected, info.Status, "algorithm %s should be %s", tt.algorithm, tt.expected)
			assert.Equal(t, tt.algorithm, info.Name)
		})
	}
}

func TestClassifyAlgorithm_FNDSA(t *testing.T) {
	tests := []struct {
		algorithm string
		keySize   int
		expected  PQCStatus
		wantName  string
	}{
		{"FN-DSA", 0, SAFE, "FN-DSA"},
		{"FN-DSA-512", 512, SAFE, "FN-DSA-512"},
		{"FN-DSA-1024", 1024, SAFE, "FN-DSA-1024"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.algorithm, tt.keySize)
			assert.Equal(t, tt.expected, info.Status)
			assert.Equal(t, tt.wantName, info.Name)
			assert.Equal(t, "Lattice", info.Family)
			assert.True(t, info.NISTStandard, "FN-DSA should be NIST standard")
		})
	}
}

func TestClassifyAlgorithm_FALCON_NormalizesToFNDSA(t *testing.T) {
	info := ClassifyAlgorithm("FALCON", 0)
	assert.Equal(t, SAFE, info.Status)
	assert.Equal(t, "FN-DSA", info.Name, "FALCON should normalize to FN-DSA")
	assert.Equal(t, "Lattice", info.Family)
}

func TestClassifyDESVariantFamilyRules(t *testing.T) {
	tests := []struct {
		input    string
		expected PQCStatus
		name     string
	}{
		{"DESede3-CBC", DEPRECATED, "3DES via DESEDE3 prefix"},
		{"DES-CBC", UNSAFE, "DES via DESCBC prefix"},
		{"DES-ECB", UNSAFE, "DES via DESECB prefix"},
		{"TripleDES", DEPRECATED, "3DES via TRIPLEDES prefix"},
		{"RSA-1000-OAEP", DEPRECATED, "RSA-1000 via prefix"},
		{"RSA-768-OAEP", UNSAFE, "RSA-768 via prefix"},
		{"RSA-512-OAEP", UNSAFE, "RSA-512 via prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ClassifyAlgorithm(tt.input, 0)
			assert.Equal(t, tt.expected, info.Status, "%s (%s)", tt.name, tt.input)
		})
	}
}
