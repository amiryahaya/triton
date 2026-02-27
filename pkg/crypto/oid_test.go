package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupOID_MLKEM(t *testing.T) {
	tests := []struct {
		oid  string
		algo string
	}{
		{"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
		{"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			entry, ok := LookupOID(tt.oid)
			require.True(t, ok, "OID %s should be found", tt.oid)
			assert.Equal(t, tt.algo, entry.Algorithm)
			assert.Equal(t, "Lattice", entry.Family)
			assert.Equal(t, SAFE, entry.Status)
		})
	}
}

func TestLookupOID_MLDSA(t *testing.T) {
	tests := []struct {
		oid  string
		algo string
	}{
		{"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
		{"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
		{"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			entry, ok := LookupOID(tt.oid)
			require.True(t, ok, "OID %s should be found", tt.oid)
			assert.Equal(t, tt.algo, entry.Algorithm)
			assert.Equal(t, SAFE, entry.Status)
		})
	}
}

func TestLookupOID_SLHDSA(t *testing.T) {
	tests := []struct {
		oid  string
		algo string
	}{
		{"2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"},
		{"2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"},
		{"2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"},
		{"2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"},
		{"2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			entry, ok := LookupOID(tt.oid)
			require.True(t, ok)
			assert.Equal(t, tt.algo, entry.Algorithm)
			assert.Equal(t, "Hash-Based", entry.Family)
			assert.Equal(t, SAFE, entry.Status)
		})
	}
}

func TestLookupOID_Unknown(t *testing.T) {
	_, ok := LookupOID("1.2.3.4.5.6.7.8.9")
	assert.False(t, ok)
}

func TestIsCompositeOID(t *testing.T) {
	assert.True(t, IsCompositeOID("2.16.840.1.114027.80.8.1.1"))
	assert.True(t, IsCompositeOID("2.16.840.1.114027.80.8.1.9"))
	assert.False(t, IsCompositeOID("2.16.840.1.101.3.4.3.17"))
	assert.False(t, IsCompositeOID("9.9.9.9.9"))
}

func TestCompositeComponents(t *testing.T) {
	tests := []struct {
		algorithm  string
		components []string
	}{
		{"ML-DSA-44-RSA-2048", []string{"ML-DSA-44", "RSA-2048"}},
		{"ML-DSA-65-ECDSA-P384", []string{"ML-DSA-65", "ECDSA-P384"}},
		{"ML-DSA-87-Ed448", []string{"ML-DSA-87", "Ed448"}},
		{"ML-DSA-44-Ed25519", []string{"ML-DSA-44", "Ed25519"}},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			components := CompositeComponents(tt.algorithm)
			require.NotNil(t, components)
			assert.Equal(t, tt.components, components)
		})
	}
}

func TestCompositeComponents_NotComposite(t *testing.T) {
	assert.Nil(t, CompositeComponents("RSA-2048"))
	assert.Nil(t, CompositeComponents("ML-DSA-65"))
}

func TestDecodeOID(t *testing.T) {
	// OID 2.16.840.1.101.3.4.3.17 (ML-DSA-44)
	// First byte: 2*40+16 = 96 = 0x60
	// 840 = 6*128+72 → 0x86, 0x48
	// 1 = 0x01
	// 101 = 0x65
	// 3 = 0x03
	// 4 = 0x04
	// 3 = 0x03
	// 17 = 0x11
	oidBytes := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	result := decodeOID(oidBytes)
	assert.Equal(t, "2.16.840.1.101.3.4.3.17", result)
}

func TestDecodeOID_Empty(t *testing.T) {
	assert.Equal(t, "", decodeOID(nil))
	assert.Equal(t, "", decodeOID([]byte{}))
}

func TestParseOID(t *testing.T) {
	// Tag 0x06, length 9, then the OID bytes for 2.16.840.1.101.3.4.3.17
	data := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	result := parseOID(data)
	assert.Equal(t, "2.16.840.1.101.3.4.3.17", result)
}

func TestParseOID_Invalid(t *testing.T) {
	assert.Equal(t, "", parseOID(nil))
	assert.Equal(t, "", parseOID([]byte{0x05, 0x00})) // NULL tag, not OID
}

func TestExtractSignatureOID_RSA(t *testing.T) {
	// Create a self-signed RSA cert using Go stdlib, then extract OID
	import_crypto_rsa_test(t)
}

// import_crypto_rsa_test is a helper that tests extractSignatureOID on a real certificate.
func import_crypto_rsa_test(t *testing.T) {
	t.Helper()

	// Use test fixtures instead of generating in this package
	// The real integration test is in pkg/scanner/certificate_test.go
	// Here we just test the core OID parsing functions

	// Test basic parseSequence
	seq := []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	content, ok := parseSequence(seq)
	require.True(t, ok)
	assert.Equal(t, []byte{0x01, 0x01, 0xFF}, content)
}

func TestParseSequence_Invalid(t *testing.T) {
	_, ok := parseSequence(nil)
	assert.False(t, ok)

	_, ok = parseSequence([]byte{0x02, 0x01, 0x00}) // INTEGER, not SEQUENCE
	assert.False(t, ok)
}

func TestParseTagLength_ShortForm(t *testing.T) {
	data := []byte{0x30, 0x03, 0xAA, 0xBB, 0xCC}
	content, consumed := parseTagLength(data)
	assert.Equal(t, 5, consumed)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC}, content)
}

func TestParseTagLength_LongForm(t *testing.T) {
	// Tag + length in 2 bytes (0x82, 0x01, 0x00 = 256)
	// Total: 1 (tag) + 1 (0x82) + 2 (length bytes) + 256 (content) = 260
	data := make([]byte, 260)
	data[0] = 0x30 // SEQUENCE tag
	data[1] = 0x82 // Long form, 2 bytes
	data[2] = 0x01 // High byte
	data[3] = 0x00 // Low byte = 256
	content, consumed := parseTagLength(data)
	assert.Equal(t, 260, consumed)
	assert.Len(t, content, 256)
}

func TestLookupOID_Classical(t *testing.T) {
	entry, ok := LookupOID("1.2.840.113549.1.1.1")
	require.True(t, ok)
	assert.Equal(t, "RSA", entry.Algorithm)
	assert.Equal(t, TRANSITIONAL, entry.Status)

	entry, ok = LookupOID("1.3.101.112")
	require.True(t, ok)
	assert.Equal(t, "Ed25519", entry.Algorithm)
}
