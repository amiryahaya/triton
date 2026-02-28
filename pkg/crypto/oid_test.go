package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

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
	certDER := generateSelfSignedCertDER(t, "RSA", 2048)
	oid := ExtractSignatureOID(certDER)
	require.NotEmpty(t, oid, "should extract signature OID from RSA cert")
	// SHA256-RSA: 1.2.840.113549.1.1.11
	assert.Equal(t, "1.2.840.113549.1.1.11", oid)
}

func TestExtractSignatureOID_ECDSA(t *testing.T) {
	certDER := generateSelfSignedCertDER(t, "ECDSA", 256)
	oid := ExtractSignatureOID(certDER)
	require.NotEmpty(t, oid, "should extract signature OID from ECDSA cert")
	// ECDSA with SHA256: 1.2.840.10045.4.3.2
	assert.True(t, strings.HasPrefix(oid, "1.2.840.10045"), "should be ECDSA OID, got: %s", oid)
}

func TestExtractSignatureOID_Ed25519(t *testing.T) {
	certDER := generateSelfSignedCertDER(t, "Ed25519", 0)
	oid := ExtractSignatureOID(certDER)
	require.NotEmpty(t, oid, "should extract signature OID from Ed25519 cert")
	assert.Equal(t, "1.3.101.112", oid)
}

func TestExtractPublicKeyOID_RSA(t *testing.T) {
	certDER := generateSelfSignedCertDER(t, "RSA", 2048)
	oid := ExtractPublicKeyOID(certDER)
	require.NotEmpty(t, oid, "should extract public key OID from RSA cert")
	// RSA: 1.2.840.113549.1.1.1
	assert.Equal(t, "1.2.840.113549.1.1.1", oid)
}

func TestExtractPublicKeyOID_ECDSA(t *testing.T) {
	certDER := generateSelfSignedCertDER(t, "ECDSA", 256)
	oid := ExtractPublicKeyOID(certDER)
	require.NotEmpty(t, oid, "should extract public key OID from ECDSA cert")
	// EC: 1.2.840.10045.2.1
	assert.Equal(t, "1.2.840.10045.2.1", oid)
}

func TestExtractPublicKeyOID_Ed25519(t *testing.T) {
	certDER := generateSelfSignedCertDER(t, "Ed25519", 0)
	oid := ExtractPublicKeyOID(certDER)
	require.NotEmpty(t, oid, "should extract public key OID from Ed25519 cert")
	assert.Equal(t, "1.3.101.112", oid)
}

func TestExtractSignatureOID_SyntheticPQC(t *testing.T) {
	// Build a synthetic DER with ML-DSA-44 signature OID
	mldsaOID := "2.16.840.1.101.3.4.3.17"
	rsaPubKeyOID := "1.2.840.113549.1.1.1"
	certDER := buildSyntheticCertDER(t, mldsaOID, rsaPubKeyOID)

	oid := ExtractSignatureOID(certDER)
	assert.Equal(t, mldsaOID, oid)
}

func TestExtractSignatureOID_SyntheticComposite(t *testing.T) {
	compositeOID := "2.16.840.1.114027.80.8.1.1" // ML-DSA-44-RSA-2048
	rsaPubKeyOID := "1.2.840.113549.1.1.1"
	certDER := buildSyntheticCertDER(t, compositeOID, rsaPubKeyOID)

	oid := ExtractSignatureOID(certDER)
	assert.Equal(t, compositeOID, oid)
	assert.True(t, IsCompositeOID(oid))
}

func TestExtractPublicKeyOID_SyntheticMLKEM(t *testing.T) {
	mlkemOID := "2.16.840.1.101.3.4.4.2" // ML-KEM-768
	rsaSigOID := "1.2.840.113549.1.1.11"
	certDER := buildSyntheticCertDER(t, rsaSigOID, mlkemOID)

	oid := ExtractPublicKeyOID(certDER)
	assert.Equal(t, mlkemOID, oid)

	entry, ok := LookupOID(oid)
	require.True(t, ok)
	assert.Equal(t, "ML-KEM-768", entry.Algorithm)
}

func TestExtractSignatureOID_Empty(t *testing.T) {
	assert.Equal(t, "", ExtractSignatureOID(nil))
	assert.Equal(t, "", ExtractSignatureOID([]byte{}))
}

func TestExtractSignatureOID_Truncated(t *testing.T) {
	// Just a SEQUENCE tag with no content
	assert.Equal(t, "", ExtractSignatureOID([]byte{0x30, 0x00}))
	// Outer SEQUENCE but inner TBS is truncated
	assert.Equal(t, "", ExtractSignatureOID([]byte{0x30, 0x02, 0x30, 0x00}))
}

func TestExtractPublicKeyOID_Empty(t *testing.T) {
	assert.Equal(t, "", ExtractPublicKeyOID(nil))
	assert.Equal(t, "", ExtractPublicKeyOID([]byte{}))
}

func TestExtractPublicKeyOID_Truncated(t *testing.T) {
	assert.Equal(t, "", ExtractPublicKeyOID([]byte{0x30, 0x00}))
}

// --- Test helpers ---

// generateSelfSignedCertDER creates a real self-signed certificate and returns raw DER bytes.
func generateSelfSignedCertDER(t *testing.T, keyType string, keySize int) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oid-test-" + keyType},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	var privKey interface{}
	var pubKey interface{}

	switch keyType {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		require.NoError(t, err)
		privKey = key
		pubKey = &key.PublicKey
	case "ECDSA":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privKey = key
		pubKey = &key.PublicKey
	case "Ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		privKey = priv
		pubKey = pub
	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)
	return certDER
}

// encodeOIDBytes encodes a dotted OID string (e.g. "2.16.840.1.101.3.4.3.17") into raw OID value bytes.
func encodeOIDBytes(t *testing.T, dotted string) []byte {
	t.Helper()
	parts := strings.Split(dotted, ".")
	require.True(t, len(parts) >= 2, "OID must have at least 2 components")

	first, err := strconv.Atoi(parts[0])
	require.NoError(t, err)
	second, err := strconv.Atoi(parts[1])
	require.NoError(t, err)

	var encoded []byte
	encoded = append(encoded, byte(first*40+second))

	for i := 2; i < len(parts); i++ {
		val, err := strconv.Atoi(parts[i])
		require.NoError(t, err)
		encoded = append(encoded, encodeBase128(val)...)
	}
	return encoded
}

// encodeBase128 encodes an integer in ASN.1 base-128 format.
func encodeBase128(val int) []byte {
	if val < 128 {
		return []byte{byte(val)}
	}
	var result []byte
	for val > 0 {
		result = append([]byte{byte(val & 0x7F)}, result...)
		val >>= 7
	}
	for i := 0; i < len(result)-1; i++ {
		result[i] |= 0x80
	}
	return result
}

// wrapASN1 wraps content with an ASN.1 tag and length.
func wrapASN1(tag byte, content []byte) []byte {
	length := len(content)
	if length < 128 {
		return append([]byte{tag, byte(length)}, content...)
	}
	// Long form length
	lenBytes := encodeLengthBytes(length)
	header := []byte{tag, byte(0x80 | len(lenBytes))}
	header = append(header, lenBytes...)
	return append(header, content...)
}

func encodeLengthBytes(length int) []byte {
	if length <= 0xFF {
		return []byte{byte(length)}
	}
	if length <= 0xFFFF {
		return []byte{byte(length >> 8), byte(length)}
	}
	return []byte{byte(length >> 16), byte(length >> 8), byte(length)}
}

// buildSyntheticCertDER builds a minimal synthetic X.509 DER structure with specified
// signature and public key OIDs. The structure matches what ExtractSignatureOID and
// ExtractPublicKeyOID expect to parse.
func buildSyntheticCertDER(t *testing.T, sigOID, pubKeyOID string) []byte {
	t.Helper()

	// Build the AlgorithmIdentifier for signature: SEQUENCE { OID, NULL }
	sigOIDBytes := encodeOIDBytes(t, sigOID)
	sigOIDTLV := wrapASN1(0x06, sigOIDBytes)
	nullParam := []byte{0x05, 0x00}
	sigAlgID := wrapASN1(0x30, append(sigOIDTLV, nullParam...))

	// Build the AlgorithmIdentifier for public key
	pubKeyOIDBytes := encodeOIDBytes(t, pubKeyOID)
	pubKeyOIDTLV := wrapASN1(0x06, pubKeyOIDBytes)
	pubKeyAlgID := wrapASN1(0x30, append(pubKeyOIDTLV, nullParam...))

	// Version [0] EXPLICIT INTEGER 2 (v3)
	versionInt := []byte{0x02, 0x01, 0x02}
	version := wrapASN1(0xA0, versionInt)

	// Serial number: INTEGER 1
	serial := []byte{0x02, 0x01, 0x01}

	// Issuer: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String("test") } } }
	cnOID := []byte{0x06, 0x03, 0x55, 0x04, 0x03} // 2.5.4.3
	cnValue := wrapASN1(0x0C, []byte("test"))     // UTF8String
	rdnSeq := wrapASN1(0x30, append(cnOID, cnValue...))
	rdnSet := wrapASN1(0x31, rdnSeq)
	issuer := wrapASN1(0x30, rdnSet)

	// Validity: SEQUENCE { UTCTime, UTCTime }
	utcNow := []byte{0x17, 0x0D}
	utcNow = append(utcNow, []byte("250101000000Z")...)
	utcLater := []byte{0x17, 0x0D}
	utcLater = append(utcLater, []byte("260101000000Z")...)
	validity := wrapASN1(0x30, append(utcNow, utcLater...))

	// Subject (same as issuer)
	subject := wrapASN1(0x30, rdnSet)

	// SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
	fakePubKey := wrapASN1(0x03, append([]byte{0x00}, make([]byte, 32)...)) // BIT STRING
	spki := wrapASN1(0x30, append(pubKeyAlgID, fakePubKey...))

	// TBSCertificate: SEQUENCE { version, serial, sigAlgID, issuer, validity, subject, spki }
	var tbsContent []byte
	tbsContent = append(tbsContent, version...)
	tbsContent = append(tbsContent, serial...)
	tbsContent = append(tbsContent, sigAlgID...)
	tbsContent = append(tbsContent, issuer...)
	tbsContent = append(tbsContent, validity...)
	tbsContent = append(tbsContent, subject...)
	tbsContent = append(tbsContent, spki...)
	tbs := wrapASN1(0x30, tbsContent)

	// Outer certificate: SEQUENCE { TBS, sigAlgID, BIT STRING(signature) }
	outerSigAlgID := wrapASN1(0x30, append(sigOIDTLV, nullParam...))
	fakeSig := wrapASN1(0x03, append([]byte{0x00}, make([]byte, 64)...))

	var certContent []byte
	certContent = append(certContent, tbs...)
	certContent = append(certContent, outerSigAlgID...)
	certContent = append(certContent, fakeSig...)

	return wrapASN1(0x30, certContent)
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

func TestOIDForAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm string
		wantOID   string
	}{
		{"ML-KEM-512", "2.16.840.1.101.3.4.4.1"},
		{"ML-KEM-768", "2.16.840.1.101.3.4.4.2"},
		{"ML-KEM-1024", "2.16.840.1.101.3.4.4.3"},
		{"ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
		{"ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
		{"ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
		{"Ed25519", "1.3.101.112"},
		{"Ed448", "1.3.101.113"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			oid := OIDForAlgorithm(tt.algorithm)
			assert.Equal(t, tt.wantOID, oid, "OID for %s", tt.algorithm)
		})
	}
}

func TestOIDForAlgorithm_Unknown(t *testing.T) {
	oid := OIDForAlgorithm("SOME-UNKNOWN-ALGO")
	assert.Equal(t, "", oid)
}

func TestLookupOID_FNDSA(t *testing.T) {
	tests := []struct {
		oid  string
		algo string
	}{
		{"2.16.840.1.101.3.4.3.32", "FN-DSA-512"},
		{"2.16.840.1.101.3.4.3.33", "FN-DSA-1024"},
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

func TestOIDForAlgorithm_FNDSA(t *testing.T) {
	tests := []struct {
		algorithm string
		wantOID   string
	}{
		{"FN-DSA-512", "2.16.840.1.101.3.4.3.32"},
		{"FN-DSA-1024", "2.16.840.1.101.3.4.3.33"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			oid := OIDForAlgorithm(tt.algorithm)
			assert.Equal(t, tt.wantOID, oid, "OID for %s", tt.algorithm)
		})
	}
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
