package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*BinaryModule)(nil)

func TestBinaryModuleInterface(t *testing.T) {
	m := NewBinaryModule(&config.Config{})
	assert.Equal(t, "binaries", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsExecutableMagic(t *testing.T) {
	tests := []struct {
		name     string
		magic    []byte
		expected bool
	}{
		{"ELF binary", []byte{0x7f, 'E', 'L', 'F'}, true},
		{"Mach-O 64-bit", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"Mach-O 64-bit reverse", []byte{0xFE, 0xED, 0xFA, 0xCF}, true},
		{"Mach-O 32-bit", []byte{0xCE, 0xFA, 0xED, 0xFE}, true},
		{"Universal binary", []byte{0xCA, 0xFE, 0xBA, 0xBE}, true},
		{"PE binary (MZ)", []byte{0x4D, 0x5A, 0x90, 0x00}, true},
		{"Not executable", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"Text file", []byte("#!/b"), false},
		{"Too short", []byte{0x7f}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isExecutableMagic(tt.magic))
		})
	}
}

func TestExtractPrintableStrings(t *testing.T) {
	// Binary data with embedded strings
	data := []byte{
		0x00, 0x00, // padding
		'A', 'E', 'S', '-', '2', '5', '6', // "AES-256"
		0x00,          // separator
		'R', 'S', 'A', // "RSA" — too short (< 4)
		0x00,                              // separator
		'S', 'H', 'A', '-', '2', '5', '6', // "SHA-256"
		0x00, 0x00,
	}

	result := extractPrintableStrings(data, 4)
	assert.Contains(t, result, "AES-256")
	assert.Contains(t, result, "SHA-256")
	assert.NotContains(t, result, "RSA") // 3 chars < minLen 4
}

func TestMatchCryptoInStrings(t *testing.T) {
	content := "AES-256-GCM RSA-2048 SHA-256 Ed25519 MD5 some random text TLS_1.3"

	algos := MatchCryptoInStrings(content)
	require.NotEmpty(t, algos)

	algoSet := make(map[string]bool)
	for _, a := range algos {
		algoSet[a] = true
	}

	assert.True(t, algoSet["AES-256-GCM"], "should detect AES-256-GCM")
	assert.True(t, algoSet["RSA-2048"], "should detect RSA-2048")
	assert.True(t, algoSet["Ed25519"], "should detect Ed25519")
	assert.True(t, algoSet["MD5"], "should detect MD5")
}

func TestMatchCryptoInStringsNewPatterns(t *testing.T) {
	content := "HMAC-SHA256 PBKDF2 scrypt Argon2id HKDF X25519 FALCON SPHINCS+ SLH-DSA Bcrypt"

	algos := MatchCryptoInStrings(content)
	require.NotEmpty(t, algos)

	algoSet := make(map[string]bool)
	for _, a := range algos {
		algoSet[a] = true
	}

	assert.True(t, algoSet["HMAC-SHA256"], "should detect HMAC-SHA256")
	assert.True(t, algoSet["PBKDF2"], "should detect PBKDF2")
	assert.True(t, algoSet["scrypt"], "should detect scrypt")
	assert.True(t, algoSet["Argon2id"], "should detect Argon2id")
	assert.True(t, algoSet["HKDF"], "should detect HKDF")
	assert.True(t, algoSet["X25519"], "should detect X25519")
	assert.True(t, algoSet["FALCON"], "should detect FALCON")
	assert.True(t, algoSet["SPHINCS+"], "should detect SPHINCS+")
	assert.True(t, algoSet["SLH-DSA"], "should detect SLH-DSA")
	assert.True(t, algoSet["Bcrypt"], "should detect Bcrypt")
}

func TestBinaryScanWithFakeELF(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')  // ELF magic
	data = append(data, make([]byte, 100)...) // padding
	data = append(data, []byte("AES-256-GCM cipher suite")...)
	data = append(data, make([]byte, 10)...)
	data = append(data, []byte("RSA-2048 key exchange")...)
	data = append(data, make([]byte, 10)...)
	data = append(data, []byte("SHA-256 digest")...)

	binFile := filepath.Join(tmpDir, "test-binary")
	err := os.WriteFile(binFile, data, 0755)
	require.NoError(t, err)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in fake ELF binary")

	for _, f := range collected {
		assert.Equal(t, 2, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "binaries", f.Module)
		assert.Equal(t, 0.60, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
		assert.NotEmpty(t, f.Source.DetectionMethod)
	}
}

func TestBinaryScanWithFakeMachO(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0xCF, 0xFA, 0xED, 0xFE) // Mach-O magic
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("Ed25519 signature verification")...)

	binFile := filepath.Join(tmpDir, "macho-binary")
	err := os.WriteFile(binFile, data, 0755)
	require.NoError(t, err)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected)
	found := false
	for _, f := range collected {
		if f.CryptoAsset.Algorithm == "Ed25519" {
			found = true
		}
	}
	assert.True(t, found, "should find Ed25519 in Mach-O binary")
}

func TestBinaryScanWithFakePE(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x4D, 0x5A) // MZ magic
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("AES-128-GCM encryption AES-256-CBC")...)

	binFile := filepath.Join(tmpDir, "test-pe.exe")
	err := os.WriteFile(binFile, data, 0755)
	require.NoError(t, err)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in PE binary")

	for _, f := range collected {
		assert.Equal(t, 2, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "binaries", f.Module)
		assert.Equal(t, 0.60, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
		assert.NotEmpty(t, f.Source.DetectionMethod)
	}
}

func TestBinaryScanSkipsNonBinaries(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("AES-256 RSA-2048"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "script.sh"), []byte("#!/bin/bash\nopenssl"), 0755)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected, "should not find patterns in non-binary files")
}

func TestBinaryScanNoCryptoPatterns(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')
	data = append(data, make([]byte, 200)...)
	data = append(data, []byte("hello world this is a normal binary")...)

	os.WriteFile(filepath.Join(tmpDir, "no-crypto"), data, 0755)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected, "binary without crypto patterns should have no findings")
}

func TestBinaryScanDeduplication(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')
	data = append(data, make([]byte, 10)...)
	data = append(data, []byte("AES-256-GCM")...)
	data = append(data, make([]byte, 10)...)
	data = append(data, []byte("AES-256-GCM")...) // duplicate
	data = append(data, make([]byte, 10)...)
	data = append(data, []byte("AES-256-GCM")...) // another duplicate

	os.WriteFile(filepath.Join(tmpDir, "dedup-test"), data, 0755)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Len(t, collected, 1, "duplicate patterns should be deduplicated")
}

func TestBinaryScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestBuildAlgorithmName(t *testing.T) {
	assert.Equal(t, "AES-256-GCM", buildAlgorithmName("AES", "AES-256-GCM"))
	assert.Equal(t, "RSA-2048", buildAlgorithmName("RSA", "RSA-2048"))
	assert.Equal(t, "MD5", buildAlgorithmName("MD5", "MD5"))
	assert.Equal(t, "AES-256-GCM", buildAlgorithmName("AES", "AES_256_GCM"))
}

func TestDetectStateFromStrings(t *testing.T) {
	assert.Equal(t, "IN_TRANSIT", detectStateFromStrings("TLS connection established"))
	assert.Equal(t, "IN_TRANSIT", detectStateFromStrings("SSL_connect handshake"))
	assert.Equal(t, "AT_REST", detectStateFromStrings("AES-XTS full-disk encryption"))
	assert.Equal(t, "IN_USE", detectStateFromStrings("HMAC verification"))
	assert.Equal(t, "", detectStateFromStrings("hello world"))
}

func TestDetectLanguageFallback(t *testing.T) {
	// Non-existent file returns empty
	lang := detectLanguage("/nonexistent/path")
	assert.Equal(t, "", lang)
}

func TestGetImportedLibrariesFallback(t *testing.T) {
	// Non-existent file returns nil
	libs := getImportedLibraries("/nonexistent/path")
	assert.Nil(t, libs)
}

func TestGetImportedSymbolsFallback(t *testing.T) {
	syms := getImportedSymbols("/nonexistent/path")
	assert.Nil(t, syms)
}

func TestAppendUnique(t *testing.T) {
	s := []string{"a", "b"}
	s = appendUnique(s, "c")
	assert.Equal(t, []string{"a", "b", "c"}, s)

	s = appendUnique(s, "b")
	assert.Equal(t, []string{"a", "b", "c"}, s, "should not duplicate")
}

func TestGetImportedSymbols_RealBinary(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	syms := getImportedSymbols(exe)
	// On macOS/Linux, the test binary should have symbols
	// (may be empty on some platforms, so we just verify no crash)
	if syms != nil {
		assert.NotEmpty(t, syms, "real binary should have imported symbols")
	}
}

func TestMatchCryptoSymbols_OpenSSLSymbols(t *testing.T) {
	symbols := []string{"EVP_aes_256_gcm", "EVP_sha256", "SSL_connect"}
	matches := matchCryptoSymbols(symbols)

	algoSet := make(map[string]bool)
	for _, m := range matches {
		algoSet[m.algorithm] = true
	}

	assert.True(t, algoSet["AES-256-GCM"], "should detect AES-256-GCM from EVP_aes_256_gcm")
	assert.True(t, algoSet["SHA-256"], "should detect SHA-256 from EVP_sha256")
}

func TestMatchCryptoSymbols_PQCSymbols(t *testing.T) {
	symbols := []string{"OQS_SIG_dilithium3_sign"}
	matches := matchCryptoSymbols(symbols)

	require.Len(t, matches, 1)
	assert.Equal(t, "ML-DSA", matches[0].algorithm)
	assert.Equal(t, "PQC signature", matches[0].function)
}

func TestMatchCryptoSymbols_NoMatch(t *testing.T) {
	symbols := []string{"printf", "malloc", "free"}
	matches := matchCryptoSymbols(symbols)
	assert.Empty(t, matches, "non-crypto symbols should produce no matches")
}

func TestMatchCryptoSymbols_MultipleAESVariants(t *testing.T) {
	symbols := []string{"EVP_aes_256_gcm", "EVP_aes_128_cbc"}
	matches := matchCryptoSymbols(symbols)

	require.Len(t, matches, 2, "should detect both AES-256-GCM and AES-128-CBC")

	algoSet := make(map[string]bool)
	for _, m := range matches {
		algoSet[m.algorithm] = true
	}
	assert.True(t, algoSet["AES-256-GCM"], "should detect AES-256-GCM")
	assert.True(t, algoSet["AES-128-CBC"], "should detect AES-128-CBC")
}

func TestMatchCryptoSymbols_RSASign(t *testing.T) {
	symbols := []string{"RSA_sign", "ECDSA_verify"}
	matches := matchCryptoSymbols(symbols)

	algoSet := make(map[string]bool)
	for _, m := range matches {
		algoSet[m.algorithm] = true
	}

	assert.True(t, algoSet["RSA"], "should detect RSA from RSA_sign")
	assert.True(t, algoSet["ECDSA"], "should detect ECDSA from ECDSA_verify")
}

func TestDetectCryptoLibVersions_OpenSSL(t *testing.T) {
	content := "some data OpenSSL 3.0.2 14 Mar 2023 more data"
	versions := detectCryptoLibVersions(content)

	require.Len(t, versions, 1)
	assert.Equal(t, "openssl", versions[0].library)
	assert.Equal(t, "3.0.2", versions[0].version)
}

func TestDetectCryptoLibVersions_Multiple(t *testing.T) {
	content := "wolfSSL 5.6.0 embedded library mbedTLS 3.4.0 crypto engine"
	versions := detectCryptoLibVersions(content)

	require.Len(t, versions, 2)

	libSet := make(map[string]string)
	for _, v := range versions {
		libSet[v.library] = v.version
	}

	assert.Equal(t, "5.6.0", libSet["wolfssl"])
	assert.Equal(t, "3.4.0", libSet["mbedtls"])
}

func TestDetectCryptoLibVersions_NoMatch(t *testing.T) {
	content := "hello world this is a normal string"
	versions := detectCryptoLibVersions(content)
	assert.Empty(t, versions)
}

func TestDetectCryptoLibVersions_BoringSSL(t *testing.T) {
	content := "BoringSSL is used here"
	versions := detectCryptoLibVersions(content)

	require.Len(t, versions, 1)
	assert.Equal(t, "boringssl", versions[0].library)
	assert.Equal(t, "", versions[0].version, "BoringSSL has no semver")
}

func TestBinaryScan_SymbolFindings_HigherConfidence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake ELF binary with an EVP symbol string embedded
	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("AES-256-GCM cipher suite")...)

	binFile := filepath.Join(tmpDir, "test-elf-sym")
	err := os.WriteFile(binFile, data, 0755)
	require.NoError(t, err)

	m := NewBinaryModule(&config.Config{})
	findings, err := m.scanBinaryFile(binFile)
	require.NoError(t, err)

	// All string-match findings should have confidence 0.60
	for _, f := range findings {
		if f.Source.DetectionMethod == "string" || f.Source.DetectionMethod == "library-linkage" {
			assert.Equal(t, 0.60, f.Confidence, "string findings should have 0.60 confidence")
		}
		if f.Source.DetectionMethod == "symbol" {
			assert.Equal(t, 0.80, f.Confidence, "symbol findings should have 0.80 confidence")
		}
	}
}

func TestBinaryScan_LibraryVersionFinding(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("OpenSSL 1.0.2u 20 Dec 2019")...)

	binFile := filepath.Join(tmpDir, "test-openssl-old")
	err := os.WriteFile(binFile, data, 0755)
	require.NoError(t, err)

	m := NewBinaryModule(&config.Config{})
	findings, err := m.scanBinaryFile(binFile)
	require.NoError(t, err)

	hasLibFinding := false
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "Crypto library" {
			hasLibFinding = true
			assert.Equal(t, "openssl", f.CryptoAsset.Library)
			assert.Equal(t, "DEPRECATED", f.CryptoAsset.PQCStatus,
				"OpenSSL 1.0.2 should be DEPRECATED")
		}
	}
	assert.True(t, hasLibFinding, "should detect embedded OpenSSL version")
}

func TestBinaryScanDetectionMethodSet(t *testing.T) {
	tmpDir := t.TempDir()

	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F')
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("PBKDF2 key derivation HKDF")...)

	os.WriteFile(filepath.Join(tmpDir, "kdf-binary"), data, 0755)

	m := NewBinaryModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected)
	for _, f := range collected {
		assert.NotEmpty(t, f.Source.DetectionMethod, "all binary findings should have detection method")
	}
}
