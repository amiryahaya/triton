package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"Not executable", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"Text file", []byte("#!/b"), false},
		{"Too short", []byte{0x7f, 'E'}, false},
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
		0x00,                                     // separator
		'R', 'S', 'A',                            // "RSA" — too short (< 4)
		0x00,                                     // separator
		'S', 'H', 'A', '-', '2', '5', '6',       // "SHA-256"
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

	// Check that known algorithms are found
	algoSet := make(map[string]bool)
	for _, a := range algos {
		algoSet[a] = true
	}

	assert.True(t, algoSet["AES-256-GCM"], "should detect AES-256-GCM")
	assert.True(t, algoSet["RSA-2048"], "should detect RSA-2048")
	assert.True(t, algoSet["Ed25519"], "should detect Ed25519")
	assert.True(t, algoSet["MD5"], "should detect MD5")
}

func TestBinaryScanWithFakeELF(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake ELF binary with embedded crypto strings
	var data []byte
	data = append(data, 0x7f, 'E', 'L', 'F') // ELF magic
	data = append(data, make([]byte, 100)...)  // padding
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

	// Check finding shape
	for _, f := range collected {
		assert.Equal(t, 2, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "binaries", f.Module)
		assert.Equal(t, 0.60, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
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

func TestBinaryScanSkipsNonBinaries(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a text file with crypto strings — should be skipped
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("AES-256 RSA-2048"), 0644)

	// Write a script with shebang — should be skipped
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

	// ELF binary with no crypto strings
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

	// Binary with repeated crypto strings
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

	// Should only have 1 finding for AES-256-GCM (deduplicated)
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
