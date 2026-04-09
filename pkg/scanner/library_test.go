package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*LibraryModule)(nil)

func TestLibraryModuleInterface(t *testing.T) {
	t.Parallel()
	m := NewLibraryModule(&scannerconfig.Config{})
	assert.Equal(t, "libraries", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsLibraryFile(t *testing.T) {
	t.Parallel()
	m := NewLibraryModule(&scannerconfig.Config{})

	// Should match crypto libraries
	assert.True(t, m.isLibraryFile("/usr/lib/libcrypto.so.1.1"))
	assert.True(t, m.isLibraryFile("/usr/lib/libssl.so.1.1"))
	assert.True(t, m.isLibraryFile("/usr/lib/libcrypto.dylib"))
	assert.True(t, m.isLibraryFile("/usr/lib/libssl.dylib"))
	assert.True(t, m.isLibraryFile("/usr/lib/libmbedcrypto.so"))
	assert.True(t, m.isLibraryFile("/usr/lib/libmbedtls.so.3"))
	assert.True(t, m.isLibraryFile("/usr/lib/libwolfssl.so"))
	assert.True(t, m.isLibraryFile("/usr/lib/libgnutls.so.30"))
	assert.True(t, m.isLibraryFile("/usr/lib/libnss3.so"))
	assert.True(t, m.isLibraryFile("/usr/lib/libgcrypt.so.20"))
	assert.True(t, m.isLibraryFile("/usr/lib/libsodium.so"))
	assert.True(t, m.isLibraryFile("/usr/lib/libnettle.so.8"))
	// DLL extension
	assert.True(t, m.isLibraryFile("/path/to/libcrypto.dll"))

	// Should NOT match non-crypto libraries
	assert.False(t, m.isLibraryFile("/usr/lib/libpthread.so"))
	assert.False(t, m.isLibraryFile("/usr/lib/libc.so.6"))
	assert.False(t, m.isLibraryFile("/usr/lib/libstdc++.so.6"))
	assert.False(t, m.isLibraryFile("/usr/lib/random.txt"))

	// Should NOT match non-library files
	assert.False(t, m.isLibraryFile("/usr/lib/libcrypto.conf"))
	assert.False(t, m.isLibraryFile("/usr/lib/libcrypto.h"))
}

func TestLibraryScanFindsLibraries(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create fake library files
	libs := []string{
		"libcrypto.so.1.1.1k",
		"libssl.so.1.1",
		"libmbedcrypto.so.3",
	}

	for _, lib := range libs {
		f := filepath.Join(tmpDir, lib)
		err := os.WriteFile(f, []byte("fake library content"), 0644)
		require.NoError(t, err)
	}

	// Also create a non-crypto library
	os.WriteFile(filepath.Join(tmpDir, "libpthread.so"), []byte("fake"), 0644)

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Len(t, collected, 3, "should find exactly 3 crypto libraries")
}

func TestLibraryFindingShape(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	libFile := filepath.Join(tmpDir, "libcrypto.so.3")
	err := os.WriteFile(libFile, []byte("fake"), 0644)
	require.NoError(t, err)

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)

	assert.Equal(t, 3, finding.Category)
	assert.Equal(t, "file", finding.Source.Type)
	assert.Equal(t, "libraries", finding.Module)
	assert.Equal(t, 0.85, finding.Confidence)

	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "Cryptographic library", finding.CryptoAsset.Function)
	assert.Equal(t, "OpenSSL", finding.CryptoAsset.Algorithm)
	assert.Contains(t, finding.CryptoAsset.Library, "OpenSSL libcrypto")
}

func TestExtractVersionFromFilename(t *testing.T) {
	t.Parallel()
	tests := []struct {
		filename string
		expected string
	}{
		{"libcrypto.so.1.1.1k", "1.1.1k"},
		{"libssl.so.3", "3"},
		{"libgnutls.so.30.33.0", "30.33.0"},
		{"libcrypto.so", ""},
		{"libcrypto.dylib", ""},
		{"libcrypto.3.dylib", "3"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractVersionFromFilename(tt.filename))
		})
	}
}

func TestLibraryVersionInFinding(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Versioned library filename
	libFile := filepath.Join(tmpDir, "libssl.so.1.1.1")
	err := os.WriteFile(libFile, []byte("fake"), 0644)
	require.NoError(t, err)

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Library, "1.1.1")
}

func TestLibraryVersionBasedClassification(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Old OpenSSL — should be DEPRECATED (version 1.0.2)
	os.WriteFile(filepath.Join(tmpDir, "libcrypto.so.1.0.2"), []byte("fake"), 0644)

	// Modern OpenSSL — should be TRANSITIONAL (version 3.0.2)
	subDir := filepath.Join(tmpDir, "modern")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "libcrypto.so.3.0.2"), []byte("fake"), 0644)

	// libsodium — should be SAFE (always)
	os.WriteFile(filepath.Join(tmpDir, "libsodium.so.23"), []byte("fake"), 0644)

	// libgnutls — should be TRANSITIONAL (version 30 > minMajor 3)
	os.WriteFile(filepath.Join(tmpDir, "libgnutls.so.30"), []byte("fake"), 0644)

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	statuses := make(map[string]string)
	for f := range findings {
		base := filepath.Base(f.Source.Path)
		statuses[base] = f.CryptoAsset.PQCStatus
	}

	assert.Equal(t, "DEPRECATED", statuses["libcrypto.so.1.0.2"],
		"OpenSSL 1.0.2 should be DEPRECATED")
	assert.Equal(t, "TRANSITIONAL", statuses["libcrypto.so.3.0.2"],
		"OpenSSL 3.0.2 should be TRANSITIONAL")
	assert.Equal(t, "SAFE", statuses["libsodium.so.23"],
		"libsodium should be SAFE")
	assert.Equal(t, "TRANSITIONAL", statuses["libgnutls.so.30"],
		"GnuTLS 30.x should be TRANSITIONAL")
}

func TestLibraryScanEmptyDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	m := NewLibraryModule(&scannerconfig.Config{})
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

func TestLibraryScanContextCancellation(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "libcrypto.so"), []byte("fake"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(ctx, target, findings)
	close(findings)
}

func TestLibraryScanSubdirectories(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create library in a subdirectory
	subDir := filepath.Join(tmpDir, "lib", "x86_64")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "libgcrypt.so.20"), []byte("fake"), 0644)

	m := NewLibraryModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Library, "libgcrypt")
}
