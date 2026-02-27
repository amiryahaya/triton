package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*KernelModule)(nil)

func TestKernelModuleInterface(t *testing.T) {
	m := NewKernelModule(&config.Config{})
	assert.Equal(t, "kernel", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestKernelModuleGracefulSkipOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("This test is for non-Linux systems")
	}

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: "/lib/modules", Depth: 5}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "should produce no findings on non-Linux")
}

func TestIsKernelModule(t *testing.T) {
	m := NewKernelModule(&config.Config{})

	assert.True(t, m.isKernelModule("/lib/modules/5.15/kernel/crypto/aes_generic.ko"))
	assert.True(t, m.isKernelModule("/lib/modules/5.15/kernel/crypto/sha256.ko.xz"))
	assert.True(t, m.isKernelModule("/lib/modules/5.15/kernel/crypto/rsa.ko.gz"))
	assert.True(t, m.isKernelModule("/lib/modules/5.15/kernel/crypto/ecb.ko.zst"))
	assert.False(t, m.isKernelModule("/lib/modules/5.15/kernel/drivers/net.ko.txt"))
	assert.False(t, m.isKernelModule("/usr/lib/libcrypto.so"))
}

func TestKernelModuleScanWithFakeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake .ko file with crypto strings
	cryptoDir := filepath.Join(tmpDir, "kernel", "crypto")
	os.MkdirAll(cryptoDir, 0755)

	// Fake kernel module with AES reference
	var aesData []byte
	aesData = append(aesData, make([]byte, 50)...)
	aesData = append(aesData, []byte("AES-256-GCM implementation for kernel")...)
	aesData = append(aesData, make([]byte, 50)...)
	aesData = append(aesData, []byte("SHA-256 hash function")...)
	os.WriteFile(filepath.Join(cryptoDir, "aes_generic.ko"), aesData, 0644)

	// Fake kernel module with RSA reference
	var rsaData []byte
	rsaData = append(rsaData, make([]byte, 50)...)
	rsaData = append(rsaData, []byte("RSA-2048 asymmetric crypto")...)
	os.WriteFile(filepath.Join(cryptoDir, "rsa_generic.ko"), rsaData, 0644)

	// Non-crypto .ko file
	var netData []byte
	netData = append(netData, make([]byte, 50)...)
	netData = append(netData, []byte("network driver module")...)
	os.WriteFile(filepath.Join(cryptoDir, "net_driver.ko"), netData, 0644)

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5}

	// Use ScanWithOverride to bypass OS check
	err := m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find crypto patterns in aes_generic.ko and rsa_generic.ko
	require.NotEmpty(t, collected, "should find crypto patterns in kernel modules")

	// Check finding shapes
	for _, f := range collected {
		assert.Equal(t, 4, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "kernel", f.Module)
		assert.Equal(t, 0.65, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.Equal(t, "Kernel crypto module", f.CryptoAsset.Function)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}

	// Verify both AES and RSA were found
	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["RSA-2048"], "should detect RSA-2048 in kernel module")
}

func TestKernelModuleScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestKernelModuleScanNoCryptoInModule(t *testing.T) {
	tmpDir := t.TempDir()

	// .ko file with no crypto strings
	var data []byte
	data = append(data, make([]byte, 50)...)
	data = append(data, []byte("just a regular kernel module with no crypto")...)
	os.WriteFile(filepath.Join(tmpDir, "regular.ko"), data, 0644)

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "kernel module without crypto should have no findings")
}

// makeFakeCryptoPayload returns raw bytes containing crypto strings for testing.
func makeFakeCryptoPayload() []byte {
	var data []byte
	data = append(data, make([]byte, 50)...)
	data = append(data, []byte("AES-256-GCM implementation for kernel crypto")...)
	data = append(data, make([]byte, 50)...)
	data = append(data, []byte("SHA-256 hash function")...)
	return data
}

func TestKernelModuleScanCompressedGz(t *testing.T) {
	tmpDir := t.TempDir()
	payload := makeFakeCryptoPayload()

	// Create gzip-compressed .ko.gz
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "aes_generic.ko.gz"), buf.Bytes(), 0644))

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	require.NotEmpty(t, collected, "should find crypto patterns in gzip-compressed kernel module")
	for _, f := range collected {
		assert.Equal(t, "kernel", f.Module)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}
}

func TestKernelModuleScanCompressedXz(t *testing.T) {
	tmpDir := t.TempDir()
	payload := makeFakeCryptoPayload()

	// Create xz-compressed .ko.xz
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	require.NoError(t, err)
	_, err = xw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, xw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "sha256.ko.xz"), buf.Bytes(), 0644))

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	require.NotEmpty(t, collected, "should find crypto patterns in xz-compressed kernel module")
	for _, f := range collected {
		assert.Equal(t, "kernel", f.Module)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}
}

func TestKernelModuleScanCompressedZst(t *testing.T) {
	tmpDir := t.TempDir()
	payload := makeFakeCryptoPayload()

	// Create zstd-compressed .ko.zst
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	require.NoError(t, err)
	_, err = zw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "ecb.ko.zst"), buf.Bytes(), 0644))

	m := NewKernelModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.ScanWithOverride(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	require.NotEmpty(t, collected, "should find crypto patterns in zstd-compressed kernel module")
	for _, f := range collected {
		assert.Equal(t, "kernel", f.Module)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}
}
