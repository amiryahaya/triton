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
var _ Module = (*WebAppModule)(nil)

func TestWebAppModuleInterface(t *testing.T) {
	m := NewWebAppModule(&config.Config{})
	assert.Equal(t, "webapp", m.Name())
	assert.Equal(t, model.CategoryPassiveCode, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsWebAppFile(t *testing.T) {
	m := NewWebAppModule(&config.Config{})

	// Should match web app files
	assert.True(t, m.isWebAppFile("/path/to/app.php"))
	assert.True(t, m.isWebAppFile("/path/to/app.js"))
	assert.True(t, m.isWebAppFile("/path/to/app.ts"))
	assert.True(t, m.isWebAppFile("/path/to/app.jsx"))
	assert.True(t, m.isWebAppFile("/path/to/app.tsx"))
	assert.True(t, m.isWebAppFile("/path/to/App.java"))
	assert.True(t, m.isWebAppFile("/path/to/main.go"))
	assert.True(t, m.isWebAppFile("/path/to/main.cs"))

	// Should NOT match (handled by script scanner or not relevant)
	assert.False(t, m.isWebAppFile("/path/to/script.py"))
	assert.False(t, m.isWebAppFile("/path/to/script.sh"))
	assert.False(t, m.isWebAppFile("/path/to/file.txt"))
	assert.False(t, m.isWebAppFile("/path/to/image.png"))
}

func TestWebAppScanPHP(t *testing.T) {
	tmpDir := t.TempDir()

	content := `<?php
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
$hash = hash('sha256', $data);
openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA256);
?>
`
	err := os.WriteFile(filepath.Join(tmpDir, "api.php"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in PHP file")

	for _, f := range collected {
		assert.Equal(t, 7, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "webapp", f.Module)
		assert.Equal(t, 0.70, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
	}
}

func TestWebAppScanJava(t *testing.T) {
	tmpDir := t.TempDir()

	content := `import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class CryptoExample {
    public void example() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "CryptoExample.java"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in Java file")
}

func TestWebAppScanJavaScript(t *testing.T) {
	tmpDir := t.TempDir()

	content := `const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('data').digest('hex');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto.js"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in JavaScript file")
}

func TestWebAppScanGo(t *testing.T) {
	tmpDir := t.TempDir()

	// Use non-.go extension in temp dir to avoid Go toolchain confusion
	// Test the pattern matching logic directly instead
	content := `package main

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/tls"
)

func main() {
	block, _ := aes.NewCipher(key)
	hash := sha256.Sum256(data)
	_ = tls.Config{MinVersion: tls.VersionTLS12}
}
`
	// Write as .go.txt to avoid interfering with the Go compiler
	goFile := filepath.Join(tmpDir, "server.go.txt")
	err := os.WriteFile(goFile, []byte(content), 0644)
	require.NoError(t, err)

	// Test the pattern matching directly
	m := NewWebAppModule(&config.Config{})
	found, err := m.scanWebAppFile(goFile)
	require.NoError(t, err)
	require.NotEmpty(t, found, "should find crypto patterns in Go source")
}

func TestWebAppScanCSharp(t *testing.T) {
	tmpDir := t.TempDir()

	content := `using System.Security.Cryptography;

var aes = Aes.Create();
var rsa = RSA.Create(2048);
var sha = SHA256.Create();
`
	err := os.WriteFile(filepath.Join(tmpDir, "Crypto.cs"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in C# file")
}

func TestWebAppScanNoCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `<?php
echo "Hello World";
$result = array_sum([1, 2, 3]);
?>
`
	err := os.WriteFile(filepath.Join(tmpDir, "hello.php"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "non-crypto web file should produce no findings")
}

func TestWebAppScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	m := NewWebAppModule(&config.Config{})
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

func TestWebAppFindingHasPQCStatus(t *testing.T) {
	tmpDir := t.TempDir()

	content := `<?php
$hash = hash('md5', $data);
?>
`
	err := os.WriteFile(filepath.Join(tmpDir, "legacy.php"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.NotEmpty(t, finding.CryptoAsset.PQCStatus)
	assert.Equal(t, "DEPRECATED", finding.CryptoAsset.PQCStatus, "MD5 should be DEPRECATED")
}
