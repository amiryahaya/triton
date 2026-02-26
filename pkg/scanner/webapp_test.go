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

	// New extensions
	assert.True(t, m.isWebAppFile("/path/to/App.scala"), "Scala")
	assert.True(t, m.isWebAppFile("/path/to/page.jsp"), "JSP")
	assert.True(t, m.isWebAppFile("/path/to/App.kt"), "Kotlin")
	assert.True(t, m.isWebAppFile("/path/to/App.swift"), "Swift")
	assert.True(t, m.isWebAppFile("/path/to/main.c"), "C")
	assert.True(t, m.isWebAppFile("/path/to/crypto.h"), "C header")
	assert.True(t, m.isWebAppFile("/path/to/main.cpp"), "C++")
	assert.True(t, m.isWebAppFile("/path/to/main.cc"), "C++ alt")

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
		assert.NotEmpty(t, f.Source.DetectionMethod, "should have detection method")
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

func TestWebAppScanCryptoJS(t *testing.T) {
	tmpDir := t.TempDir()

	content := `var encrypted = CryptoJS.AES.encrypt("message", "secret");
var decrypted = CryptoJS.AES.decrypt(encrypted, "secret");
var hash = CryptoJS.SHA256("data");
var hmac = CryptoJS.HmacSHA256("data", "key");
var hmac512 = CryptoJS.HmacSHA512("data", "key");
var dk = CryptoJS.PBKDF2("password", "salt", {keySize: 256/32});
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto-js.js"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["AES"], "should detect CryptoJS.AES")
	assert.True(t, algos["SHA-256"], "should detect CryptoJS.SHA256")
	assert.True(t, algos["HMAC-SHA256"], "should detect CryptoJS.HmacSHA256")
	assert.True(t, algos["HMAC-SHA512"], "should detect CryptoJS.HmacSHA512")
	assert.True(t, algos["PBKDF2"], "should detect CryptoJS.PBKDF2")
}

func TestWebAppScanEVP(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#include <openssl/evp.h>

void encrypt(void) {
    EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    EVP_DecryptInit(ctx, cipher, key, iv);
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_PKEY *pkey = EVP_PKEY_new();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto.c"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["AES"], "should detect EVP_EncryptInit")
	assert.True(t, algos["AES-256-GCM"], "should detect EVP_aes_256_gcm")
	assert.True(t, algos["SHA-256"], "should detect EVP_sha256")
	assert.True(t, algos["RSA"], "should detect EVP_PKEY_new")
	assert.True(t, algos["TLS"], "should detect SSL_CTX_new")
}

func TestWebAppScanSwift(t *testing.T) {
	tmpDir := t.TempDir()

	content := `import Security

let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
let encrypted = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, data as CFData, &error)
let hash = CC_SHA256(data, CC_LONG(data.count), &digest)
`
	err := os.WriteFile(filepath.Join(tmpDir, "Crypto.swift"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["RSA"], "should detect SecKeyCreateRandomKey")
	assert.True(t, algos["SHA-256"], "should detect CC_SHA256")
}

func TestWebAppScanECCCurves(t *testing.T) {
	tmpDir := t.TempDir()

	content := `var key = ec.KeyFromPrivate(privateKey, 'hex');
// Using secp256k1 curve
var curve = prime256v1;
var bp = brainpoolP256r1;
var p384 = secp384r1;
`
	err := os.WriteFile(filepath.Join(tmpDir, "ecc.js"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["ECDSA-P256"], "should detect secp256k1/prime256v1/brainpool")
	assert.True(t, algos["ECDSA-P384"], "should detect secp384r1")
}

func TestWebAppScanJavaPBKDF2(t *testing.T) {
	tmpDir := t.TempDir()

	content := `import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;

SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
`
	err := os.WriteFile(filepath.Join(tmpDir, "Auth.java"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["PBKDF2"], "should detect SecretKeyFactory PBKDF2")
	assert.True(t, algos["HMAC-SHA256"], "should detect javax.crypto.Mac")
	assert.True(t, algos["TLS"], "should detect SSLContext")
}

func TestWebAppScanCSharpHMAC(t *testing.T) {
	tmpDir := t.TempDir()

	content := `using System.Security.Cryptography;

var hmac = new HMACSHA256(key);
var dk = new Rfc2898DeriveBytes(password, salt, iterations);
`
	err := os.WriteFile(filepath.Join(tmpDir, "Auth.cs"), []byte(content), 0644)
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

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}

	assert.True(t, algos["HMAC-SHA256"], "should detect HMACSHA256")
	assert.True(t, algos["PBKDF2"], "should detect Rfc2898DeriveBytes")
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

func TestWebAppDetectionMethodPopulated(t *testing.T) {
	tmpDir := t.TempDir()

	content := `<?php
$hash = hash('sha256', $data);
?>
`
	os.WriteFile(filepath.Join(tmpDir, "test.php"), []byte(content), 0644)

	m := NewWebAppModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	for f := range findings {
		assert.NotEmpty(t, f.Source.DetectionMethod, "detection method should be set")
	}
}
