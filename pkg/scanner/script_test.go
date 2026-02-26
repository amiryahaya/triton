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
var _ Module = (*ScriptModule)(nil)

func TestScriptModuleInterface(t *testing.T) {
	m := NewScriptModule(&config.Config{})
	assert.Equal(t, "scripts", m.Name())
	assert.Equal(t, model.CategoryPassiveCode, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsScriptFile(t *testing.T) {
	m := NewScriptModule(&config.Config{})

	// Should match script files
	assert.True(t, m.isScriptFile("/path/to/script.py"))
	assert.True(t, m.isScriptFile("/path/to/script.sh"))
	assert.True(t, m.isScriptFile("/path/to/script.rb"))
	assert.True(t, m.isScriptFile("/path/to/script.pl"))
	assert.True(t, m.isScriptFile("/path/to/script.bash"))
	assert.True(t, m.isScriptFile("/path/to/script.zsh"))

	// New extensions
	assert.True(t, m.isScriptFile("/path/to/script.ps1"), "PowerShell")
	assert.True(t, m.isScriptFile("/path/to/module.psm1"), "PowerShell module")
	assert.True(t, m.isScriptFile("/path/to/script.bat"), "Batch file")
	assert.True(t, m.isScriptFile("/path/to/script.cmd"), "Batch command")

	// Should NOT match
	assert.False(t, m.isScriptFile("/path/to/file.txt"))
	assert.False(t, m.isScriptFile("/path/to/file.go"))
	assert.False(t, m.isScriptFile("/path/to/file.java"))
	assert.False(t, m.isScriptFile("/path/to/binary"))
}

func TestScriptScanPythonCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

h = hashlib.sha256(b"test data")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto.py"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in Python script")

	for _, f := range collected {
		assert.Equal(t, 6, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "scripts", f.Module)
		assert.Equal(t, 0.75, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.Source.DetectionMethod, "should have detection method")
	}
}

func TestScriptScanShellCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/bin/bash
openssl genrsa -out key.pem 2048
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.txt
openssl dgst -sha256 -sign key.pem -out signature.bin data.txt
`
	err := os.WriteFile(filepath.Join(tmpDir, "deploy.sh"), []byte(content), 0755)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in shell script")
}

func TestScriptScanPerlCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	perlContent := `#!/usr/bin/perl
use Digest::SHA qw(sha256_hex);
use Crypt::OpenSSL::RSA;
use Crypt::PBKDF2;
my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
`
	err := os.WriteFile(filepath.Join(tmpDir, "encrypt.pl"), []byte(perlContent), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in Perl script")

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["RSA"], "should detect RSA")
	assert.True(t, algos["PBKDF2"], "should detect PBKDF2")
}

func TestScriptScanRubyCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `require 'openssl'
require 'digest'

key = OpenSSL::PKey::RSA.generate(2048)
digest = Digest::SHA256.hexdigest("data")
cipher = OpenSSL::Cipher::AES256.new(:CBC)
hmac = OpenSSL::HMAC.hexdigest("SHA256", key, data)
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto.rb"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in Ruby script")

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["HMAC-SHA256"], "should detect OpenSSL::HMAC")
}

func TestScriptScanPowerShell(t *testing.T) {
	tmpDir := t.TempDir()

	content := `# PowerShell crypto script
$aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
$hash = Get-FileHash -Path "file.txt" -Algorithm SHA256
$sha = [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
`
	err := os.WriteFile(filepath.Join(tmpDir, "crypto.ps1"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in PowerShell")

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["AES"], "should detect AES in PowerShell")
	assert.True(t, algos["RSA"], "should detect RSA in PowerShell")
}

func TestScriptScanBatch(t *testing.T) {
	tmpDir := t.TempDir()

	content := `@echo off
certutil -hashfile "document.pdf" SHA256
certutil -encode input.bin output.b64
cipher /e /s:C:\Secure
`
	err := os.WriteFile(filepath.Join(tmpDir, "verify.bat"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns in batch file")
	assert.Equal(t, "SHA-256", collected[0].CryptoAsset.Algorithm)
}

func TestScriptScanPythonKDF(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

dk = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
h = hmac.new(key, msg, hashlib.sha256)
ec_key = ec.SECP256R1()
ctx = ssl.create_default_context()
`
	err := os.WriteFile(filepath.Join(tmpDir, "kdf.py"), []byte(content), 0644)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
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

	assert.True(t, algos["PBKDF2"], "should detect PBKDF2")
	assert.True(t, algos["HMAC-SHA256"], "should detect hmac.new")
	assert.True(t, algos["ECDSA-P256"], "should detect ec.SECP256R1")
	assert.True(t, algos["TLS"], "should detect ssl.create_default_context")
}

func TestScriptScanNoCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/bin/bash
echo "Hello World"
ls -la /tmp
date +%Y-%m-%d
`
	err := os.WriteFile(filepath.Join(tmpDir, "simple.sh"), []byte(content), 0755)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected, "non-crypto script should produce no findings")
}

func TestScriptScanDeduplication(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/bin/bash
openssl enc -aes-256-cbc -in file1.txt -out enc1.txt
openssl enc -aes-256-cbc -in file2.txt -out enc2.txt
openssl enc -aes-256-cbc -in file3.txt -out enc3.txt
`
	err := os.WriteFile(filepath.Join(tmpDir, "repeated.sh"), []byte(content), 0755)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
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
	assert.True(t, len(collected) <= len(algos)+1, "duplicate algorithms should be deduplicated per file")
}

func TestScriptFindingHasPQCStatus(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/bin/bash
openssl enc -aes-256-cbc -in plain.txt -out enc.txt
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.sh"), []byte(content), 0755)
	require.NoError(t, err)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find crypto patterns")
	require.NotNil(t, collected[0].CryptoAsset)
	assert.NotEmpty(t, collected[0].CryptoAsset.PQCStatus, "script findings should have PQC classification")
}

func TestScriptScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	m := NewScriptModule(&config.Config{})
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

func TestScriptScanContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.py"), []byte("import hashlib"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(ctx, target, findings)
	close(findings)
}

func TestScriptDetectionMethodPopulated(t *testing.T) {
	tmpDir := t.TempDir()

	content := `#!/usr/bin/env python3
h = hashlib.sha256(b"test")
`
	os.WriteFile(filepath.Join(tmpDir, "test.py"), []byte(content), 0644)

	m := NewScriptModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	for f := range findings {
		assert.NotEmpty(t, f.Source.DetectionMethod, "detection method should be set")
	}
}
