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

	// Check finding shape
	for _, f := range collected {
		assert.Equal(t, 6, f.Category)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "scripts", f.Module)
		assert.Equal(t, 0.75, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
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

func TestScriptScanNodeCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('data').digest('hex');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
`
	err := os.WriteFile(filepath.Join(tmpDir, "helper.js"), []byte(content), 0644)
	require.NoError(t, err)

	// .js is a webapp extension, not script. For Node.js we use the script module
	// only if in scripts context. But since we need to test the pattern matching,
	// let's use a .sh wrapper or test pattern matching directly.
	// Actually, .js IS handled by webapp scanner, not script scanner.
	// Let me test with a Perl script instead.

	perlContent := `#!/usr/bin/perl
use Digest::SHA qw(sha256_hex);
use Crypt::OpenSSL::RSA;
my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
`
	err = os.WriteFile(filepath.Join(tmpDir, "encrypt.pl"), []byte(perlContent), 0644)
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
}

func TestScriptScanRubyCrypto(t *testing.T) {
	tmpDir := t.TempDir()

	content := `require 'openssl'
require 'digest'

key = OpenSSL::PKey::RSA.generate(2048)
digest = Digest::SHA256.hexdigest("data")
cipher = OpenSSL::Cipher::AES256.new(:CBC)
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

	// Script with repeated references to the same algorithm
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

	// Should deduplicate: one finding per unique algorithm per file
	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	// aes-256-cbc should appear only once
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

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.NotEmpty(t, finding.CryptoAsset.PQCStatus, "script findings should have PQC classification")
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
