//go:build integration

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

func fixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "test", "fixtures")
}

func TestIntegrationEngineWithFixtures(t *testing.T) {
	cfg := &config.Config{
		Profile: "quick",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewCertificateModule(cfg))
	eng.RegisterModule(NewKeyModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	assert.NotEmpty(t, result.Metadata.Hostname)
	assert.True(t, result.Metadata.Duration > 0)

	assert.NotEmpty(t, result.Findings, "should have findings from fixture files")

	var certFindings, keyFindings int
	for _, f := range result.Findings {
		switch f.Module {
		case "certificates":
			certFindings++
		case "keys":
			keyFindings++
		}
	}
	assert.True(t, certFindings > 0, "should find certificates from fixtures (found %d)", certFindings)
	assert.True(t, keyFindings > 0, "should find keys from fixtures (found %d)", keyFindings)

	for _, f := range result.Findings {
		assert.NotEmpty(t, f.ID, "every finding should have an ID")
		assert.NotEmpty(t, f.Source.Type, "every finding should have a source type")
		assert.NotEmpty(t, f.Source.Path, "every finding should have a source path")
		assert.NotEmpty(t, f.Module, "every finding should have a module name")
		assert.True(t, f.Confidence > 0, "every finding should have confidence > 0")
	}

	for _, f := range result.Findings {
		if f.Module == "certificates" {
			require.NotNil(t, f.CryptoAsset, "certificate findings must have CryptoAsset")
			assert.NotEmpty(t, f.CryptoAsset.Algorithm, "certificate should have algorithm")
			assert.True(t, f.CryptoAsset.KeySize > 0, "certificate should have key size")
			assert.NotEmpty(t, f.CryptoAsset.Subject, "certificate should have subject")
			assert.NotEmpty(t, f.CryptoAsset.Issuer, "certificate should have issuer")
		}
	}

	assert.Equal(t, len(result.Findings), result.Summary.TotalFindings)
}

func TestIntegrationCertificateScanFixtures(t *testing.T) {
	certDir := filepath.Join(fixturesDir(), "certificates")
	cfg := &config.Config{}

	m := NewCertificateModule(cfg)
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: certDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.GreaterOrEqual(t, len(collected), 8, "should find at least 8 certificates")

	algos := make(map[string]bool)
	for _, f := range collected {
		if f.CryptoAsset != nil {
			algos[f.CryptoAsset.Algorithm] = true
		}
	}
	assert.True(t, len(algos) >= 3, "should find at least 3 different algorithms, got: %v", algos)
}

func TestIntegrationKeyScanFixtures(t *testing.T) {
	keyDir := filepath.Join(fixturesDir(), "keys")
	cfg := &config.Config{}

	m := NewKeyModule(cfg)
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: keyDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.GreaterOrEqual(t, len(collected), 5, "should find at least 5 key files")

	keyTypes := make(map[string]bool)
	for _, f := range collected {
		if f.CryptoAsset != nil {
			keyTypes[f.CryptoAsset.Function] = true
		}
	}
	assert.True(t, len(keyTypes) >= 3, "should find at least 3 different key types, got: %v", keyTypes)
}

func TestIntegrationProgressReporting(t *testing.T) {
	cfg := &config.Config{
		Profile: "quick",
		Workers: 2,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewCertificateModule(cfg))
	eng.RegisterModule(NewKeyModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	eng.Scan(ctx, progressCh)

	var messages []Progress
	for p := range progressCh {
		messages = append(messages, p)
	}

	require.NotEmpty(t, messages)
	last := messages[len(messages)-1]
	assert.True(t, last.Complete)
	assert.NotNil(t, last.Result)
}

func TestShouldRunModuleWithFilter(t *testing.T) {
	cfg := &config.Config{
		Modules: []string{"certificates"},
		Workers: 2,
	}
	eng := New(cfg)

	certModule := NewCertificateModule(cfg)
	keyModule := NewKeyModule(cfg)

	assert.True(t, eng.shouldRunModule(certModule))
	assert.False(t, eng.shouldRunModule(keyModule))
}

func TestIntegrationAllFileBasedScanners(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up a mixed test directory with all scannable types
	setupPhase2Fixtures(t, tmpDir)

	cfg := &config.Config{
		Profile: "standard",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewCertificateModule(cfg))
	eng.RegisterModule(NewKeyModule(cfg))
	eng.RegisterModule(NewLibraryModule(cfg))
	eng.RegisterModule(NewBinaryModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.Findings, "should have findings from mixed test directory")

	// Verify we got findings from multiple modules
	moduleFindings := make(map[string]int)
	for _, f := range result.Findings {
		moduleFindings[f.Module]++
	}

	assert.True(t, moduleFindings["certificates"] > 0, "should find certificates")
	assert.True(t, moduleFindings["keys"] > 0, "should find keys")
	assert.True(t, moduleFindings["libraries"] > 0, "should find libraries")
	assert.True(t, moduleFindings["binaries"] > 0, "should find binary crypto patterns")

	// Verify findings from cert/key/binary modules have proper PQC classification
	// (Library findings use library name as "algorithm", not a crypto algo)
	for _, f := range result.Findings {
		if f.CryptoAsset != nil && f.Module != "libraries" &&
			f.CryptoAsset.Algorithm != "" && f.CryptoAsset.Algorithm != "Unknown" {
			assert.NotEmpty(t, f.CryptoAsset.PQCStatus,
				"finding for %s should have PQC status", f.CryptoAsset.Algorithm)
		}
	}

	// Verify summary
	assert.Equal(t, len(result.Findings), result.Summary.TotalFindings)
	assert.True(t, result.Summary.TotalCryptoAssets > 0, "should have crypto assets in summary")
}

func TestIntegrationPhase3ScriptAndWebApp(t *testing.T) {
	tmpDir := t.TempDir()
	setupPhase3Fixtures(t, tmpDir)

	cfg := &config.Config{
		Profile: "standard",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewScriptModule(cfg))
	eng.RegisterModule(NewWebAppModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.Findings, "should have findings from script/webapp fixtures")

	moduleFindings := make(map[string]int)
	for _, f := range result.Findings {
		moduleFindings[f.Module]++
	}

	assert.True(t, moduleFindings["scripts"] > 0, "should find crypto in scripts")
	assert.True(t, moduleFindings["webapp"] > 0, "should find crypto in web apps")

	// Verify PQC classification on all findings
	for _, f := range result.Findings {
		if f.CryptoAsset != nil {
			assert.NotEmpty(t, f.CryptoAsset.PQCStatus,
				"finding for %s should have PQC status", f.CryptoAsset.Algorithm)
		}
	}
}

func TestIntegrationPhase3AllModulesWithFixtures(t *testing.T) {
	tmpDir := t.TempDir()
	setupPhase2Fixtures(t, tmpDir)
	setupPhase3Fixtures(t, tmpDir)

	cfg := &config.Config{
		Profile: "comprehensive",
		Workers: 4,
		Modules: []string{"certificates", "keys", "libraries", "binaries", "scripts", "webapp"},
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterDefaultModules()

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.Findings)

	moduleFindings := make(map[string]int)
	for _, f := range result.Findings {
		moduleFindings[f.Module]++
	}

	// All file-based scanners should produce findings
	assert.True(t, moduleFindings["certificates"] > 0, "should find certificates")
	assert.True(t, moduleFindings["keys"] > 0, "should find keys")
	assert.True(t, moduleFindings["libraries"] > 0, "should find libraries")
	assert.True(t, moduleFindings["binaries"] > 0, "should find binary crypto patterns")
	assert.True(t, moduleFindings["scripts"] > 0, "should find script crypto patterns")
	assert.True(t, moduleFindings["webapp"] > 0, "should find webapp crypto patterns")

	// Verify summary
	assert.Equal(t, len(result.Findings), result.Summary.TotalFindings)
	assert.True(t, result.Summary.TotalCryptoAssets > 0)
}

// setupPhase3Fixtures creates test files for script and webapp scanners.
func setupPhase3Fixtures(t *testing.T, tmpDir string) {
	t.Helper()

	// Script files
	scriptDir := filepath.Join(tmpDir, "scripts")
	os.MkdirAll(scriptDir, 0755)

	os.WriteFile(filepath.Join(scriptDir, "encrypt.py"), []byte(`
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
sha256_hash = hashlib.sha256(b"data").hexdigest()
`), 0644)

	os.WriteFile(filepath.Join(scriptDir, "deploy.sh"), []byte(`#!/bin/bash
openssl aes-256-cbc -in file.txt -out file.enc
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
`), 0755)

	// Web app files
	webDir := filepath.Join(tmpDir, "web")
	os.MkdirAll(webDir, 0755)

	os.WriteFile(filepath.Join(webDir, "auth.php"), []byte(`<?php
$hash = password_hash($password, PASSWORD_BCRYPT);
$encrypted = openssl_encrypt($data, 'aes-256-cbc', $key);
?>`), 0644)

	os.WriteFile(filepath.Join(webDir, "crypto.java"), []byte(`
import javax.crypto.Cipher;
import java.security.MessageDigest;
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
MessageDigest md = MessageDigest.getInstance("SHA-256");
`), 0644)
}

// setupPhase2Fixtures creates test files for integration testing of all Phase 2 scanners.
func setupPhase2Fixtures(t *testing.T, tmpDir string) {
	t.Helper()

	// 1. Certificate
	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "phase2-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certFile, err := os.Create(filepath.Join(certDir, "test.pem"))
	require.NoError(t, err)
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// 2. Key
	keyDir := filepath.Join(tmpDir, "keys")
	os.MkdirAll(keyDir, 0755)

	os.WriteFile(filepath.Join(keyDir, "server.key"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f\n-----END RSA PRIVATE KEY-----\n"), 0600)

	// 3. Libraries
	libDir := filepath.Join(tmpDir, "lib")
	os.MkdirAll(libDir, 0755)

	os.WriteFile(filepath.Join(libDir, "libcrypto.so.1.1"), []byte("fake library"), 0644)
	os.WriteFile(filepath.Join(libDir, "libssl.so.3"), []byte("fake library"), 0644)

	// 4. Binary with crypto strings
	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0755)

	var binData []byte
	binData = append(binData, 0x7f, 'E', 'L', 'F') // ELF magic
	binData = append(binData, make([]byte, 50)...)
	binData = append(binData, []byte("AES-256-GCM cipher enabled")...)
	binData = append(binData, make([]byte, 10)...)
	binData = append(binData, []byte("RSA-2048 key exchange")...)
	os.WriteFile(filepath.Join(binDir, "crypto-app"), binData, 0755)
}
