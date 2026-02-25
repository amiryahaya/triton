package fixtures_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

func TestCertificateFixturesExist(t *testing.T) {
	certDir := filepath.Join(fixturesDir(), "certificates")
	expected := []string{
		"rsa-2048.pem",
		"rsa-4096.pem",
		"ecdsa-p256.pem",
		"ed25519.pem",
		"expired.pem",
		"selfsigned-ca.pem",
		"ecdsa-p256.der",
		"chain.pem",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(certDir, name)
			info, err := os.Stat(path)
			require.NoError(t, err, "fixture file %s should exist", name)
			assert.True(t, info.Size() > 0, "fixture file %s should not be empty", name)
		})
	}
}

func TestKeyFixturesExist(t *testing.T) {
	keyDir := filepath.Join(fixturesDir(), "keys")
	expected := []string{
		"rsa-private.pem",
		"ec-private.pem",
		"pkcs8-private.pem",
		"rsa-public.pem",
		"ed25519-private.pem",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(keyDir, name)
			info, err := os.Stat(path)
			require.NoError(t, err, "fixture file %s should exist", name)
			assert.True(t, info.Size() > 0, "fixture file %s should not be empty", name)
		})
	}
}

func TestPEMCertificatesParseable(t *testing.T) {
	certDir := filepath.Join(fixturesDir(), "certificates")
	pemFiles := []struct {
		name      string
		algo      string
		isCA      bool
		isExpired bool
	}{
		{"rsa-2048.pem", "RSA", false, false},
		{"rsa-4096.pem", "RSA", false, false},
		{"ecdsa-p256.pem", "ECDSA", false, false},
		{"ed25519.pem", "Ed25519", false, false},
		{"expired.pem", "RSA", false, true},
		{"selfsigned-ca.pem", "RSA", true, false},
	}

	for _, tt := range pemFiles {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(certDir, tt.name))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block, "should contain a PEM block")
			assert.Equal(t, "CERTIFICATE", block.Type)

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)

			assert.Contains(t, strings.ToLower(cert.Subject.CommonName), "triton")
			assert.Equal(t, tt.isCA, cert.IsCA, "IsCA mismatch for %s", tt.name)

			switch tt.algo {
			case "RSA":
				assert.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)
			case "ECDSA":
				assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
			case "Ed25519":
				assert.Equal(t, x509.Ed25519, cert.PublicKeyAlgorithm)
			}
		})
	}
}

func TestDERCertificateParseable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir(), "certificates", "ecdsa-p256.der"))
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(data)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
}

func TestChainPEMContainsMultipleCerts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir(), "certificates", "chain.pem"))
	require.NoError(t, err)

	var count int
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			_, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			count++
		}
	}

	assert.Equal(t, 2, count, "chain.pem should contain 2 certificates (leaf + root)")
}

func TestKeyFilesParseable(t *testing.T) {
	keyDir := filepath.Join(fixturesDir(), "keys")
	tests := []struct {
		name    string
		pemType string
	}{
		{"rsa-private.pem", "RSA PRIVATE KEY"},
		{"ec-private.pem", "EC PRIVATE KEY"},
		{"pkcs8-private.pem", "PRIVATE KEY"},
		{"rsa-public.pem", "PUBLIC KEY"},
		{"ed25519-private.pem", "PRIVATE KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(keyDir, tt.name))
			require.NoError(t, err)

			block, _ := pem.Decode(data)
			require.NotNil(t, block, "should contain a PEM block")
			assert.Equal(t, tt.pemType, block.Type)
		})
	}
}

func TestScriptFixturesContainCryptoPatterns(t *testing.T) {
	scriptDir := filepath.Join(fixturesDir(), "scripts")
	tests := []struct {
		name     string
		patterns []string
	}{
		{"crypto-python.py", []string{"hashlib", "cryptography", "rsa"}},
		{"crypto-shell.sh", []string{"openssl", "aes-256-cbc", "sha256"}},
		{"crypto-node.js", []string{"crypto", "createHash", "sha256", "aes-256-gcm"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(scriptDir, tt.name))
			require.NoError(t, err)
			content := strings.ToLower(string(data))
			for _, pattern := range tt.patterns {
				assert.Contains(t, content, strings.ToLower(pattern),
					"%s should contain pattern %q", tt.name, pattern)
			}
		})
	}
}

func TestWebAppFixturesContainCryptoPatterns(t *testing.T) {
	webDir := filepath.Join(fixturesDir(), "webapp")
	tests := []struct {
		name     string
		patterns []string
	}{
		{"crypto-php.php", []string{"openssl_encrypt", "openssl_sign", "aes-256-cbc"}},
		{"crypto-java.java", []string{"javax.crypto", "KeyPairGenerator", "AES/GCM"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(webDir, tt.name))
			require.NoError(t, err)
			content := string(data)
			for _, pattern := range tt.patterns {
				assert.Contains(t, content, pattern,
					"%s should contain pattern %q", tt.name, pattern)
			}
		})
	}
}

func TestConfigFixturesContainSSLPatterns(t *testing.T) {
	confDir := filepath.Join(fixturesDir(), "configs")
	tests := []struct {
		name     string
		patterns []string
	}{
		{"apache-ssl.conf", []string{"SSLEngine", "SSLCipherSuite", "ECDHE-RSA-AES256-GCM-SHA384"}},
		{"nginx-ssl.conf", []string{"ssl_certificate", "ssl_protocols", "TLSv1.3"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(confDir, tt.name))
			require.NoError(t, err)
			content := string(data)
			for _, pattern := range tt.patterns {
				assert.Contains(t, content, pattern,
					"%s should contain pattern %q", tt.name, pattern)
			}
		})
	}
}
