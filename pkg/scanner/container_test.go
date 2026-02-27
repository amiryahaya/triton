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

func TestContainerModule_Name(t *testing.T) {
	m := NewContainerModule(nil)
	assert.Equal(t, "containers", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestContainerModule_ScanDockerfile(t *testing.T) {
	dir := t.TempDir()

	dockerfile := filepath.Join(dir, "Dockerfile")
	content := `FROM nginx:latest
COPY server.crt /etc/ssl/certs/server.crt
COPY server.key /etc/ssl/private/server.key
ENV SSL_PROTOCOLS=TLSv1.2
RUN openssl genrsa -aes256 -out ca-key.pem 4096
`
	require.NoError(t, os.WriteFile(dockerfile, []byte(content), 0o644))

	cfg := &config.Config{
		ScanTargets: []model.ScanTarget{{Type: model.TargetFilesystem, Value: dir, Depth: 3}},
	}
	m := NewContainerModule(cfg)

	findings := make(chan *model.Finding, 50)
	err := m.Scan(context.Background(), cfg.ScanTargets[0], findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.NotEmpty(t, results, "should find crypto references in Dockerfile")
	for _, f := range results {
		assert.Equal(t, "containers", f.Module)
		assert.Equal(t, 8, f.Category)
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
		assert.Equal(t, dockerfile, f.Source.Path)
	}
}

func TestContainerModule_ScanDockerCompose(t *testing.T) {
	dir := t.TempDir()

	compose := filepath.Join(dir, "docker-compose.yml")
	content := `version: '3'
services:
  web:
    image: nginx
    volumes:
      - ./certs/server.pem:/etc/ssl/server.pem
    environment:
      - SSL_CERT_FILE=/etc/ssl/server.pem
      - ENCRYPTION_ALGORITHM=AES-256
`
	require.NoError(t, os.WriteFile(compose, []byte(content), 0o644))

	cfg := &config.Config{
		ScanTargets: []model.ScanTarget{{Type: model.TargetFilesystem, Value: dir, Depth: 3}},
	}
	m := NewContainerModule(cfg)

	findings := make(chan *model.Finding, 50)
	err := m.Scan(context.Background(), cfg.ScanTargets[0], findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.NotEmpty(t, results, "should find crypto references in docker-compose")
}

func TestContainerModule_InsecureProtocol(t *testing.T) {
	dir := t.TempDir()

	dockerfile := filepath.Join(dir, "Dockerfile")
	content := `FROM nginx:latest
ENV SSL_PROTOCOLS=SSLv3
`
	require.NoError(t, os.WriteFile(dockerfile, []byte(content), 0o644))

	cfg := &config.Config{
		ScanTargets: []model.ScanTarget{{Type: model.TargetFilesystem, Value: dir, Depth: 3}},
	}
	m := NewContainerModule(cfg)

	findings := make(chan *model.Finding, 50)
	err := m.Scan(context.Background(), cfg.ScanTargets[0], findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.NotEmpty(t, results)
	// SSLv3 should be detected
	foundSSL := false
	for _, f := range results {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "SSLv3" {
			foundSSL = true
		}
	}
	assert.True(t, foundSSL, "should detect SSLv3 as insecure protocol")
}

func TestContainerModule_NoMatchingFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a non-container file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o644))

	cfg := &config.Config{
		ScanTargets: []model.ScanTarget{{Type: model.TargetFilesystem, Value: dir, Depth: 3}},
	}
	m := NewContainerModule(cfg)

	findings := make(chan *model.Finding, 50)
	err := m.Scan(context.Background(), cfg.ScanTargets[0], findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.Empty(t, results)
}

func TestIsContainerFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"Dockerfile", true},
		{"Dockerfile.prod", true},
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"compose.yml", true},
		{"compose.yaml", true},
		{"app.dockerfile", true},
		{"readme.md", false},
		{"main.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, isContainerFile(tt.path))
		})
	}
}

func TestExtractAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"openssl rsa key generation", "RSA"},
		{"using aes-256 encryption", "AES"},
		{"protocol sslv3", "SSLv3"},
		{"sha256 hash", "SHA-256"},
		{"md5 digest", "MD5"},
		{"ed25519 key", "Ed25519"},
		{"no match here", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractAlgorithm(tt.input))
		})
	}
}

func TestContainerModule_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	dockerfile := filepath.Join(dir, "Dockerfile")
	content := `FROM nginx:latest
COPY server.crt /etc/ssl/certs/server.crt
`
	require.NoError(t, os.WriteFile(dockerfile, []byte(content), 0o644))

	cfg := &config.Config{
		ScanTargets: []model.ScanTarget{{Type: model.TargetFilesystem, Value: dir, Depth: 3}},
	}
	m := NewContainerModule(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	findings := make(chan *model.Finding, 50)
	_ = m.Scan(ctx, cfg.ScanTargets[0], findings)
	close(findings)
	// Should not hang
}
