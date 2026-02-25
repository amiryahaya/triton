package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

type KeyModule struct {
	config *config.Config
}

func NewKeyModule(cfg *config.Config) *KeyModule {
	return &KeyModule{config: cfg}
}

func (m *KeyModule) Name() string {
	return "keys"
}

func (m *KeyModule) Scan(ctx context.Context, target string, findings chan<- *model.Finding) error {
	return filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !m.isKeyFile(path) {
			return nil
		}

		keyInfo, err := m.parseKeyFile(path)
		if err != nil {
			return nil
		}

		select {
		case findings <- keyInfo:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})
}

func (m *KeyModule) isKeyFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".key") ||
		strings.HasSuffix(lower, ".pem") ||
		strings.HasSuffix(lower, ".priv") ||
		strings.HasSuffix(lower, ".pub") ||
		strings.Contains(lower, "private") ||
		strings.Contains(lower, "id_rsa") ||
		strings.Contains(lower, "id_ecdsa") ||
		strings.Contains(lower, "id_ed25519")
}

func (m *KeyModule) parseKeyFile(path string) (*model.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	
	// Detect key type from PEM headers
	keyType := m.detectKeyType(content)
	
	return &model.Finding{
		Type: "key",
		Path: path,
		CryptoAsset: &model.CryptoAsset{
			Type:      keyType,
			Algorithm: m.classifyAlgorithm(content),
		},
		Confidence: 0.8,
	}, nil
}

func (m *KeyModule) detectKeyType(content string) string {
	if strings.Contains(content, "BEGIN RSA PRIVATE KEY") {
		return "rsa-private"
	}
	if strings.Contains(content, "BEGIN EC PRIVATE KEY") || strings.Contains(content, "BEGIN OPENSSH PRIVATE KEY") {
		return "ec-private"
	}
	if strings.Contains(content, "BEGIN PRIVATE KEY") {
		return "pkcs8-private"
	}
	if strings.Contains(content, "BEGIN PUBLIC KEY") {
		return "public"
	}
	if strings.Contains(content, "BEGIN OPENSSH PRIVATE KEY") {
		return "openssh-private"
	}
	return "unknown"
}

func (m *KeyModule) classifyAlgorithm(content string) string {
	if strings.Contains(content, "RSA") {
		return "RSA"
	}
	if strings.Contains(content, "EC") || strings.Contains(content, "ECDSA") {
		return "ECDSA"
	}
	if strings.Contains(content, "ED25519") {
		return "Ed25519"
	}
	return "Unknown"
}
