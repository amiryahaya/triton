package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

// keyPEMHeaders maps PEM header types to (keyType, algorithm) pairs.
var keyPEMHeaders = []struct {
	header    string
	keyType   string
	algorithm string
}{
	{"BEGIN RSA PRIVATE KEY", "rsa-private", "RSA"},
	{"BEGIN EC PRIVATE KEY", "ec-private", "ECDSA"},
	{"BEGIN OPENSSH PRIVATE KEY", "openssh-private", "Unknown"},
	{"BEGIN DSA PRIVATE KEY", "dsa-private", "DSA"},
	{"BEGIN PRIVATE KEY", "pkcs8-private", "Unknown"}, // PKCS#8 wraps any algo
	{"BEGIN PUBLIC KEY", "public", "Unknown"},
	{"BEGIN RSA PUBLIC KEY", "rsa-public", "RSA"},
}

type KeyModule struct {
	config *config.Config
}

func NewKeyModule(cfg *config.Config) *KeyModule {
	return &KeyModule{config: cfg}
}

func (m *KeyModule) Name() string {
	return "keys"
}

func (m *KeyModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *KeyModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *KeyModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isKeyFile,
		processFile: func(path string) error {
			finding, err := m.parseKeyFile(path)
			if err != nil || finding == nil {
				return nil
			}

			select {
			case findings <- finding:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		},
	})
}

// isKeyFile checks if a file path looks like it could contain cryptographic keys
// based on file extension and SSH key naming conventions.
func (m *KeyModule) isKeyFile(path string) bool {
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Match by extension
	if ext == ".key" || ext == ".pem" || ext == ".priv" || ext == ".pub" {
		return true
	}

	// Match SSH key filenames (exact base name patterns)
	if base == "id_rsa" || base == "id_ecdsa" || base == "id_ed25519" ||
		base == "id_dsa" || base == "id_rsa.pub" || base == "id_ecdsa.pub" ||
		base == "id_ed25519.pub" {
		return true
	}

	// Match files with "private_key" or "public_key" in name (compound pattern)
	if strings.Contains(lower, "private_key") || strings.Contains(lower, "public_key") {
		return true
	}

	return false
}

// parseKeyFile reads a file and produces a finding only if it contains a recognized
// key PEM header. Returns (nil, nil) if the file has no key content.
func (m *KeyModule) parseKeyFile(path string) (*model.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	keyType, algorithm := m.detectKeyTypeAndAlgorithm(content)
	if keyType == "" {
		// No recognized key PEM header found — skip this file
		return nil, nil
	}

	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Function:  keyType,
		Algorithm: algorithm,
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.New().String(),
		Category: 5, // Key scanning
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.8,
		Module:      "keys",
		Timestamp:   time.Now(),
	}, nil
}

// detectKeyTypeAndAlgorithm identifies the key type and algorithm from PEM headers.
// Returns ("", "") if no key header is found.
func (m *KeyModule) detectKeyTypeAndAlgorithm(content string) (keyType, algorithm string) {
	for _, h := range keyPEMHeaders {
		if strings.Contains(content, h.header) {
			return h.keyType, h.algorithm
		}
	}
	return "", ""
}
