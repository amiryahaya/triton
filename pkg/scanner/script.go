package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

// scriptCryptoPatterns defines regex patterns for detecting crypto usage in scripts.
var scriptCryptoPatterns = []struct {
	pattern   *regexp.Regexp
	algorithm string
	function  string
}{
	// Python
	{regexp.MustCompile(`hashlib\.sha256`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`hashlib\.sha512`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`hashlib\.sha1`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`hashlib\.md5`), "MD5", "Hash function"},
	{regexp.MustCompile(`from\s+cryptography`), "", "Cryptography library import"},
	{regexp.MustCompile(`Fernet`), "AES-128-CBC", "Symmetric encryption (Fernet)"},
	{regexp.MustCompile(`rsa\.generate_private_key`), "RSA", "Key generation"},

	// Shell (openssl commands)
	{regexp.MustCompile(`openssl\s+genrsa`), "RSA", "Key generation"},
	{regexp.MustCompile(`openssl\s+genpkey`), "", "Key generation"},
	{regexp.MustCompile(`openssl\s+enc\s+-aes-256-cbc`), "AES-256-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`openssl\s+enc\s+-aes-128-cbc`), "AES-128-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`openssl\s+enc\s+-aes-256-gcm`), "AES-256-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`openssl\s+enc\s+-des3`), "3DES", "Symmetric encryption"},
	{regexp.MustCompile(`openssl\s+dgst\s+-sha256`), "SHA-256", "Digital signature/hash"},
	{regexp.MustCompile(`openssl\s+dgst\s+-sha512`), "SHA-512", "Digital signature/hash"},
	{regexp.MustCompile(`openssl\s+dgst\s+-sha1`), "SHA-1", "Digital signature/hash"},
	{regexp.MustCompile(`openssl\s+dgst\s+-md5`), "MD5", "Hash function"},
	{regexp.MustCompile(`openssl\s+s_client`), "TLS", "TLS client connection"},
	{regexp.MustCompile(`openssl\s+req\s+.*-x509`), "", "Certificate generation"},

	// Ruby
	{regexp.MustCompile(`OpenSSL::PKey::RSA`), "RSA", "Key generation"},
	{regexp.MustCompile(`OpenSSL::PKey::EC`), "ECDSA", "Key generation"},
	{regexp.MustCompile(`OpenSSL::Cipher::AES`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`Digest::SHA256`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`Digest::SHA512`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`Digest::SHA1`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`Digest::MD5`), "MD5", "Hash function"},

	// Perl
	{regexp.MustCompile(`Crypt::OpenSSL::RSA`), "RSA", "Key generation"},
	{regexp.MustCompile(`Crypt::OpenSSL::AES`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`Digest::SHA256`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`Digest::SHA512`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`Digest::SHA1`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`Digest::SHA\b`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`Crypt::CBC`), "", "Symmetric encryption"},

	// Generic patterns (cross-language) — split by mode for accurate classification
	{regexp.MustCompile(`(?i)AES[-_]?256[-_]?GCM`), "AES-256-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_]?256[-_]?CBC`), "AES-256-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_]?256[-_]?CTR`), "AES-256-CTR", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_]?128[-_]?GCM`), "AES-128-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_]?128[-_]?CBC`), "AES-128-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_]?128[-_]?CTR`), "AES-128-CTR", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)RSA[-_]?2048`), "RSA-2048", "Asymmetric encryption"},
	{regexp.MustCompile(`(?i)RSA[-_]?4096`), "RSA-4096", "Asymmetric encryption"},
}

// ScriptModule scans script files for crypto API usage patterns.
type ScriptModule struct {
	config *config.Config
}

func NewScriptModule(cfg *config.Config) *ScriptModule {
	return &ScriptModule{config: cfg}
}

func (m *ScriptModule) Name() string {
	return "scripts"
}

func (m *ScriptModule) Category() model.ModuleCategory {
	return model.CategoryPassiveCode
}

func (m *ScriptModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *ScriptModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isScriptFile,
		processFile: func(path string) error {
			found, err := m.scanScriptFile(path)
			if err != nil {
				return nil
			}

			for _, f := range found {
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isScriptFile checks if a file is a script by extension.
func (m *ScriptModule) isScriptFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".pm":
		return true
	}
	return false
}

const maxCodeFileSize = 2 * 1024 * 1024 // 2MB cap for source code files

// scanScriptFile reads a script file and looks for crypto patterns.
func (m *ScriptModule) scanScriptFile(path string) ([]*model.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxCodeFileSize {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	seen := make(map[string]bool)
	var findings []*model.Finding

	for _, sp := range scriptCryptoPatterns {
		if !sp.pattern.MatchString(content) {
			continue
		}

		algo := sp.algorithm
		if algo == "" {
			continue // Pattern matched but no specific algorithm (e.g. generic import)
		}

		// Deduplicate by algorithm per file
		if seen[algo] {
			continue
		}
		seen[algo] = true

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  sp.function,
			Algorithm: algo,
			Purpose:   "Crypto usage in script",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 6,
			Source: model.FindingSource{
				Type: "file",
				Path: path,
			},
			CryptoAsset: asset,
			Confidence:  0.75,
			Module:      "scripts",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
