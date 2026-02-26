package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// scriptCryptoPatterns defines patterns for detecting crypto usage in scripts.
// Uses CryptoPattern for hybrid literal/regex matching.
var scriptCryptoPatterns = []CryptoPattern{
	// === Python ===
	lit("hashlib.sha256", "SHA-256", "Hash function", "api-call"),
	lit("hashlib.sha512", "SHA-512", "Hash function", "api-call"),
	lit("hashlib.sha1", "SHA-1", "Hash function", "api-call"),
	lit("hashlib.md5", "MD5", "Hash function", "api-call"),
	rx(`from\s+cryptography`, "", "Cryptography library import", "import"),
	lit("Fernet", "AES-128-CBC", "Symmetric encryption (Fernet)", "api-call"),
	lit("rsa.generate_private_key", "RSA", "Key generation", "api-call"),
	lit("pbkdf2_hmac", "PBKDF2", "Key derivation", "api-call"),
	lit("hmac.new", "HMAC-SHA256", "HMAC authentication", "api-call"),
	lit("hmac.compare_digest", "HMAC-SHA256", "HMAC verification", "api-call"),
	lit("bcrypt.hashpw", "Bcrypt", "Password hashing", "api-call"),
	lit("bcrypt.gensalt", "Bcrypt", "Password hashing", "api-call"),
	lit("ec.SECP256R1", "ECDSA-P256", "Elliptic curve", "api-call"),
	lit("ec.SECP384R1", "ECDSA-P384", "Elliptic curve", "api-call"),
	lit("ec.SECP521R1", "ECDSA-P521", "Elliptic curve", "api-call"),
	lit("ssl.create_default_context", "TLS", "TLS context creation", "api-call"),
	lit("ssl.wrap_socket", "TLS", "TLS socket wrapping", "api-call"),
	lit("SSLContext", "TLS", "TLS configuration", "api-call"),

	// === Shell (openssl commands) ===
	rx(`openssl\s+genrsa`, "RSA", "Key generation", "command"),
	rx(`openssl\s+genpkey`, "", "Key generation", "command"),
	rx(`openssl\s+enc\s+-aes-256-cbc`, "AES-256-CBC", "Symmetric encryption", "command"),
	rx(`openssl\s+enc\s+-aes-128-cbc`, "AES-128-CBC", "Symmetric encryption", "command"),
	rx(`openssl\s+enc\s+-aes-256-gcm`, "AES-256-GCM", "Symmetric encryption", "command"),
	rx(`openssl\s+enc\s+-des3`, "3DES", "Symmetric encryption", "command"),
	rx(`openssl\s+dgst\s+-sha256`, "SHA-256", "Digital signature/hash", "command"),
	rx(`openssl\s+dgst\s+-sha512`, "SHA-512", "Digital signature/hash", "command"),
	rx(`openssl\s+dgst\s+-sha1`, "SHA-1", "Digital signature/hash", "command"),
	rx(`openssl\s+dgst\s+-md5`, "MD5", "Hash function", "command"),
	rx(`openssl\s+s_client`, "TLS", "TLS client connection", "command"),
	rx(`openssl\s+req\s+.*-x509`, "", "Certificate generation", "command"),

	// === Ruby ===
	lit("OpenSSL::PKey::RSA", "RSA", "Key generation", "api-call"),
	lit("OpenSSL::PKey::EC", "ECDSA", "Key generation", "api-call"),
	lit("OpenSSL::Cipher::AES", "AES", "Symmetric encryption", "api-call"),
	lit("Digest::SHA256", "SHA-256", "Hash function", "api-call"),
	lit("Digest::SHA512", "SHA-512", "Hash function", "api-call"),
	lit("Digest::SHA1", "SHA-1", "Hash function", "api-call"),
	lit("Digest::MD5", "MD5", "Hash function", "api-call"),
	lit("OpenSSL::HMAC", "HMAC-SHA256", "HMAC authentication", "api-call"),

	// === Perl ===
	lit("Crypt::OpenSSL::RSA", "RSA", "Key generation", "import"),
	lit("Crypt::OpenSSL::AES", "AES", "Symmetric encryption", "import"),
	lit("Crypt::PBKDF2", "PBKDF2", "Key derivation", "import"),
	rx(`Digest::SHA\b`, "SHA-256", "Hash function", "import"),
	lit("Crypt::CBC", "", "Symmetric encryption", "import"),

	// === PowerShell ===
	lit("[System.Security.Cryptography.AesCryptoServiceProvider]", "AES", "Symmetric encryption", "api-call"),
	lit("ConvertTo-SecureString", "", "Secure string conversion", "command"),
	lit("New-Object System.Security.Cryptography", "", "Crypto object creation", "api-call"),
	lit("Get-FileHash", "SHA-256", "File hashing", "command"),
	lit("[System.Security.Cryptography.RSACryptoServiceProvider]", "RSA", "Asymmetric encryption", "api-call"),
	lit("[System.Security.Cryptography.SHA256CryptoServiceProvider]", "SHA-256", "Hash function", "api-call"),

	// === Batch ===
	lit("certutil -hashfile", "SHA-256", "File hashing", "command"),
	lit("certutil -encode", "", "Base64 encoding", "command"),
	lit("cipher /e", "", "File encryption (EFS)", "command"),

	// === Cross-language KDF/HMAC patterns ===
	rx(`\bPBKDF2\b`, "PBKDF2", "Key derivation", "string"),
	rx(`\bscrypt\b`, "scrypt", "Key derivation", "string"),
	rx(`\bargon2\b`, "Argon2", "Key derivation", "string"),

	// === Generic patterns (cross-language) — split by mode for accurate classification ===
	rx(`(?i)AES[-_]?256[-_]?GCM`, "AES-256-GCM", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_]?256[-_]?CBC`, "AES-256-CBC", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_]?256[-_]?CTR`, "AES-256-CTR", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_]?128[-_]?GCM`, "AES-128-GCM", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_]?128[-_]?CBC`, "AES-128-CBC", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_]?128[-_]?CTR`, "AES-128-CTR", "Symmetric encryption", "string"),
	rx(`(?i)RSA[-_]?2048`, "RSA-2048", "Asymmetric encryption", "string"),
	rx(`(?i)RSA[-_]?4096`, "RSA-4096", "Asymmetric encryption", "string"),
}

// ScriptModule scans script files for crypto API usage patterns.
type ScriptModule struct {
	config      *config.Config
	lastScanned int64
	lastMatched int64
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

func (m *ScriptModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *ScriptModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		target:       target,
		config:       m.config,
		matchFile:    m.isScriptFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
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
	case ".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".pm",
		".ps1", ".psm1", // PowerShell
		".bat", ".cmd": // Batch
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
	findings := make([]*model.Finding, 0, len(scriptCryptoPatterns))

	for _, sp := range scriptCryptoPatterns {
		if !sp.Match(content) {
			continue
		}

		algo := sp.Algorithm
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
			Function:  sp.Function,
			Algorithm: algo,
			Purpose:   "Crypto usage in script",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 6,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: sp.DetectionMethod,
			},
			CryptoAsset: asset,
			Confidence:  0.75,
			Module:      "scripts",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
