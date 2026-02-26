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

// webAppCryptoPatterns defines regex patterns for detecting crypto usage in web application source.
var webAppCryptoPatterns = []struct {
	pattern   *regexp.Regexp
	algorithm string
	function  string
}{
	// PHP
	{regexp.MustCompile(`openssl_pkey_new`), "RSA", "Key generation"},
	{regexp.MustCompile(`openssl_encrypt`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`openssl_decrypt`), "AES", "Symmetric decryption"},
	{regexp.MustCompile(`openssl_sign`), "RSA", "Digital signature"},
	{regexp.MustCompile(`openssl_verify`), "RSA", "Signature verification"},
	{regexp.MustCompile(`hash\(\s*['"]sha256['"]\s*,`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`hash\(\s*['"]sha512['"]\s*,`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`hash\(\s*['"]sha1['"]\s*,`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`hash\(\s*['"]md5['"]\s*,`), "MD5", "Hash function"},
	{regexp.MustCompile(`password_hash\(`), "Bcrypt", "Password hashing"},
	{regexp.MustCompile(`sodium_crypto_`), "ChaCha20-Poly1305", "Libsodium crypto"},

	// JavaScript / TypeScript / Node.js
	{regexp.MustCompile(`crypto\.createHash\(['"]sha256['"]\)`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`crypto\.createHash\(['"]sha512['"]\)`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`crypto\.createHash\(['"]sha1['"]\)`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`crypto\.createHash\(['"]md5['"]\)`), "MD5", "Hash function"},
	{regexp.MustCompile(`crypto\.createCipheriv\(['"]aes-256-gcm['"]\)`), "AES-256-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`crypto\.createCipheriv\(['"]aes-256-cbc['"]\)`), "AES-256-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`crypto\.createCipheriv\(['"]aes-128-gcm['"]\)`), "AES-128-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`crypto\.createCipheriv\(['"]aes-128-cbc['"]\)`), "AES-128-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`crypto\.generateKeyPairSync\(['"]rsa['"]\)`), "RSA", "Key generation"},
	{regexp.MustCompile(`crypto\.generateKeyPairSync\(['"]ec['"]\)`), "ECDSA", "Key generation"},
	{regexp.MustCompile(`require\(['"]crypto['"]\)`), "", "Node.js crypto module"},
	{regexp.MustCompile(`SubtleCrypto|crypto\.subtle`), "", "Web Crypto API"},

	// Java
	{regexp.MustCompile(`javax\.crypto\.Cipher`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`javax\.crypto\.KeyGenerator`), "AES", "Key generation"},
	{regexp.MustCompile(`java\.security\.KeyPairGenerator`), "RSA", "Key pair generation"},
	{regexp.MustCompile(`java\.security\.MessageDigest`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`Cipher\.getInstance\(["']AES/GCM`), "AES", "Symmetric encryption (GCM mode)"},
	{regexp.MustCompile(`Cipher\.getInstance\(["']AES/CBC`), "AES", "Symmetric encryption (CBC mode)"},
	{regexp.MustCompile(`Cipher\.getInstance\(["']RSA`), "RSA", "Asymmetric encryption"},
	{regexp.MustCompile(`Cipher\.getInstance\(["']DESede`), "3DES", "Symmetric encryption"},
	{regexp.MustCompile(`Cipher\.getInstance\(["']DES[/"']`), "DES", "Symmetric encryption"},
	{regexp.MustCompile(`MessageDigest\.getInstance\(["']SHA-256["']\)`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`MessageDigest\.getInstance\(["']SHA-1["']\)`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`MessageDigest\.getInstance\(["']MD5["']\)`), "MD5", "Hash function"},
	{regexp.MustCompile(`KeyPairGenerator\.getInstance\(["']RSA["']\)`), "RSA", "Key generation"},
	{regexp.MustCompile(`KeyPairGenerator\.getInstance\(["']EC["']\)`), "ECDSA", "Key generation"},

	// Go
	{regexp.MustCompile(`"crypto/aes"`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`"crypto/des"`), "3DES", "Symmetric encryption"},
	{regexp.MustCompile(`"crypto/rsa"`), "RSA", "Asymmetric encryption"},
	{regexp.MustCompile(`"crypto/ecdsa"`), "ECDSA", "Digital signature"},
	{regexp.MustCompile(`"crypto/ed25519"`), "Ed25519", "Digital signature"},
	{regexp.MustCompile(`"crypto/sha256"`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`"crypto/sha512"`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`"crypto/md5"`), "MD5", "Hash function"},
	{regexp.MustCompile(`"crypto/tls"`), "TLS", "TLS configuration"},
	{regexp.MustCompile(`"crypto/rc4"`), "RC4", "Stream cipher"},

	// C# / .NET
	{regexp.MustCompile(`System\.Security\.Cryptography`), "", "Crypto namespace import"},
	{regexp.MustCompile(`Aes\.Create\(`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`RSA\.Create\(`), "RSA", "Asymmetric encryption"},
	{regexp.MustCompile(`ECDsa\.Create\(`), "ECDSA", "Digital signature"},
	{regexp.MustCompile(`SHA256\.Create\(`), "SHA-256", "Hash function"},
	{regexp.MustCompile(`SHA512\.Create\(`), "SHA-512", "Hash function"},
	{regexp.MustCompile(`SHA1\.Create\(`), "SHA-1", "Hash function"},
	{regexp.MustCompile(`MD5\.Create\(`), "MD5", "Hash function"},

	// Generic patterns (work across languages) — split by mode for accurate classification
	{regexp.MustCompile(`(?i)AES[-_/]?256[-_/]?GCM`), "AES-256-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_/]?256[-_/]?CBC`), "AES-256-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_/]?256[-_/]?CTR`), "AES-256-CTR", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_/]?128[-_/]?GCM`), "AES-128-GCM", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_/]?128[-_/]?CBC`), "AES-128-CBC", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)AES[-_/]?128[-_/]?CTR`), "AES-128-CTR", "Symmetric encryption"},
	{regexp.MustCompile(`(?i)RSA[-_]?2048`), "RSA-2048", "Asymmetric encryption"},
	{regexp.MustCompile(`(?i)RSA[-_]?4096`), "RSA-4096", "Asymmetric encryption"},
}

// WebAppModule scans web application source files for crypto API usage patterns.
type WebAppModule struct {
	config *config.Config
}

func NewWebAppModule(cfg *config.Config) *WebAppModule {
	return &WebAppModule{config: cfg}
}

func (m *WebAppModule) Name() string {
	return "webapp"
}

func (m *WebAppModule) Category() model.ModuleCategory {
	return model.CategoryPassiveCode
}

func (m *WebAppModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *WebAppModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isWebAppFile,
		processFile: func(path string) error {
			found, err := m.scanWebAppFile(path)
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

// isWebAppFile checks if a file is a web application source file by extension.
func (m *WebAppModule) isWebAppFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".php", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs":
		return true
	}
	return false
}

// scanWebAppFile reads a web app source file and looks for crypto patterns.
func (m *WebAppModule) scanWebAppFile(path string) ([]*model.Finding, error) {
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

	for _, wp := range webAppCryptoPatterns {
		if !wp.pattern.MatchString(content) {
			continue
		}

		algo := wp.algorithm
		if algo == "" {
			continue // Pattern matched but no specific algorithm
		}

		// Deduplicate by algorithm per file
		if seen[algo] {
			continue
		}
		seen[algo] = true

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  wp.function,
			Algorithm: algo,
			Purpose:   "Crypto usage in application source",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type: "file",
				Path: path,
			},
			CryptoAsset: asset,
			Confidence:  0.70,
			Module:      "webapp",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
