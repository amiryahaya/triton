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

// webAppCryptoPatterns defines patterns for detecting crypto usage in web application source.
// Uses CryptoPattern for hybrid literal/regex matching.
var webAppCryptoPatterns = []CryptoPattern{
	// === PHP ===
	lit("openssl_pkey_new", "RSA", "Key generation", "api-call"),
	lit("openssl_encrypt", "AES", "Symmetric encryption", "api-call"),
	lit("openssl_decrypt", "AES", "Symmetric decryption", "api-call"),
	lit("openssl_sign", "RSA", "Digital signature", "api-call"),
	lit("openssl_verify", "RSA", "Signature verification", "api-call"),
	rx(`hash\(\s*['"]sha256['"]\s*,`, "SHA-256", "Hash function", "api-call"),
	rx(`hash\(\s*['"]sha512['"]\s*,`, "SHA-512", "Hash function", "api-call"),
	rx(`hash\(\s*['"]sha1['"]\s*,`, "SHA-1", "Hash function", "api-call"),
	rx(`hash\(\s*['"]md5['"]\s*,`, "MD5", "Hash function", "api-call"),
	lit("password_hash(", "Bcrypt", "Password hashing", "api-call"),
	lit("sodium_crypto_", "ChaCha20-Poly1305", "Libsodium crypto", "api-call"),

	// === JavaScript / TypeScript / Node.js ===
	rx(`crypto\.createHash\(['"]sha256['"]\)`, "SHA-256", "Hash function", "api-call"),
	rx(`crypto\.createHash\(['"]sha512['"]\)`, "SHA-512", "Hash function", "api-call"),
	rx(`crypto\.createHash\(['"]sha1['"]\)`, "SHA-1", "Hash function", "api-call"),
	rx(`crypto\.createHash\(['"]md5['"]\)`, "MD5", "Hash function", "api-call"),
	rx(`crypto\.createCipheriv\(['"]aes-256-gcm['"]\)`, "AES-256-GCM", "Symmetric encryption", "api-call"),
	rx(`crypto\.createCipheriv\(['"]aes-256-cbc['"]\)`, "AES-256-CBC", "Symmetric encryption", "api-call"),
	rx(`crypto\.createCipheriv\(['"]aes-128-gcm['"]\)`, "AES-128-GCM", "Symmetric encryption", "api-call"),
	rx(`crypto\.createCipheriv\(['"]aes-128-cbc['"]\)`, "AES-128-CBC", "Symmetric encryption", "api-call"),
	rx(`crypto\.generateKeyPairSync\(['"]rsa['"]\)`, "RSA", "Key generation", "api-call"),
	rx(`crypto\.generateKeyPairSync\(['"]ec['"]\)`, "ECDSA", "Key generation", "api-call"),
	rx(`require\(['"]crypto['"]\)`, "", "Node.js crypto module", "import"),
	rx(`SubtleCrypto|crypto\.subtle`, "", "Web Crypto API", "import"),
	lit("crypto.createHmac", "HMAC-SHA256", "HMAC authentication", "api-call"),
	lit("crypto.pbkdf2", "PBKDF2", "Key derivation", "api-call"),

	// CryptoJS
	lit("CryptoJS.AES.encrypt", "AES", "Symmetric encryption (CryptoJS)", "api-call"),
	lit("CryptoJS.AES.decrypt", "AES", "Symmetric decryption (CryptoJS)", "api-call"),
	lit("CryptoJS.SHA256", "SHA-256", "Hash function (CryptoJS)", "api-call"),
	lit("CryptoJS.HmacSHA256", "HMAC-SHA256", "HMAC (CryptoJS)", "api-call"),
	lit("CryptoJS.HmacSHA512", "HMAC-SHA512", "HMAC (CryptoJS)", "api-call"),
	lit("CryptoJS.PBKDF2", "PBKDF2", "Key derivation (CryptoJS)", "api-call"),

	// === Java / Kotlin ===
	lit("javax.crypto.Cipher", "AES", "Symmetric encryption", "import"),
	lit("javax.crypto.KeyGenerator", "AES", "Key generation", "import"),
	lit("java.security.KeyPairGenerator", "RSA", "Key pair generation", "import"),
	lit("java.security.MessageDigest", "SHA-256", "Hash function", "import"),
	rx(`Cipher\.getInstance\(["']AES/GCM`, "AES", "Symmetric encryption (GCM mode)", "api-call"),
	rx(`Cipher\.getInstance\(["']AES/CBC`, "AES", "Symmetric encryption (CBC mode)", "api-call"),
	rx(`Cipher\.getInstance\(["']RSA`, "RSA", "Asymmetric encryption", "api-call"),
	rx(`Cipher\.getInstance\(["']DESede`, "3DES", "Symmetric encryption", "api-call"),
	rx(`Cipher\.getInstance\(["']DES[/"']`, "DES", "Symmetric encryption", "api-call"),
	rx(`MessageDigest\.getInstance\(["']SHA-256["']\)`, "SHA-256", "Hash function", "api-call"),
	rx(`MessageDigest\.getInstance\(["']SHA-1["']\)`, "SHA-1", "Hash function", "api-call"),
	rx(`MessageDigest\.getInstance\(["']MD5["']\)`, "MD5", "Hash function", "api-call"),
	rx(`KeyPairGenerator\.getInstance\(["']RSA["']\)`, "RSA", "Key generation", "api-call"),
	rx(`KeyPairGenerator\.getInstance\(["']EC["']\)`, "ECDSA", "Key generation", "api-call"),
	lit("javax.crypto.Mac", "HMAC-SHA256", "HMAC authentication", "import"),
	rx(`SecretKeyFactory\.getInstance\(["']PBKDF2`, "PBKDF2", "Key derivation", "api-call"),
	lit("SSLContext", "TLS", "TLS configuration", "api-call"),

	// === Go ===
	lit(`"crypto/aes"`, "AES", "Symmetric encryption", "import"),
	lit(`"crypto/des"`, "3DES", "Symmetric encryption", "import"),
	lit(`"crypto/rsa"`, "RSA", "Asymmetric encryption", "import"),
	lit(`"crypto/ecdsa"`, "ECDSA", "Digital signature", "import"),
	lit(`"crypto/ed25519"`, "Ed25519", "Digital signature", "import"),
	lit(`"crypto/sha256"`, "SHA-256", "Hash function", "import"),
	lit(`"crypto/sha512"`, "SHA-512", "Hash function", "import"),
	lit(`"crypto/md5"`, "MD5", "Hash function", "import"),
	lit(`"crypto/tls"`, "TLS", "TLS configuration", "import"),
	lit(`"crypto/rc4"`, "RC4", "Stream cipher", "import"),
	rx(`tls\.Config\{`, "TLS", "TLS configuration", "api-call"),
	rx(`hmac\.New\(sha256\.New`, "HMAC-SHA256", "HMAC authentication", "api-call"),

	// === C# / .NET ===
	lit("System.Security.Cryptography", "", "Crypto namespace import", "import"),
	lit("Aes.Create(", "AES", "Symmetric encryption", "api-call"),
	lit("RSA.Create(", "RSA", "Asymmetric encryption", "api-call"),
	lit("ECDsa.Create(", "ECDSA", "Digital signature", "api-call"),
	lit("SHA256.Create(", "SHA-256", "Hash function", "api-call"),
	lit("SHA512.Create(", "SHA-512", "Hash function", "api-call"),
	lit("SHA1.Create(", "SHA-1", "Hash function", "api-call"),
	lit("MD5.Create(", "MD5", "Hash function", "api-call"),
	lit("HMACSHA256", "HMAC-SHA256", "HMAC authentication", "api-call"),
	lit("Rfc2898DeriveBytes", "PBKDF2", "Key derivation", "api-call"),

	// === C/C++ (EVP / OpenSSL) ===
	lit("EVP_EncryptInit", "AES", "Symmetric encryption (EVP)", "symbol"),
	lit("EVP_DecryptInit", "AES", "Symmetric decryption (EVP)", "symbol"),
	lit("EVP_DigestInit", "SHA-256", "Hash function (EVP)", "symbol"),
	lit("EVP_PKEY_new", "RSA", "Key generation (EVP)", "symbol"),
	lit("EVP_aes_256_gcm", "AES-256-GCM", "Symmetric encryption (EVP)", "symbol"),
	lit("EVP_sha256", "SHA-256", "Hash function (EVP)", "symbol"),
	lit("SSL_CTX_new", "TLS", "TLS context creation", "symbol"),

	// === Swift ===
	lit("SecKeyCreateRandomKey", "RSA", "Key generation", "api-call"),
	lit("SecKeyCreateEncryptedData", "RSA", "Asymmetric encryption", "api-call"),
	lit("CC_SHA256", "SHA-256", "Hash function (CommonCrypto)", "api-call"),

	// === ECC curve names (cross-language) ===
	lit("secp256k1", "ECDSA-P256", "Elliptic curve (secp256k1)", "string"),
	lit("prime256v1", "ECDSA-P256", "Elliptic curve (prime256v1)", "string"),
	lit("brainpoolP256r1", "ECDSA-P256", "Elliptic curve (brainpool)", "string"),
	lit("secp384r1", "ECDSA-P384", "Elliptic curve (secp384r1)", "string"),

	// === TLS context (cross-language) ===
	rx(`ssl_set_cipher_list`, "TLS", "TLS cipher configuration", "api-call"),

	// === Generic patterns (cross-language) — split by mode for accurate classification ===
	rx(`(?i)AES[-_/]?256[-_/]?GCM`, "AES-256-GCM", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_/]?256[-_/]?CBC`, "AES-256-CBC", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_/]?256[-_/]?CTR`, "AES-256-CTR", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_/]?128[-_/]?GCM`, "AES-128-GCM", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_/]?128[-_/]?CBC`, "AES-128-CBC", "Symmetric encryption", "string"),
	rx(`(?i)AES[-_/]?128[-_/]?CTR`, "AES-128-CTR", "Symmetric encryption", "string"),
	rx(`(?i)RSA[-_]?2048`, "RSA-2048", "Asymmetric encryption", "string"),
	rx(`(?i)RSA[-_]?4096`, "RSA-4096", "Asymmetric encryption", "string"),
}

// WebAppModule scans web application source files for crypto API usage patterns.
type WebAppModule struct {
	config      *config.Config
	lastScanned int64
	lastMatched int64
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

func (m *WebAppModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *WebAppModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		target:       target,
		config:       m.config,
		matchFile:    m.isWebAppFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
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
	case ".php", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs",
		".scala", ".jsp", ".kt", // JVM languages
		".swift",                  // Swift
		".c", ".h", ".cpp", ".cc": // C/C++
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
	findings := make([]*model.Finding, 0, len(webAppCryptoPatterns))

	for _, wp := range webAppCryptoPatterns {
		if !wp.Match(content) {
			continue
		}

		algo := wp.Algorithm
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
			Function:  wp.Function,
			Algorithm: algo,
			Purpose:   "Crypto usage in application source",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: wp.DetectionMethod,
			},
			CryptoAsset: asset,
			Confidence:  0.70,
			Module:      "webapp",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
