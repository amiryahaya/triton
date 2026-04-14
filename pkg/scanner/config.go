package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// ConfigModule scans configuration files for cryptographic settings.
// Supports sshd_config, crypto-policies, and java.security.
type ConfigModule struct {
	config      *scannerconfig.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
	reader      fsadapter.FileReader
}

func (m *ConfigModule) SetStore(s store.Store)               { m.store = s }
func (m *ConfigModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func NewConfigModule(cfg *scannerconfig.Config) *ConfigModule {
	return &ConfigModule{config: cfg}
}

func (m *ConfigModule) Name() string {
	return "configs"
}

func (m *ConfigModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *ConfigModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *ConfigModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *ConfigModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    m.isConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			results := m.parseConfigFile(ctx, reader, path)
			for _, finding := range results {
				select {
				case findings <- finding:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isConfigFile checks if a file is a known crypto config file.
func (m *ConfigModule) isConfigFile(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "sshd_config", "ssh_config":
		return true
	case "current": // crypto-policies state file
		return strings.Contains(path, "crypto-policies")
	case "java.security":
		return true
	case "renewal.conf":
		return strings.Contains(path, "letsencrypt")
	}
	// Match *.conf files under letsencrypt/renewal/ directories
	if filepath.Ext(path) == ".conf" && strings.Contains(path, "letsencrypt") && strings.Contains(path, "renewal") {
		return true
	}
	return false
}

// parseConfigFile dispatches to the appropriate parser based on filename.
func (m *ConfigModule) parseConfigFile(ctx context.Context, reader fsadapter.FileReader, path string) []*model.Finding {
	base := filepath.Base(path)
	switch base {
	case "sshd_config", "ssh_config":
		return m.parseSSHConfig(path)
	case "current":
		if strings.Contains(path, "crypto-policies") {
			return m.parseCryptoPolicies(ctx, reader, path)
		}
	case "java.security":
		return m.parseJavaSecurity(path)
	case "renewal.conf":
		if strings.Contains(path, "letsencrypt") {
			return m.parseCertbotConfig(ctx, reader, path)
		}
	default:
		// Match *.conf files under letsencrypt/renewal/ directories
		if filepath.Ext(path) == ".conf" && strings.Contains(path, "letsencrypt") && strings.Contains(path, "renewal") {
			return m.parseCertbotConfig(ctx, reader, path)
		}
	}
	return nil
}

// sshDirective maps SSH config directive names to algorithm categories.
var sshDirectives = map[string]string{
	"kexalgorithms":               "Key exchange",
	"hostkeyalgorithms":           "Host key authentication",
	"ciphers":                     "Symmetric encryption",
	"macs":                        "Message authentication",
	"pubkeyacceptedkeytypes":      "Public key authentication",
	"pubkeyacceptedalgorithms":    "Public key authentication",
	"hostkeyalgorithm":            "Host key authentication",
	"hostbasedacceptedalgorithms": "Host-based authentication",
}

// sshAlgorithmMap maps SSH-specific algorithm names to registry-compatible names.
var sshAlgorithmMap = map[string]string{
	"aes256-gcm@openssh.com":               "AES-256-GCM",
	"aes128-gcm@openssh.com":               "AES-128-GCM",
	"aes256-ctr":                           "AES-256-CTR",
	"aes192-ctr":                           "AES-192-CTR",
	"aes128-ctr":                           "AES-128-CTR",
	"aes256-cbc":                           "AES-256-CBC",
	"aes128-cbc":                           "AES-128-CBC",
	"chacha20-poly1305@openssh.com":        "ChaCha20-Poly1305",
	"3des-cbc":                             "3DES",
	"hmac-sha2-512-etm@openssh.com":        "HMAC-SHA512",
	"hmac-sha2-256-etm@openssh.com":        "HMAC-SHA256",
	"hmac-sha2-512":                        "HMAC-SHA512",
	"hmac-sha2-256":                        "HMAC-SHA256",
	"hmac-sha1":                            "HMAC-SHA1",
	"hmac-sha1-etm@openssh.com":            "HMAC-SHA1",
	"hmac-md5":                             "HMAC-MD5",
	"curve25519-sha256":                    "X25519",
	"curve25519-sha256@libssh.org":         "X25519",
	"ecdh-sha2-nistp256":                   "ECDSA-P256",
	"ecdh-sha2-nistp384":                   "ECDSA-P384",
	"ecdh-sha2-nistp521":                   "ECDSA-P521",
	"diffie-hellman-group16-sha512":        "DH",
	"diffie-hellman-group14-sha256":        "DH",
	"diffie-hellman-group14-sha1":          "DH",
	"diffie-hellman-group-exchange-sha256": "DH",
	"ssh-ed25519":                          "Ed25519",
	"ssh-rsa":                              "RSA", // Signature algorithm; actual key size unknown
	"rsa-sha2-512":                         "RSA", // SHA-512 signature; actual key size unknown
	"rsa-sha2-256":                         "RSA", // SHA-256 signature; actual key size unknown
	"ecdsa-sha2-nistp256":                  "ECDSA-P256",
	"ecdsa-sha2-nistp384":                  "ECDSA-P384",
	"ecdsa-sha2-nistp521":                  "ECDSA-P521",
}

// parseSSHConfig parses sshd_config or ssh_config for crypto directives.
func (m *ConfigModule) parseSSHConfig(path string) []*model.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var findings []*model.Finding
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		function, isSSHDirective := sshDirectives[directive]
		if !isSSHDirective {
			continue
		}

		// Split comma-separated algorithms
		algos := strings.Split(strings.TrimSpace(parts[1]), ",")
		for _, algo := range algos {
			algo = strings.TrimSpace(algo)
			if algo == "" {
				continue
			}

			// Map SSH algorithm name to registry name
			registryName := algo
			if mapped, ok := sshAlgorithmMap[algo]; ok {
				registryName = mapped
			}

			info := crypto.ClassifyAlgorithm(registryName, 0)
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  function,
				Algorithm: info.Name,
				KeySize:   info.KeySize,
				Purpose:   "SSH " + function,
			}
			crypto.ClassifyCryptoAsset(asset)

			findings = append(findings, &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: 8, // Configuration scanning
				Source: model.FindingSource{
					Type:            "file",
					Path:            path,
					DetectionMethod: "configuration",
				},
				CryptoAsset: asset,
				Confidence:  0.90,
				Module:      "configs",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// parseCryptoPolicies reads the crypto-policies state file.
func (m *ConfigModule) parseCryptoPolicies(ctx context.Context, reader fsadapter.FileReader, path string) []*model.Finding {
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil
	}

	policy := strings.TrimSpace(string(data))
	if policy == "" {
		return nil
	}

	// Map policy names to algorithm implications
	var pqcStatus string
	var purpose string
	switch strings.ToUpper(policy) {
	case "FUTURE":
		pqcStatus = "TRANSITIONAL"
		purpose = "System crypto policy (forward-looking, restricts legacy)"
	case "FIPS":
		pqcStatus = "TRANSITIONAL"
		purpose = "System crypto policy (FIPS 140 compliant)"
	case "DEFAULT":
		pqcStatus = "TRANSITIONAL"
		purpose = "System crypto policy (balanced defaults)"
	case "LEGACY":
		pqcStatus = "DEPRECATED"
		purpose = "System crypto policy (allows legacy algorithms)"
	default:
		pqcStatus = "TRANSITIONAL"
		purpose = "System crypto policy (" + policy + ")"
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "System crypto policy",
		Algorithm: "crypto-policies:" + policy,
		Purpose:   purpose,
		PQCStatus: pqcStatus,
	}

	return []*model.Finding{{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 8,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.85,
		Module:      "configs",
		Timestamp:   time.Now(),
	}}
}

// parseJavaSecurity parses java.security for disabled/legacy algorithm lists.
func (m *ConfigModule) parseJavaSecurity(path string) []*model.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var findings []*model.Finding
	scanner := bufio.NewScanner(f)

	// java.security properties can span multiple lines with backslash continuation
	var currentKey string
	var currentValue strings.Builder

	flush := func() {
		if currentKey != "" {
			findings = append(findings, m.parseJavaSecurityProperty(path, currentKey, currentValue.String())...)
			currentKey = ""
			currentValue.Reset()
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check for line continuation
		if strings.HasSuffix(trimmed, `\`) {
			trimmed = strings.TrimSuffix(trimmed, `\`)
			if currentKey == "" {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					currentKey = strings.TrimSpace(parts[0])
					currentValue.WriteString(strings.TrimSpace(parts[1]))
				}
			} else {
				currentValue.WriteString(strings.TrimSpace(trimmed))
			}
			continue
		}

		// End of continuation or single-line property
		if currentKey != "" {
			currentValue.WriteString(strings.TrimSpace(trimmed))
			flush()
		} else {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				currentKey = strings.TrimSpace(parts[0])
				currentValue.WriteString(strings.TrimSpace(parts[1]))
				flush()
			}
		}
	}
	flush() // Handle any remaining property

	return findings
}

// javaAlgorithmMap maps Java security algorithm names to registry-compatible names.
var javaAlgorithmMap = map[string]string{
	"SSLv3":        "SSL 3.0",
	"TLSv1":        "TLS 1.0",
	"TLSv1.1":      "TLS 1.1",
	"RC4":          "RC4",
	"DES":          "DES",
	"3DES_EDE_CBC": "3DES",
	"MD5":          "MD5",
	"MD2":          "MD2",
	"SHA1":         "SHA-1",
	"NULL":         "NULL",
}

// parseJavaSecurityProperty creates findings from a java.security disabled algorithms property.
func (m *ConfigModule) parseJavaSecurityProperty(path, key, value string) []*model.Finding {
	var function string
	switch key {
	case "jdk.tls.disabledAlgorithms":
		function = "TLS disabled algorithms"
	case "jdk.certpath.disabledAlgorithms":
		function = "Certificate path disabled algorithms"
	case "jdk.tls.legacyAlgorithms":
		function = "TLS legacy algorithms"
	default:
		return nil
	}

	entries := strings.Split(value, ",")
	findings := make([]*model.Finding, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.Contains(entry, "keySize") ||
			strings.Contains(entry, "usage") || strings.Contains(entry, "jdkCA") ||
			strings.Contains(entry, "&") || entry == "anon" {
			continue
		}

		// Clean up algorithm name
		algo := entry
		if strings.Contains(algo, "withRSA") {
			algo = "RSA-1024" // MD5withRSA → weak RSA
		}

		// Map to registry name
		if mapped, ok := javaAlgorithmMap[algo]; ok {
			algo = mapped
		}

		info := crypto.ClassifyAlgorithm(algo, 0)
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  function,
			Algorithm: info.Name,
			KeySize:   info.KeySize,
			Purpose:   "Java " + function + " (disabled/legacy)",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 8,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      "configs",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// parseCertbotConfig parses a Let's Encrypt/certbot renewal configuration file.
func (m *ConfigModule) parseCertbotConfig(ctx context.Context, reader fsadapter.FileReader, path string) []*model.Finding {
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil
	}

	content := string(data)
	if content == "" {
		return nil
	}

	asset := &model.CryptoAsset{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Function: "ACME certificate renewal",
		Purpose:  "ACME certificate renewal",
	}

	// Try to extract key type and size from the config.
	// Certbot uses both underscore (key_type) and hyphen (key-type) forms.
	algo := "RSA-2048" // default
	rsaKeySize := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		// Normalize key names: treat underscores and hyphens as equivalent
		normalized := strings.ReplaceAll(line, "-", "_")
		if strings.HasPrefix(normalized, "key_type ") || strings.HasPrefix(normalized, "key_type=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				parts = strings.SplitN(line, " ", 2)
			}
			if len(parts) == 2 {
				kt := strings.TrimSpace(parts[1])
				switch strings.ToLower(kt) {
				case "ecdsa":
					algo = "ECDSA-P256"
				case "rsa":
					algo = "RSA-2048"
				}
			}
		}
		if strings.HasPrefix(normalized, "rsa_key_size ") || strings.HasPrefix(normalized, "rsa_key_size=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				parts = strings.SplitN(line, " ", 2)
			}
			if len(parts) == 2 {
				sizeStr := strings.TrimSpace(parts[1])
				if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 {
					rsaKeySize = size
				}
			}
		}
	}

	// Apply rsa_key_size if key_type is RSA (or default)
	if rsaKeySize > 0 && strings.HasPrefix(algo, "RSA") {
		algo = fmt.Sprintf("RSA-%d", rsaKeySize)
	}

	asset.Algorithm = algo
	crypto.ClassifyCryptoAsset(asset)

	return []*model.Finding{{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 8,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.85,
		Module:      "configs",
		Timestamp:   time.Now(),
	}}
}
