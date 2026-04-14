package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
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

// SecretsMgrModule scans secrets manager configuration files for
// encryption backend metadata:
//
//   - HashiCorp Vault: seal stanzas (transit, awskms, gcpckms, azurekeyvault,
//     pkcs11), TLS listener config, tls_disable detection
//   - SOPS: .sops.yaml creation rules — age, KMS, PGP key references
//   - AWS: ~/.aws/config kms_key_id references
//
// Metadata only — never extracts secrets, keys, or tokens.
// Enterprise tier (accesses secrets infrastructure config).
type SecretsMgrModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewSecretsMgrModule constructs a SecretsMgrModule.
func NewSecretsMgrModule(cfg *scannerconfig.Config) *SecretsMgrModule {
	return &SecretsMgrModule{config: cfg}
}

func (m *SecretsMgrModule) Name() string                         { return "secrets_mgr" }
func (m *SecretsMgrModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *SecretsMgrModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *SecretsMgrModule) SetStore(s store.Store)               { m.store = s }

func (m *SecretsMgrModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses matching config files.
func (m *SecretsMgrModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isSecretsMgrConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			data, err := reader.ReadFile(ctx, path)
			if err != nil {
				return nil
			}
			results := m.parseConfig(path, data)
			for _, f := range results {
				if f == nil {
					continue
				}
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

// isSecretsMgrConfigFile matches secrets manager config files.
func isSecretsMgrConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Vault HCL/JSON configs — match /vault/ or /vault.d/ in path,
	// or vault*.hcl basename. Excludes "keyvault" (Azure).
	if (strings.Contains(lower, "/vault/") || strings.Contains(lower, "/vault.d/") ||
		strings.HasPrefix(base, "vault")) &&
		(strings.HasSuffix(base, ".hcl") || strings.HasSuffix(base, ".json")) {
		return true
	}

	// AWS config
	if strings.Contains(lower, ".aws/") && base == "config" {
		return true
	}
	if strings.Contains(lower, "/aws/") && base == "config" {
		return true
	}

	// Azure Key Vault configs
	if strings.Contains(lower, "/azure/") && strings.Contains(lower, "keyvault") &&
		(strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".yaml")) {
		return true
	}

	// SOPS config
	if base == ".sops.yaml" || base == ".sops.yml" {
		return true
	}

	// SOPS age key files
	if strings.Contains(lower, "/sops/") && strings.Contains(lower, "/age/") {
		return true
	}

	return false
}

// parseConfig dispatches to the right sub-parser.
func (m *SecretsMgrModule) parseConfig(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "/vault/") || strings.Contains(lower, "/vault.d/") || strings.HasPrefix(base, "vault"):
		return m.parseVaultConfig(path, data)
	case base == ".sops.yaml" || base == ".sops.yml":
		return m.parseSOPSConfig(path, data)
	case strings.Contains(lower, ".aws/") || (strings.Contains(lower, "/aws/") && base == "config"):
		return m.parseAWSConfig(path, data)
	case strings.Contains(lower, "/azure/") && strings.Contains(lower, "keyvault"):
		return m.parseAzureKVConfig(path, data)
	case strings.Contains(lower, "/sops/") && strings.Contains(lower, "/age/"):
		return m.parseSOPSAgeKeys(path, data)
	}
	return nil
}

// --- Vault ---

// vaultSealTypes maps Vault seal stanza names to their crypto backend descriptions.
var vaultSealTypes = map[string]struct {
	function  string
	algorithm string
}{
	"transit":       {"Vault auto-unseal (transit)", "AES-256-GCM"},
	"awskms":        {"Vault auto-unseal (awskms)", "AWS-KMS"},
	"gcpckms":       {"Vault auto-unseal (gcpckms)", "GCP-Cloud-KMS"},
	"azurekeyvault": {"Vault auto-unseal (azurekeyvault)", "Azure-Key-Vault"},
	"pkcs11":        {"Vault auto-unseal (pkcs11)", "PKCS#11"},
	"ocikms":        {"Vault auto-unseal (ocikms)", "OCI-KMS"},
}

// parseVaultConfig extracts seal stanzas and TLS listener config from Vault HCL.
// This is a line-oriented heuristic parser — not a full HCL parser —
// sufficient for extracting the crypto-relevant stanzas.
func (m *SecretsMgrModule) parseVaultConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "vault", sc.Err()) }()

	base := filepath.Base(path)
	hasTLSCert := false
	hasTLSDisable := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Seal stanzas: seal "type" {
		if strings.HasPrefix(line, "seal") {
			for sealType, info := range vaultSealTypes {
				if strings.Contains(line, `"`+sealType+`"`) {
					out = append(out, m.secretsMgrFinding(path, info.function, info.algorithm,
						fmt.Sprintf("Vault seal %s in %s", sealType, base)))
				}
			}
		}

		// TLS cert presence
		if strings.Contains(line, "tls_cert_file") {
			hasTLSCert = true
		}

		// TLS disabled
		if strings.Contains(line, "tls_disable") {
			val := extractHCLValue(line)
			if val == "1" || val == "true" || val == `"1"` || val == `"true"` {
				hasTLSDisable = true
			}
		}
	}

	if hasTLSDisable {
		out = append(out, m.secretsMgrFinding(path, "Vault TLS disabled", "plaintext",
			fmt.Sprintf("Vault tls_disable in %s", base)))
	} else if hasTLSCert {
		out = append(out, m.secretsMgrFinding(path, "Vault TLS listener", "TLS",
			fmt.Sprintf("Vault TLS listener in %s", base)))
	}

	return out
}

// extractHCLValue extracts the value from a simple HCL assignment like
// `key = value` or `key = "value"`.
func extractHCLValue(line string) string {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return ""
	}
	val := strings.TrimSpace(line[eq+1:])
	val = strings.Trim(val, `"`)
	return val
}

// --- SOPS ---

// parseSOPSConfig extracts encryption key references from .sops.yaml.
// Line-oriented heuristic — looks for age:, kms:, pgp:, gcp_kms:,
// azure_keyvault: keys.
func (m *SecretsMgrModule) parseSOPSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "sops", sc.Err()) }()

	base := filepath.Base(path)
	// Track which key types we've seen to avoid duplicates
	seen := make(map[string]bool)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for _, spec := range []struct {
			prefix    string
			function  string
			algorithm string
		}{
			{"age:", "SOPS age encryption", "X25519"},
			{"kms:", "SOPS AWS KMS encryption", "AWS-KMS"},
			{"gcp_kms:", "SOPS GCP KMS encryption", "GCP-Cloud-KMS"},
			{"azure_kv:", "SOPS Azure Key Vault encryption", "Azure-Key-Vault"},
			{"pgp:", "SOPS PGP encryption", "PGP"},
			{"hc_vault_transit_uri:", "SOPS Vault transit encryption", "AES-256-GCM"},
		} {
			if strings.HasPrefix(line, spec.prefix) {
				if !seen[spec.function] {
					seen[spec.function] = true
					out = append(out, m.secretsMgrFinding(path, spec.function, spec.algorithm,
						fmt.Sprintf("SOPS %s in %s", spec.prefix, base)))
				}
			}
		}
	}
	return out
}

// --- AWS ---

// parseAWSConfig looks for kms_key_id references in AWS CLI config.
func (m *SecretsMgrModule) parseAWSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "aws", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "kms_key_id") {
			out = append(out, m.secretsMgrFinding(path, "AWS KMS key reference", "AWS-KMS",
				fmt.Sprintf("AWS kms_key_id in %s", base)))
		}
	}
	return out
}

// --- Azure Key Vault ---

// parseAzureKVConfig detects Azure Key Vault configuration references.
func (m *SecretsMgrModule) parseAzureKVConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "azure-kv", sc.Err()) }()

	base := filepath.Base(path)
	hasVaultURL := false
	hasKeyName := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vault.azure.net") || strings.Contains(lower, "vault-url") || strings.Contains(lower, "vaulturl") {
			hasVaultURL = true
		}
		if strings.Contains(lower, "key-name") || strings.Contains(lower, "keyname") || strings.Contains(lower, "key_name") {
			hasKeyName = true
		}
	}

	if hasVaultURL {
		out = append(out, m.secretsMgrFinding(path, "Azure Key Vault reference", "Azure-Key-Vault",
			fmt.Sprintf("Azure KV endpoint in %s", base)))
	}
	if hasKeyName {
		out = append(out, m.secretsMgrFinding(path, "Azure Key Vault key reference", "Azure-Key-Vault",
			fmt.Sprintf("Azure KV key-name in %s", base)))
	}
	return out
}

// --- SOPS age key files ---

// parseSOPSAgeKeys detects age key files used by SOPS for encryption.
// Age uses X25519 for key exchange and ChaCha20-Poly1305 for encryption.
func (m *SecretsMgrModule) parseSOPSAgeKeys(path string, data []byte) []*model.Finding {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "sops-age", sc.Err()) }()
	hasKey := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// age secret keys start with AGE-SECRET-KEY-
		// age public keys start with age1
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") || strings.HasPrefix(line, "age1") {
			hasKey = true
			break
		}
	}
	if !hasKey {
		return nil
	}
	return []*model.Finding{m.secretsMgrFinding(path, "SOPS age key file", "X25519",
		fmt.Sprintf("age key in %s", filepath.Base(path)))}
}

// --- finding builder ---

func (m *SecretsMgrModule) secretsMgrFinding(path, function, algorithm, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algorithm

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceHigh,
		Module:      "secrets_mgr",
		Timestamp:   time.Now(),
	}
}
