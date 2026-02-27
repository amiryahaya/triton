package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// ContainerModule scans container configuration files (Dockerfiles, docker-compose,
// Kubernetes manifests) for cryptographic references and insecure configurations.
type ContainerModule struct {
	config      *config.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
}

func NewContainerModule(cfg *config.Config) *ContainerModule {
	return &ContainerModule{config: cfg}
}

func (m *ContainerModule) Name() string                         { return "containers" }
func (m *ContainerModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *ContainerModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *ContainerModule) SetStore(s store.Store)               { m.store = s }
func (m *ContainerModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// containerFilePatterns matches container-related configuration files.
var containerFilePatterns = []string{
	"Dockerfile",
	"Dockerfile.*",
	"docker-compose.yml",
	"docker-compose.yaml",
	"compose.yml",
	"compose.yaml",
	"*.dockerfile",
}

// containerCryptoPatterns detects cryptographic references in container configs.
var containerCryptoPatterns = []*regexp.Regexp{
	// TLS/SSL related
	regexp.MustCompile(`(?i)(ssl_protocols?\s+[^;]+)`),
	regexp.MustCompile(`(?i)(ssl_ciphers?\s+[^;]+)`),
	regexp.MustCompile(`(?i)(tls_version|TLS_VERSION|PROTOCOL_TLS)[=:\s]+([^\s;]+)`),

	// Certificate mounts/copies
	regexp.MustCompile(`(?i)(COPY|ADD)\s+.*\.(pem|crt|cer|key|p12|pfx)\b`),
	regexp.MustCompile(`(?i)volumes?:.*\.(pem|crt|cer|key)\b`),

	// Environment variables with crypto config
	regexp.MustCompile(`(?i)(SSL_CERT|TLS_CERT|CERT_FILE|KEY_FILE|CA_FILE)[=:\s]+\S+`),

	// Algorithm mentions in env/commands
	regexp.MustCompile(`(?i)(openssl|keytool|certutil)\s+.*(rsa|ecdsa|ed25519|aes|des|sha|md5)`),
	regexp.MustCompile(`(?i)(ENCRYPTION_ALGORITHM|CIPHER_SUITE|KEY_ALGORITHM)[=:\s]+(\S+)`),

	// Insecure protocol settings
	regexp.MustCompile(`(?i)(SSLv[23]|TLSv1\.0|TLSv1\.1)\b`),
}

// matchAlgoEntries maps substrings to algorithm names, ordered longest-first
// to prevent shorter matches shadowing longer ones (e.g. "sha" vs "sha256").
type algoEntry struct {
	key  string
	algo string
}

var matchAlgoEntries = []algoEntry{
	{"sha512", "SHA-512"},
	{"sha384", "SHA-384"},
	{"sha256", "SHA-256"},
	{"sha1", "SHA-1"},
	{"sslv2", "SSLv2"},
	{"sslv3", "SSLv3"},
	{"tlsv1.0", "TLS-1.0"},
	{"tlsv1.1", "TLS-1.1"},
	{"ed25519", "Ed25519"},
	{"ecdsa", "ECDSA"},
	{"3des", "3DES"},
	{"rsa", "RSA"},
	{"aes", "AES"},
	{"des", "DES"},
	{"md5", "MD5"},
}

func (m *ContainerModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	var scanned, matched int64

	wc := walkerConfig{
		target:       target,
		config:       m.config,
		filesScanned: &scanned,
		filesMatched: &matched,
		store:        m.store,
		matchFile:    isContainerFile,
		processFile: func(path string) error {
			return m.processContainerFile(ctx, path, findings)
		},
	}

	err := walkTarget(wc)
	atomic.StoreInt64(&m.lastScanned, scanned)
	atomic.StoreInt64(&m.lastMatched, matched)
	return err
}

func isContainerFile(path string) bool {
	base := filepath.Base(path)
	baseLower := strings.ToLower(base)

	for _, pat := range containerFilePatterns {
		matched, err := filepath.Match(strings.ToLower(pat), baseLower)
		if err == nil && matched {
			return true
		}
	}

	// Also check kubernetes YAML files for crypto references
	if strings.HasSuffix(baseLower, ".yaml") || strings.HasSuffix(baseLower, ".yml") {
		dir := strings.ToLower(filepath.Dir(path))
		if strings.Contains(dir, "k8s") || strings.Contains(dir, "kubernetes") ||
			strings.Contains(dir, "kube") || strings.Contains(dir, "helm") {
			return true
		}
	}

	return false
}

func (m *ContainerModule) processContainerFile(ctx context.Context, path string, findings chan<- *model.Finding) error {
	f, err := os.Open(path)
	if err != nil {
		return nil // Skip unreadable files
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		for _, pat := range containerCryptoPatterns {
			matches := pat.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}

			matchStr := strings.ToLower(strings.Join(matches, " "))
			algo := extractAlgorithm(matchStr)
			if algo == "" {
				algo = "TLS" // Default for generic SSL/TLS references
			}

			asset := &model.CryptoAsset{
				ID:        uuid.New().String(),
				Function:  "Container configuration",
				Algorithm: algo,
				Purpose:   strings.TrimSpace(matches[0]),
			}
			crypto.ClassifyCryptoAsset(asset)

			finding := &model.Finding{
				ID:       uuid.New().String(),
				Category: 8, // Container/configuration
				Source: model.FindingSource{
					Type:            "file",
					Path:            path,
					DetectionMethod: "configuration",
				},
				CryptoAsset: asset,
				Confidence:  0.70,
				Module:      "containers",
				Timestamp:   time.Now(),
			}

			select {
			case findings <- finding:
			case <-ctx.Done():
				return ctx.Err()
			}

			break // One finding per line
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// extractAlgorithm identifies the specific algorithm from a match string.
// Uses longest-match-first ordering to avoid ambiguity (e.g. "sha" vs "sha256").
func extractAlgorithm(matchStr string) string {
	lower := strings.ToLower(matchStr)
	for _, entry := range matchAlgoEntries {
		if strings.Contains(lower, entry.key) {
			return entry.algo
		}
	}
	return ""
}
