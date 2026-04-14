package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

// sshKeyPrefixes maps SSH public key type prefixes to algorithms.
var sshKeyPrefixes = []struct {
	prefix    string
	algorithm string
	keySize   int
}{
	{"ssh-rsa", "RSA", 0}, // key size varies
	{"ssh-ed25519", "Ed25519", 256},
	{"ecdsa-sha2-nistp256", "ECDSA-P256", 256},
	{"ecdsa-sha2-nistp384", "ECDSA-P384", 384},
	{"ecdsa-sha2-nistp521", "ECDSA-P521", 521},
	{"ssh-dss", "DSA", 0},
}

type KeyModule struct {
	config      *scannerconfig.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
}

func (m *KeyModule) SetStore(s store.Store) { m.store = s }

func NewKeyModule(cfg *scannerconfig.Config) *KeyModule {
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

func (m *KeyModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *KeyModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    m.isKeyFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			finding, err := m.parseKeyFile(ctx, reader, path)
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
		base == "id_ed25519.pub" || base == "authorized_keys" || base == "known_hosts" {
		return true
	}

	// SSH server host keys live in /etc/ssh/ on Linux/macOS and
	// have no extension on the private side, so the extension
	// matcher above misses them. Sprint A2 — close the host-key
	// blind spot. Same parser handles them; only the matcher
	// changed. Pattern: ssh_host_<algo>_key[.pub]
	if strings.HasPrefix(base, "ssh_host_") &&
		(strings.HasSuffix(base, "_key") || strings.HasSuffix(base, "_key.pub")) {
		return true
	}

	// Match files with "private_key" or "public_key" in name (compound pattern)
	if strings.Contains(lower, "private_key") || strings.Contains(lower, "public_key") {
		return true
	}

	return false
}

// parseKeyFile reads a file and produces a finding only if it contains a recognized
// key PEM header or SSH public key format. Returns (nil, nil) if no key content found.
func (m *KeyModule) parseKeyFile(ctx context.Context, reader fsadapter.FileReader, path string) (*model.Finding, error) {
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// Try PEM-based key detection first
	keyType, algorithm, keySize := m.detectPEMKey(data, content)

	// If no PEM key found, try SSH public key format
	if keyType == "" {
		keyType, algorithm, keySize = m.detectSSHPublicKey(content)
	}

	if keyType == "" {
		return nil, nil
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  keyType,
		Algorithm: algorithm,
		KeySize:   keySize,
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "keys",
		Timestamp:   time.Now(),
	}, nil
}

// detectPEMKey detects key type and algorithm from PEM content.
// For PKCS#8 keys, it parses the DER to identify the actual algorithm.
func (m *KeyModule) detectPEMKey(data []byte, content string) (keyType, algorithm string, keySize int) {
	keyType, algorithm = m.detectKeyTypeAndAlgorithm(content)
	if keyType == "" {
		return "", "", 0
	}

	// For PKCS#8 private keys, parse the DER to determine the actual algorithm
	if keyType == "pkcs8-private" {
		block, _ := pem.Decode(data)
		if block != nil {
			algo, size := m.parsePKCS8Algorithm(block.Bytes)
			if algo != "" {
				algorithm = algo
				keySize = size
			}
		}
	}

	// For standard PEM private keys, try to extract key size
	if keySize == 0 {
		block, _ := pem.Decode(data)
		if block != nil {
			keySize = m.extractPEMKeySize(block, keyType)
		}
	}

	// For public keys, try to parse and extract algorithm/size
	if keyType == "public" {
		block, _ := pem.Decode(data)
		if block != nil {
			algo, size := m.parsePublicKeyAlgorithm(block.Bytes)
			if algo != "" {
				algorithm = algo
				keySize = size
			}
		}
	}

	return keyType, algorithm, keySize
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

// parsePKCS8Algorithm parses a PKCS#8 DER-encoded private key to determine the algorithm.
func (m *KeyModule) parsePKCS8Algorithm(derBytes []byte) (algorithm string, keySize int) {
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return "", 0
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		return "ECDSA-P" + strconv.Itoa(k.Curve.Params().BitSize), k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		return "Ed25519", 256
	default:
		return "", 0
	}
}

// parsePublicKeyAlgorithm parses a DER-encoded public key to determine algorithm and size.
func (m *KeyModule) parsePublicKeyAlgorithm(derBytes []byte) (algorithm string, keySize int) {
	key, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return "", 0
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA-P" + strconv.Itoa(k.Curve.Params().BitSize), k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "", 0
	}
}

// extractPEMKeySize tries to parse standard PEM key formats to extract key size.
func (m *KeyModule) extractPEMKeySize(block *pem.Block, keyType string) int {
	switch keyType {
	case "rsa-private":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key.N.BitLen()
		}
	case "ec-private":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			return key.Curve.Params().BitSize
		}
	case "rsa-public":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err == nil {
			return key.N.BitLen()
		}
	}
	return 0
}

// detectSSHPublicKey detects SSH public key format (ssh-rsa, ssh-ed25519, etc.)
func (m *KeyModule) detectSSHPublicKey(content string) (keyType, algorithm string, keySize int) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for _, prefix := range sshKeyPrefixes {
			if strings.HasPrefix(line, prefix.prefix+" ") {
				return "ssh-public", prefix.algorithm, prefix.keySize
			}
		}
	}
	return "", "", 0
}
