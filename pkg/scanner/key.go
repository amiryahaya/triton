package scanner

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
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
	reader      fsadapter.FileReader
}

func (m *KeyModule) SetStore(s store.Store)               { m.store = s }
func (m *KeyModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

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
		reader:       m.reader,
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

	// Check for encrypted keys first — report even though we can't parse contents.
	if finding := m.detectEncryptedKeyFinding(data, content, path); finding != nil {
		return finding, nil
	}

	// Try PEM-based key detection first
	keyType, algorithm, keySize, pubKey := m.detectPEMKey(data, content)

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

	// Key-quality audit. Non-blocking: warnings are informational.
	if pubKey != nil {
		ws := keyquality.Analyze(pubKey, asset.Algorithm, asset.KeySize)
		if len(ws) > 0 {
			asset.QualityWarnings = keyquality.ToModel(ws)
		}
	}

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
// The returned pub is the parsed crypto.PublicKey (nil if not extractable).
func (m *KeyModule) detectPEMKey(data []byte, content string) (keyType, algorithm string, keySize int, pub stdcrypto.PublicKey) {
	keyType, algorithm = m.detectKeyTypeAndAlgorithm(content)
	if keyType == "" {
		return "", "", 0, nil
	}

	// For PKCS#8 private keys, parse the DER to determine the actual algorithm
	if keyType == "pkcs8-private" {
		block, _ := pem.Decode(data)
		if block != nil {
			algo, size, p := m.parsePKCS8Algorithm(block.Bytes)
			if algo != "" {
				algorithm = algo
				keySize = size
				pub = p
			}
		}
	}

	// For standard PEM private keys, try to extract key size + public key
	if keySize == 0 {
		block, _ := pem.Decode(data)
		if block != nil {
			size, p := m.extractPEMKeyInfo(block, keyType)
			keySize = size
			if pub == nil {
				pub = p
			}
		}
	}

	// For public keys, try to parse and extract algorithm/size
	if keyType == "public" {
		block, _ := pem.Decode(data)
		if block != nil {
			algo, size, p := m.parsePublicKeyAlgorithm(block.Bytes)
			if algo != "" {
				algorithm = algo
				keySize = size
				pub = p
			}
		}
	}

	return keyType, algorithm, keySize, pub
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
func (m *KeyModule) parsePKCS8Algorithm(derBytes []byte) (algorithm string, keySize int, pub stdcrypto.PublicKey) {
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return "", 0, nil
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", k.N.BitLen(), &k.PublicKey
	case *ecdsa.PrivateKey:
		return "ECDSA-P" + strconv.Itoa(k.Curve.Params().BitSize), k.Curve.Params().BitSize, &k.PublicKey
	case ed25519.PrivateKey:
		return "Ed25519", 256, k.Public()
	default:
		return "", 0, nil
	}
}

// parsePublicKeyAlgorithm parses a DER-encoded public key to determine algorithm and size.
func (m *KeyModule) parsePublicKeyAlgorithm(derBytes []byte) (algorithm string, keySize int, pub stdcrypto.PublicKey) {
	key, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return "", 0, nil
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), k
	case *ecdsa.PublicKey:
		return "ECDSA-P" + strconv.Itoa(k.Curve.Params().BitSize), k.Curve.Params().BitSize, k
	case ed25519.PublicKey:
		return "Ed25519", 256, k
	default:
		return "", 0, nil
	}
}

// extractPEMKeyInfo tries to parse standard PEM key formats to extract key size
// and the public key (nil if not extractable).
func (m *KeyModule) extractPEMKeyInfo(block *pem.Block, keyType string) (int, stdcrypto.PublicKey) {
	switch keyType {
	case "rsa-private":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key.N.BitLen(), &key.PublicKey
		}
	case "ec-private":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			return key.Curve.Params().BitSize, &key.PublicKey
		}
	case "rsa-public":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err == nil {
			return key.N.BitLen(), key
		}
	}
	return 0, nil
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

// opensshKeyMagic is the 15-byte null-terminated magic string at the start
// of every OpenSSH private key blob (RFC draft-miller-ssh-agent).
const opensshKeyMagic = "openssh-key-v1\x00"

// detectEncryptedKeyFinding inspects raw key file bytes and PEM content to
// identify password-protected private keys that cannot be parsed in plaintext.
// It recognises three formats:
//
//  1. RFC 1423 / OpenSSL legacy: BEGIN RSA/EC/DSA PRIVATE KEY with
//     Proc-Type: 4,ENCRYPTED + DEK-Info: <cipher>,<iv> headers.
//  2. PKCS#8 encrypted wrapper: BEGIN ENCRYPTED PRIVATE KEY.
//  3. OpenSSH private key with a cipher other than "none".
//
// Returns a *model.Finding ready to emit, or nil if the file is not a
// recognisably-encrypted private key (falls through to normal parsing).
func (m *KeyModule) detectEncryptedKeyFinding(data []byte, _, path string) *model.Finding {
	block, _ := pem.Decode(data)

	// ── 1. RFC 1423 legacy encrypted PEM (Proc-Type / DEK-Info headers) ──
	if block != nil && block.Headers != nil {
		if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			cipher := ""
			if dekInfo, ok := block.Headers["DEK-Info"]; ok {
				if idx := strings.Index(dekInfo, ","); idx != -1 {
					cipher = dekInfo[:idx]
				} else {
					cipher = dekInfo
				}
			}
			// Determine algorithm from PEM block type.
			algo := "Unknown"
			switch block.Type {
			case "RSA PRIVATE KEY":
				algo = "RSA"
			case "EC PRIVATE KEY":
				algo = "ECDSA"
			case "DSA PRIVATE KEY":
				algo = "DSA"
			}
			purpose := "encrypted private key"
			if cipher != "" {
				purpose = fmt.Sprintf("encrypted private key (%s)", cipher)
			}
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  "encrypted-private",
				Algorithm: algo,
				KeySize:   0,
				Purpose:   purpose,
			}
			crypto.ClassifyCryptoAsset(asset)
			return &model.Finding{
				ID:          uuid.Must(uuid.NewV7()).String(),
				Category:    5,
				Source:      model.FindingSource{Type: "file", Path: path},
				CryptoAsset: asset,
				Confidence:  0.85,
				Module:      "keys",
				Timestamp:   time.Now(),
			}
		}
	}

	// ── 2. PKCS#8 encrypted wrapper ──
	if block != nil && block.Type == "ENCRYPTED PRIVATE KEY" {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "encrypted-private (PKCS#8)",
			Algorithm: "Unknown",
			KeySize:   0,
			Purpose:   "encrypted private key (PKCS#8)",
		}
		crypto.ClassifyCryptoAsset(asset)
		return &model.Finding{
			ID:          uuid.Must(uuid.NewV7()).String(),
			Category:    5,
			Source:      model.FindingSource{Type: "file", Path: path},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      "keys",
			Timestamp:   time.Now(),
		}
	}

	// ── 3. OpenSSH private key — check embedded cipher field ──
	if block != nil && block.Type == "OPENSSH PRIVATE KEY" {
		cipher := detectOpenSSHCipher(block.Bytes)
		if cipher != "" && cipher != "none" {
			purpose := fmt.Sprintf("encrypted private key (OpenSSH, %s)", cipher)
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  "encrypted-private",
				Algorithm: "Unknown",
				KeySize:   0,
				Purpose:   purpose,
			}
			crypto.ClassifyCryptoAsset(asset)
			return &model.Finding{
				ID:          uuid.Must(uuid.NewV7()).String(),
				Category:    5,
				Source:      model.FindingSource{Type: "file", Path: path},
				CryptoAsset: asset,
				Confidence:  0.85,
				Module:      "keys",
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// detectOpenSSHCipher parses the raw DER bytes of an OpenSSH private key block
// (after PEM decode) to extract the cipher name string. The format starts with
// the 15-byte magic "openssh-key-v1\x00" followed by a length-prefixed string
// for the cipher name. Returns "" if the blob is too short or malformed.
func detectOpenSSHCipher(der []byte) string {
	magic := []byte(opensshKeyMagic)
	if len(der) < len(magic)+4 {
		return ""
	}
	if !bytes.Equal(der[:len(magic)], magic) {
		return ""
	}
	offset := len(magic)
	rawLen := binary.BigEndian.Uint32(der[offset : offset+4])
	offset += 4
	// Guard against overflow on 32-bit platforms and unreasonably long names.
	if rawLen > 64 || offset+int(rawLen) > len(der) {
		return ""
	}
	return string(der[offset : offset+int(rawLen)])
}
