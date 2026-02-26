package scanner

import (
	"bytes"
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

// Binary magic bytes for executable detection
var (
	elfMagic   = []byte{0x7f, 'E', 'L', 'F'}
	machoMagic = []byte{0xCF, 0xFA, 0xED, 0xFE} // 64-bit Mach-O
	machoCigam = []byte{0xFE, 0xED, 0xFA, 0xCF} // 64-bit Mach-O (reverse)
	macho32    = []byte{0xCE, 0xFA, 0xED, 0xFE} // 32-bit Mach-O
	machoFat   = []byte{0xCA, 0xFE, 0xBA, 0xBE} // Universal binary
)

// cryptoPatterns defines regex patterns for detecting crypto algorithm usage in binaries.
var cryptoPatterns = []struct {
	pattern   *regexp.Regexp
	algorithm string
	family    string
}{
	{regexp.MustCompile(`AES[-_]?(128|192|256)[-_]?(GCM|CBC|CTR|CCM|ECB)?`), "AES", "AES"},
	{regexp.MustCompile(`DES[-_]?(EDE3|CBC|ECB)`), "3DES", "DES"},
	{regexp.MustCompile(`\bTriple.?DES\b`), "3DES", "DES"},
	{regexp.MustCompile(`RSA[-_]?(1024|2048|3072|4096|8192)`), "RSA", "RSA"},
	{regexp.MustCompile(`ECDSA[-_]?(P[-_]?256|P[-_]?384|P[-_]?521)`), "ECDSA", "ECDSA"},
	{regexp.MustCompile(`\bEd25519\b`), "Ed25519", "EdDSA"},
	{regexp.MustCompile(`\bEd448\b`), "Ed448", "EdDSA"},
	{regexp.MustCompile(`SHA[-_]?(1|224|256|384|512)\b`), "SHA", "SHA"},
	{regexp.MustCompile(`SHA3[-_]?(224|256|384|512)`), "SHA3", "SHA3"},
	{regexp.MustCompile(`\bMD5\b`), "MD5", "MD5"},
	{regexp.MustCompile(`\bMD4\b`), "MD4", "MD4"},
	{regexp.MustCompile(`\bRC4\b`), "RC4", "RC4"},
	{regexp.MustCompile(`ChaCha20[-_]?Poly1305`), "ChaCha20-Poly1305", "ChaCha"},
	{regexp.MustCompile(`\bBlowfish\b`), "Blowfish", "Blowfish"},
	{regexp.MustCompile(`\bCamellia[-_]?(128|256)\b`), "Camellia", "Camellia"},
	{regexp.MustCompile(`ML[-_]?KEM`), "ML-KEM", "Lattice"},
	{regexp.MustCompile(`ML[-_]?DSA`), "ML-DSA", "Lattice"},
	{regexp.MustCompile(`CRYSTALS[-_]?Kyber`), "ML-KEM", "Lattice"},
	{regexp.MustCompile(`CRYSTALS[-_]?Dilithium`), "ML-DSA", "Lattice"},
	{regexp.MustCompile(`TLS[-_]?1[._]([0123])`), "TLS", "TLS"},
	{regexp.MustCompile(`SSLv[23]`), "SSLv2/3", "SSL"},
}

// maxBinaryReadSize limits how much of each binary we read for strings analysis.
const maxBinaryReadSize = 1 * 1024 * 1024 // 1MB

// BinaryModule scans executable files on disk for crypto algorithm patterns.
type BinaryModule struct {
	config *config.Config
}

func NewBinaryModule(cfg *config.Config) *BinaryModule {
	return &BinaryModule{config: cfg}
}

func (m *BinaryModule) Name() string {
	return "binaries"
}

func (m *BinaryModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *BinaryModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *BinaryModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isBinaryFile,
		processFile: func(path string) error {
			found, err := m.scanBinaryFile(path)
			if err != nil {
				return nil // Skip errors
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

// isBinaryFile is a lightweight pre-filter that skips files with known non-binary
// extensions. The actual magic byte check happens in scanBinaryFile to avoid
// opening each file twice.
func (m *BinaryModule) isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt", ".md", ".json", ".xml", ".html", ".htm", ".css", ".js", ".ts",
		".py", ".go", ".java", ".c", ".h", ".cpp", ".hpp", ".rs", ".rb", ".pl",
		".sh", ".bash", ".zsh", ".fish", ".bat", ".ps1",
		".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".env",
		".log", ".csv", ".tsv", ".sql",
		".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx", ".jks",
		".so", ".dylib", ".dll", ".ko",
		".gz", ".xz", ".zst", ".zip", ".tar", ".bz2", ".7z", ".rar",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mkv", ".wav", ".flac",
		".git", ".lock", ".sum", ".mod":
		return false
	}
	return true
}

// isExecutableMagic checks if the first 4 bytes match known executable formats.
func isExecutableMagic(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	return bytes.Equal(magic[:4], elfMagic) ||
		bytes.Equal(magic[:4], machoMagic) ||
		bytes.Equal(magic[:4], machoCigam) ||
		bytes.Equal(magic[:4], macho32) ||
		bytes.Equal(magic[:4], machoFat)
}

// scanBinaryFile reads a binary file, verifies magic bytes, and looks for crypto-related strings.
func (m *BinaryModule) scanBinaryFile(path string) ([]*model.Finding, error) {
	data, err := m.readBinaryHead(path)
	if err != nil {
		return nil, err
	}

	// Verify executable magic bytes (authoritative check)
	if len(data) < 4 || !isExecutableMagic(data[:4]) {
		return nil, nil
	}

	// Extract printable strings from binary
	printable := extractPrintableStrings(data, 4)

	// Match crypto patterns against extracted strings
	found := m.matchCryptoPatterns(path, printable)

	return found, nil
}

// readBinaryHead reads the first maxBinaryReadSize bytes of a binary file.
func (m *BinaryModule) readBinaryHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := info.Size()
	if size > int64(maxBinaryReadSize) {
		size = int64(maxBinaryReadSize)
	}

	buf := make([]byte, size)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// extractPrintableStrings extracts runs of printable ASCII characters from binary data.
func extractPrintableStrings(data []byte, minLen int) string {
	var result strings.Builder
	var current strings.Builder

	for _, b := range data {
		if b >= 32 && b < 127 {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				result.WriteString(current.String())
				result.WriteByte(' ')
			}
			current.Reset()
		}
	}

	if current.Len() >= minLen {
		result.WriteString(current.String())
	}

	return result.String()
}

// matchCryptoPatterns finds crypto algorithm references in extracted strings.
func (m *BinaryModule) matchCryptoPatterns(path, content string) []*model.Finding {
	seen := make(map[string]bool)
	var findings []*model.Finding

	for _, cp := range cryptoPatterns {
		matches := cp.pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Deduplicate by algorithm match
			key := cp.family + ":" + match
			if seen[key] {
				continue
			}
			seen[key] = true

			algoName := buildAlgorithmName(cp.algorithm, match)

			asset := &model.CryptoAsset{
				ID:        uuid.New().String(),
				Function:  "Binary crypto reference",
				Algorithm: algoName,
				Purpose:   "Detected in executable binary",
			}
			crypto.ClassifyCryptoAsset(asset)

			findings = append(findings, &model.Finding{
				ID:       uuid.New().String(),
				Category: 2,
				Source: model.FindingSource{
					Type: "file",
					Path: path,
				},
				CryptoAsset: asset,
				Confidence:  0.60,
				Module:      "binaries",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// buildAlgorithmName creates a canonical algorithm name from the pattern match.
func buildAlgorithmName(baseAlgo, match string) string {
	// For specific matches like "AES-256-GCM", use the match directly
	match = strings.ReplaceAll(match, "_", "-")
	if len(match) > len(baseAlgo) {
		return match
	}
	return baseAlgo
}

// ExtractPrintableStrings is exported for reuse by kernel module scanner.
func ExtractPrintableStrings(data []byte, minLen int) string {
	return extractPrintableStrings(data, minLen)
}

// MatchCryptoInStrings matches crypto patterns in a string, returning algorithm names found.
func MatchCryptoInStrings(content string) []string {
	seen := make(map[string]bool)
	var algos []string

	for _, cp := range cryptoPatterns {
		matches := cp.pattern.FindAllString(content, -1)
		for _, match := range matches {
			key := cp.family + ":" + match
			if !seen[key] {
				seen[key] = true
				algos = append(algos, buildAlgorithmName(cp.algorithm, match))
			}
		}
	}
	return algos
}
