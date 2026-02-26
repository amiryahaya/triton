package scanner

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
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
	peMagic    = []byte{0x4D, 0x5A}              // MZ header (PE/COFF)
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

	// New patterns
	{regexp.MustCompile(`\bHMAC[-_]?(SHA256|SHA512|SHA1|MD5)\b`), "HMAC", "HMAC"},
	{regexp.MustCompile(`\bPBKDF2\b`), "PBKDF2", "KDF"},
	{regexp.MustCompile(`\bscrypt\b`), "scrypt", "KDF"},
	{regexp.MustCompile(`\b[Aa]rgon2(id?|d|i)?\b`), "Argon2", "KDF"},
	{regexp.MustCompile(`\bHKDF\b`), "HKDF", "KDF"},
	{regexp.MustCompile(`\b[Bb]crypt\b`), "Bcrypt", "Password-Hash"},
	{regexp.MustCompile(`\bX25519\b`), "X25519", "ECDH"},
	{regexp.MustCompile(`\bX448\b`), "X448", "ECDH"},
	{regexp.MustCompile(`\bFALCON\b`), "FALCON", "Lattice"},
	{regexp.MustCompile(`SPHINCS\+`), "SPHINCS+", "Hash-Based"},
	{regexp.MustCompile(`SLH[-_]?DSA`), "SLH-DSA", "Hash-Based"},
}

// maxBinaryReadSize limits how much of each binary we read for strings analysis.
const maxBinaryReadSize = 1 * 1024 * 1024 // 1MB

// cryptoLibTable maps library name substrings to canonical crypto library names.
var cryptoLibTable = []struct {
	substring string
	library   string
	state     string // Primary state signal: IN_TRANSIT, AT_REST, IN_USE, or ""
}{
	{"libssl", "OpenSSL", "IN_TRANSIT"},
	{"libcrypto", "OpenSSL", "IN_USE"},
	{"boringssl", "BoringSSL", "IN_TRANSIT"},
	{"libgnutls", "GnuTLS", "IN_TRANSIT"},
	{"libnss", "NSS", "IN_TRANSIT"},
	{"libsodium", "libsodium", "IN_USE"},
	{"libwolfssl", "wolfSSL", "IN_TRANSIT"},
	{"libmbedtls", "mbedTLS", "IN_TRANSIT"},
	{"libmbedcrypto", "mbedTLS", "IN_USE"},
	{"libgcrypt", "libgcrypt", "IN_USE"},
	{"libsqlcipher", "SQLCipher", "AT_REST"},
	{"Security.framework", "Apple Security", "IN_USE"},
	{"bcrypt.dll", "Windows CNG", "IN_USE"},
	{"ncrypt.dll", "Windows CNG", "IN_USE"},
	{"crypt32.dll", "Windows CAPI", "IN_USE"},
}

// stateSymbols maps symbol/function substrings to crypto state.
var stateSymbols = []struct {
	substring string
	state     string
}{
	{"SSL_connect", "IN_TRANSIT"},
	{"SSL_accept", "IN_TRANSIT"},
	{"SSL_read", "IN_TRANSIT"},
	{"SSL_write", "IN_TRANSIT"},
	{"SSL_CTX_new", "IN_TRANSIT"},
	{"tls_connect", "IN_TRANSIT"},
	{"EVP_SignFinal", "IN_USE"},
	{"EVP_VerifyFinal", "IN_USE"},
	{"EVP_DigestSign", "IN_USE"},
	{"EVP_DigestVerify", "IN_USE"},
	{"EVP_EncryptInit", "AT_REST"},
	{"EVP_DecryptInit", "AT_REST"},
}

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

// isExecutableMagic checks if the first bytes match known executable formats.
func isExecutableMagic(magic []byte) bool {
	if len(magic) < 2 {
		return false
	}
	// PE check (2-byte MZ header)
	if bytes.Equal(magic[:2], peMagic) {
		return true
	}
	if len(magic) < 4 {
		return false
	}
	return bytes.Equal(magic[:4], elfMagic) ||
		bytes.Equal(magic[:4], machoMagic) ||
		bytes.Equal(magic[:4], machoCigam) ||
		bytes.Equal(magic[:4], macho32) ||
		bytes.Equal(magic[:4], machoFat)
}

// binaryMeta holds structured metadata extracted from a binary.
type binaryMeta struct {
	language        string
	cryptoLibraries []string
	state           string // Dominant state from multi-signal scoring
}

// scanBinaryFile reads a binary file, verifies magic bytes, and looks for crypto-related strings.
func (m *BinaryModule) scanBinaryFile(path string) ([]*model.Finding, error) {
	data, err := m.readBinaryHead(path)
	if err != nil {
		return nil, err
	}

	// Verify executable magic bytes (authoritative check)
	if len(data) < 2 || !isExecutableMagic(data) {
		return nil, nil
	}

	// Try structured parsing first
	meta := m.analyzeBinaryStructured(path)

	// Extract printable strings from binary (fallback / string scanning)
	printable := extractPrintableStrings(data, 4)

	// Enhance state from string patterns if structured didn't find one
	if meta.state == "" {
		meta.state = detectStateFromStrings(printable)
	}

	// Match crypto patterns against extracted strings
	found := m.matchCryptoPatterns(path, printable, &meta)

	return found, nil
}

// analyzeBinaryStructured uses Go stdlib debug packages to extract metadata.
func (m *BinaryModule) analyzeBinaryStructured(path string) binaryMeta {
	meta := binaryMeta{}

	// Language detection (4-tier, fast-exit)
	meta.language = detectLanguage(path)

	// Crypto library linkage from imported libraries
	libs := getImportedLibraries(path)
	for _, lib := range libs {
		libLower := strings.ToLower(lib)
		for _, entry := range cryptoLibTable {
			if strings.Contains(libLower, strings.ToLower(entry.substring)) {
				meta.cryptoLibraries = appendUnique(meta.cryptoLibraries, entry.library)
				if meta.state == "" && entry.state != "" {
					meta.state = entry.state
				}
			}
		}
	}

	// Symbol-based state detection
	syms := getImportedSymbols(path)
	for _, sym := range syms {
		for _, ss := range stateSymbols {
			if strings.Contains(sym, ss.substring) {
				if meta.state == "" {
					meta.state = ss.state
				}
				break
			}
		}
	}

	return meta
}

// detectLanguage identifies the programming language of a binary.
// 4-tier: buildinfo (Go definitive) → section names → symbol patterns → byte fallback.
func detectLanguage(path string) string {
	// Tier 1: debug/buildinfo — definitive for Go binaries (~100μs for non-Go)
	if _, err := buildinfo.ReadFile(path); err == nil {
		return "Go"
	}

	// Tier 2-4: ELF section/symbol analysis
	if ef, err := elf.Open(path); err == nil {
		defer ef.Close()

		// Tier 2: Section names
		for _, sec := range ef.Sections {
			switch sec.Name {
			case ".go.buildinfo", ".gopclntab", ".go.buildid":
				return "Go"
			case ".note.rustc":
				return "Rust"
			}
		}

		// Tier 3: Symbol patterns
		if syms, err := ef.Symbols(); err == nil {
			for _, s := range syms {
				if strings.Contains(s.Name, "rust_begin_unwind") || strings.HasPrefix(s.Name, "_ZN4core") {
					return "Rust"
				}
				if strings.HasPrefix(s.Name, "runtime.") && strings.Contains(s.Name, "goroutine") {
					return "Go"
				}
			}
		}

		return "C/C++"
	}

	// Mach-O
	if mf, err := macho.Open(path); err == nil {
		defer mf.Close()

		for _, sec := range mf.Sections {
			switch sec.Name {
			case "__go_buildinfo", "__gopclntab":
				return "Go"
			}
			if strings.Contains(sec.Name, "swift") {
				return "Swift"
			}
		}
		return "C/C++"
	}

	// Mach-O fat binary
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		if len(ff.Arches) > 0 {
			for _, sec := range ff.Arches[0].Sections {
				if sec.Name == "__go_buildinfo" || sec.Name == "__gopclntab" {
					return "Go"
				}
			}
		}
		return "C/C++"
	}

	// PE
	if pf, err := pe.Open(path); err == nil {
		defer pf.Close()

		for _, sec := range pf.Sections {
			if sec.Name == ".go.buildinfo" {
				return "Go"
			}
		}
		return "C/C++"
	}

	return ""
}

// getImportedLibraries extracts imported dynamic libraries from a binary.
func getImportedLibraries(path string) []string {
	// Try ELF
	if ef, err := elf.Open(path); err == nil {
		defer ef.Close()
		if libs, err := ef.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	// Try Mach-O
	if mf, err := macho.Open(path); err == nil {
		defer mf.Close()
		if libs, err := mf.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	// Try Mach-O fat binary
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		if len(ff.Arches) > 0 {
			if libs, err := ff.Arches[0].ImportedLibraries(); err == nil {
				return libs
			}
		}
		return nil
	}

	// Try PE
	if pf, err := pe.Open(path); err == nil {
		defer pf.Close()
		if libs, err := pf.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	return nil
}

// getImportedSymbols extracts imported symbol names from a binary.
func getImportedSymbols(path string) []string {
	// Try ELF
	if ef, err := elf.Open(path); err == nil {
		defer ef.Close()
		if syms, err := ef.ImportedSymbols(); err == nil {
			names := make([]string, 0, len(syms))
			for _, s := range syms {
				names = append(names, s.Name)
			}
			return names
		}
		return nil
	}

	// Try PE
	if pf, err := pe.Open(path); err == nil {
		defer pf.Close()
		if syms, err := pf.ImportedSymbols(); err == nil {
			return syms
		}
		return nil
	}

	return nil
}

// detectStateFromStrings infers crypto state from string content patterns.
func detectStateFromStrings(content string) string {
	contentUpper := strings.ToUpper(content)

	transitKeywords := []string{"TLS", "SSL", "HTTPS", "DTLS", "STARTTLS", "IPSEC", "WIREGUARD"}
	restKeywords := []string{"AES-XTS", "LUKS", "DMCRYPT", "SQLCIPHER", "BITLOCKER", "FILEVAULT", "ENCRYPT_AT_REST"}
	useKeywords := []string{"SIGN", "VERIFY", "HMAC", "DIGEST", "HASH", "KDF", "PBKDF"}

	for _, kw := range transitKeywords {
		if strings.Contains(contentUpper, kw) {
			return "IN_TRANSIT"
		}
	}
	for _, kw := range restKeywords {
		if strings.Contains(contentUpper, kw) {
			return "AT_REST"
		}
	}
	for _, kw := range useKeywords {
		if strings.Contains(contentUpper, kw) {
			return "IN_USE"
		}
	}

	return ""
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
func (m *BinaryModule) matchCryptoPatterns(path, content string, meta *binaryMeta) []*model.Finding {
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

			// Populate metadata from structured analysis
			if meta != nil {
				asset.Language = meta.language
				asset.State = meta.state
				asset.CryptoLibraries = meta.cryptoLibraries
			}

			crypto.ClassifyCryptoAsset(asset)

			detectionMethod := "string"
			if meta != nil && len(meta.cryptoLibraries) > 0 {
				detectionMethod = "library-linkage"
			}

			findings = append(findings, &model.Finding{
				ID:       uuid.New().String(),
				Category: 2,
				Source: model.FindingSource{
					Type:            "file",
					Path:            path,
					DetectionMethod: detectionMethod,
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

// appendUnique appends s to slice if not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
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
