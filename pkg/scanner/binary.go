package scanner

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

// Binary magic bytes for executable detection
var (
	elfMagic   = []byte{0x7f, 'E', 'L', 'F'}
	machoMagic = []byte{0xCF, 0xFA, 0xED, 0xFE} // 64-bit Mach-O
	machoCigam = []byte{0xFE, 0xED, 0xFA, 0xCF} // 64-bit Mach-O (reverse)
	macho32    = []byte{0xCE, 0xFA, 0xED, 0xFE} // 32-bit Mach-O
	machoFat   = []byte{0xCA, 0xFE, 0xBA, 0xBE} // Universal binary
	peMagic    = []byte{0x4D, 0x5A}             // MZ header (PE/COFF)
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
	{regexp.MustCompile(`TLS[-_]?1[._]3`), "TLS 1.3", "TLS"},
	{regexp.MustCompile(`TLS[-_]?1[._]2`), "TLS 1.2", "TLS"},
	{regexp.MustCompile(`TLS[-_]?1[._]1`), "TLS 1.1", "TLS"},
	{regexp.MustCompile(`TLS[-_]?1[._]0`), "TLS 1.0", "TLS"},
	{regexp.MustCompile(`SSLv2\b`), "SSL 2.0", "SSL"},
	{regexp.MustCompile(`SSLv3\b`), "SSL 3.0", "SSL"},

	// New patterns
	{regexp.MustCompile(`\bHMAC[-_]?(SHA256|SHA512|SHA1|MD5)\b`), "HMAC", "HMAC"},
	{regexp.MustCompile(`\bPBKDF2\b`), "PBKDF2", "KDF"},
	{regexp.MustCompile(`\bscrypt\b`), "scrypt", "KDF"},
	{regexp.MustCompile(`\b[Aa]rgon2(id?|d|i)?\b`), "Argon2", "KDF"},
	{regexp.MustCompile(`\bHKDF\b`), "HKDF", "KDF"},
	{regexp.MustCompile(`\b[Bb]crypt\b`), "Bcrypt", "Password-Hash"},
	{regexp.MustCompile(`\bX25519\b`), "X25519", "ECDH"},
	{regexp.MustCompile(`\bX448\b`), "X448", "ECDH"},
	{regexp.MustCompile(`\bFN[-_]?DSA[-_]?(512|1024)?\b`), "FN-DSA", "Lattice"},
	{regexp.MustCompile(`\bFALCON\b`), "FN-DSA", "Lattice"},
	{regexp.MustCompile(`SPHINCS\+`), "SPHINCS+", "Hash-Based"},
	{regexp.MustCompile(`SLH[-_]?DSA`), "SLH-DSA", "Hash-Based"},
}

// cryptoSymbolPatterns maps dynamic symbol names to crypto algorithms.
var cryptoSymbolPatterns = []struct {
	pattern   *regexp.Regexp
	algorithm string
	function  string
}{
	{regexp.MustCompile(`EVP_aes_(\d+)_(gcm|cbc|ctr|ccm)`), "AES", "Symmetric encryption"},
	{regexp.MustCompile(`EVP_sha(1|224|256|384|512)\b`), "SHA", "Hash"},
	{regexp.MustCompile(`RSA_sign|RSA_verify`), "RSA", "Digital signature"},
	{regexp.MustCompile(`ECDSA_sign|ECDSA_verify`), "ECDSA", "Digital signature"},
	{regexp.MustCompile(`ED25519_sign|ED25519_verify`), "Ed25519", "Digital signature"},
	{regexp.MustCompile(`OQS_SIG_.*dilithium`), "ML-DSA", "PQC signature"},
	{regexp.MustCompile(`OQS_KEM_.*kyber`), "ML-KEM", "PQC key encapsulation"},
	{regexp.MustCompile(`OQS_SIG_.*falcon`), "FN-DSA", "PQC signature"},
}

// symbolMatch represents a crypto algorithm detected from a symbol.
type symbolMatch struct {
	algorithm string
	function  string
	symbol    string // the actual symbol that matched
}

// cryptoVersionPatterns matches embedded crypto library version strings.
var cryptoVersionPatterns = []struct {
	pattern *regexp.Regexp
	library string
}{
	{regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+[a-z]?)`), "openssl"},
	{regexp.MustCompile(`wolfSSL (\d+\.\d+\.\d+)`), "wolfssl"},
	{regexp.MustCompile(`GnuTLS (\d+\.\d+\.\d+)`), "gnutls"},
	{regexp.MustCompile(`mbedTLS (\d+\.\d+\.\d+)`), "mbedtls"},
	{regexp.MustCompile(`libsodium (\d+\.\d+\.\d+)`), "libsodium"},
	{regexp.MustCompile(`BoringSSL`), "boringssl"},
}

// libVersion holds a detected crypto library and its version.
type libVersion struct {
	library string
	version string
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
	config      *scannerconfig.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
	reader      fsadapter.FileReader
}

func (m *BinaryModule) SetStore(s store.Store)               { m.store = s }
func (m *BinaryModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func NewBinaryModule(cfg *scannerconfig.Config) *BinaryModule {
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

func (m *BinaryModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *BinaryModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    m.isBinaryFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(_ context.Context, _ fsadapter.FileReader, path string) error {
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
	symbolFindings  []symbolMatch
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

	// Emit symbol-based findings (higher confidence than string matching)
	symbolAlgos := make(map[string]bool)
	for _, sm := range meta.symbolFindings {
		symbolAlgos[sm.algorithm] = true

		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  sm.function,
			Algorithm: sm.algorithm,
			Purpose:   "Detected via imported symbol: " + sm.symbol,
		}
		if meta.language != "" {
			asset.Language = meta.language
		}
		if meta.state != "" {
			asset.State = meta.state
		}
		if len(meta.cryptoLibraries) > 0 {
			asset.CryptoLibraries = meta.cryptoLibraries
		}
		crypto.ClassifyCryptoAsset(asset)

		found = append(found, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 2,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: "symbol",
			},
			CryptoAsset: asset,
			Confidence:  0.80,
			Module:      "binaries",
			Timestamp:   time.Now(),
		})
	}

	// Deduplicate: remove string-match findings that overlap with symbol findings
	if len(symbolAlgos) > 0 {
		deduped := make([]*model.Finding, 0, len(found))
		for _, f := range found {
			if f.Source.DetectionMethod != "symbol" && symbolAlgos[f.CryptoAsset.Algorithm] {
				continue // drop string-match in favor of symbol-match
			}
			deduped = append(deduped, f)
		}
		found = deduped
	}

	// Detect embedded crypto library versions
	libVersions := detectCryptoLibVersions(printable)
	for _, lv := range libVersions {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Crypto library",
			Algorithm: lv.library,
			Library:   lv.library,
			Purpose:   "Embedded crypto library detected in binary",
		}
		if lv.version != "" {
			asset.Purpose = fmt.Sprintf("Embedded %s %s detected in binary", lv.library, lv.version)
		}
		crypto.ClassifyLibraryAsset(asset, lv.library, lv.version)

		found = append(found, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 2,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: "string",
			},
			CryptoAsset: asset,
			Confidence:  0.70,
			Module:      "binaries",
			Timestamp:   time.Now(),
		})
	}

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

	// Symbol-based state detection and crypto symbol matching
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

	// Match crypto algorithms from symbols
	meta.symbolFindings = matchCryptoSymbols(syms)

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
		defer func() { _ = ef.Close() }()

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
		defer func() { _ = mf.Close() }()

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
		defer func() { _ = ff.Close() }()
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
		defer func() { _ = pf.Close() }()

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
func getImportedLibraries(path string) (result []string) {
	// The stdlib PE parser can panic on malformed binaries (e.g. corrupt import tables).
	defer func() {
		if r := recover(); r != nil {
			result = nil
		}
	}()
	// Try ELF
	if ef, err := elf.Open(path); err == nil {
		defer func() { _ = ef.Close() }()
		if libs, err := ef.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	// Try Mach-O
	if mf, err := macho.Open(path); err == nil {
		defer func() { _ = mf.Close() }()
		if libs, err := mf.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	// Try Mach-O fat binary
	if ff, err := macho.OpenFat(path); err == nil {
		defer func() { _ = ff.Close() }()
		if len(ff.Arches) > 0 {
			if libs, err := ff.Arches[0].ImportedLibraries(); err == nil {
				return libs
			}
		}
		return nil
	}

	// Try PE
	if pf, err := pe.Open(path); err == nil {
		defer func() { _ = pf.Close() }()
		if libs, err := pf.ImportedLibraries(); err == nil {
			return libs
		}
		return nil
	}

	return nil
}

// getImportedSymbols extracts imported symbol names from a binary.
func getImportedSymbols(path string) (result []string) {
	// The stdlib PE parser can panic on malformed binaries (e.g. corrupt import tables).
	defer func() {
		if r := recover(); r != nil {
			result = nil
		}
	}()
	// Try ELF
	if ef, err := elf.Open(path); err == nil {
		defer func() { _ = ef.Close() }()
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
		defer func() { _ = pf.Close() }()
		if syms, err := pf.ImportedSymbols(); err == nil {
			return syms
		}
		return nil
	}

	// Try Mach-O
	if mf, err := macho.Open(path); err == nil {
		defer func() { _ = mf.Close() }()
		return extractMachoSymbols(mf)
	}

	// Try Mach-O fat binary
	if ff, err := macho.OpenFat(path); err == nil {
		defer func() { _ = ff.Close() }()
		if len(ff.Arches) > 0 {
			return extractMachoSymbols(ff.Arches[0].File)
		}
	}

	return nil
}

// extractMachoSymbols extracts external symbol names from a Mach-O file's symbol table.
func extractMachoSymbols(mf *macho.File) []string {
	if mf.Symtab == nil {
		return nil
	}

	var names []string
	for _, s := range mf.Symtab.Syms {
		// N_EXT (0x01) = external symbol
		if s.Type&0x01 != 0 && s.Name != "" {
			names = append(names, s.Name)
		}
	}
	return names
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

// matchCryptoSymbols matches symbol names against known crypto function patterns.
func matchCryptoSymbols(symbols []string) []symbolMatch {
	var matches []symbolMatch
	seen := make(map[string]bool)

	for _, sym := range symbols {
		for _, pat := range cryptoSymbolPatterns {
			if !pat.pattern.MatchString(sym) {
				continue
			}
			// Refine algorithm name from submatch before dedup
			algo := pat.algorithm
			if sub := pat.pattern.FindStringSubmatch(sym); len(sub) > 1 {
				switch pat.algorithm {
				case "AES":
					algo = "AES-" + sub[1] + "-" + strings.ToUpper(sub[2])
				case "SHA":
					algo = "SHA-" + sub[1]
				}
			}

			algoKey := algo + ":" + pat.function
			if seen[algoKey] {
				break
			}
			seen[algoKey] = true

			matches = append(matches, symbolMatch{
				algorithm: algo,
				function:  pat.function,
				symbol:    sym,
			})
			break // one pattern match per symbol
		}
	}
	return matches
}

// detectCryptoLibVersions finds embedded crypto library version strings in binary content.
func detectCryptoLibVersions(content string) []libVersion {
	var results []libVersion
	seen := make(map[string]bool)

	for _, pat := range cryptoVersionPatterns {
		matches := pat.pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if seen[pat.library] {
				continue
			}
			seen[pat.library] = true

			ver := ""
			if len(m) > 1 {
				ver = m[1]
			}
			results = append(results, libVersion{
				library: pat.library,
				version: ver,
			})
		}
	}
	return results
}

// readBinaryHead reads the first maxBinaryReadSize bytes of a binary file.
func (m *BinaryModule) readBinaryHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := info.Size()
	if size > int64(maxBinaryReadSize) {
		size = int64(maxBinaryReadSize)
	}

	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
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
				ID:        uuid.Must(uuid.NewV7()).String(),
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
				ID:       uuid.Must(uuid.NewV7()).String(),
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
	match = strings.ReplaceAll(match, "_", "-")
	if len(match) <= len(baseAlgo) {
		return baseAlgo
	}

	// Align baseAlgo against match, skipping hyphens in both, to find
	// where the suffix starts in match. E.g. baseAlgo="FN-DSA" aligns
	// against "FNDSA1024" → suffix starts at index 5.
	bi, mi := 0, 0
	for bi < len(baseAlgo) && mi < len(match) {
		for bi < len(baseAlgo) && (baseAlgo[bi] == '-' || baseAlgo[bi] == '_') {
			bi++
		}
		for mi < len(match) && (match[mi] == '-' || match[mi] == '_') {
			mi++
		}
		if bi >= len(baseAlgo) || mi >= len(match) {
			break
		}
		if !equalFoldByte(baseAlgo[bi], match[mi]) {
			return match // prefix doesn't align — return match as-is
		}
		bi++
		mi++
	}

	// If baseAlgo was fully consumed and a digit suffix remains, insert hyphen
	if bi >= len(baseAlgo) && mi < len(match) {
		suffix := match[mi:]
		if suffix[0] >= '0' && suffix[0] <= '9' {
			return baseAlgo + "-" + suffix
		}
	}
	return match
}

// equalFoldByte compares two ASCII bytes case-insensitively.
func equalFoldByte(a, b byte) bool {
	if a == b {
		return true
	}
	if a >= 'A' && a <= 'Z' {
		a += 'a' - 'A'
	}
	if b >= 'A' && b <= 'Z' {
		b += 'a' - 'A'
	}
	return a == b
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
