package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// cryptoLibPatterns defines known cryptographic shared libraries.
var cryptoLibPatterns = []struct {
	pattern   string // filename pattern (glob-style or prefix)
	name      string // human-readable library name
	algorithm string // primary algorithm family
}{
	{"libcrypto", "OpenSSL libcrypto", "OpenSSL"},
	{"libssl", "OpenSSL libssl", "TLS"},
	{"libmbedcrypto", "mbedTLS crypto", "mbedTLS"},
	{"libmbedtls", "mbedTLS TLS", "TLS"},
	{"libmbedx509", "mbedTLS X.509", "mbedTLS"},
	{"libwolfssl", "wolfSSL", "TLS"},
	{"libgnutls", "GnuTLS", "TLS"},
	{"libnss3", "NSS", "NSS"},
	{"libnspr4", "NSPR", "NSS"},
	{"libgcrypt", "libgcrypt", "GnuPG"},
	{"libsodium", "libsodium", "NaCl"},
	{"libnettle", "Nettle", "Nettle"},
	{"libhogweed", "Hogweed", "Nettle"},
	{"libbcrypt", "Bouncy Castle", "JCA"},
	{"libboringssl", "BoringSSL", "TLS"},
}

// versionRegex matches common version patterns in strings output.
var versionRegex = regexp.MustCompile(`(?i)(?:version|openssl)\s+(\d+\.\d+[.\d]*[a-z]?)`)

// LibraryModule scans for cryptographic shared libraries on the filesystem.
type LibraryModule struct {
	config      *config.Config
	lastScanned int64
	lastMatched int64
}

func NewLibraryModule(cfg *config.Config) *LibraryModule {
	return &LibraryModule{config: cfg}
}

func (m *LibraryModule) Name() string {
	return "libraries"
}

func (m *LibraryModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *LibraryModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *LibraryModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *LibraryModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		target:       target,
		config:       m.config,
		matchFile:    m.isLibraryFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		processFile: func(path string) error {
			finding := m.createLibraryFinding(path)
			if finding == nil {
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

// isLibraryFile checks if a file is a shared library by extension and name.
func (m *LibraryModule) isLibraryFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	// Check for shared library extensions
	isSO := strings.HasSuffix(lower, ".so") || strings.Contains(lower, ".so.")
	isDylib := strings.HasSuffix(lower, ".dylib")
	isDLL := strings.HasSuffix(lower, ".dll")

	if !isSO && !isDylib && !isDLL {
		return false
	}

	// Match against known crypto library patterns
	for _, pat := range cryptoLibPatterns {
		if strings.HasPrefix(lower, pat.pattern) {
			return true
		}
	}

	return false
}

// createLibraryFinding creates a finding for a detected crypto library.
func (m *LibraryModule) createLibraryFinding(path string) *model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	var libName, algorithm string
	for _, pat := range cryptoLibPatterns {
		if strings.HasPrefix(lower, pat.pattern) {
			libName = pat.name
			algorithm = pat.algorithm
			break
		}
	}

	if libName == "" {
		return nil
	}

	// Try to extract version from filename (e.g., libcrypto.so.1.1.1k)
	version := extractVersionFromFilename(base)

	// If no version in filename, try reading strings from the file
	if version == "" {
		version = m.extractVersionFromFile(path)
	}

	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Function:  "Cryptographic library",
		Algorithm: algorithm,
		Library:   libName,
		Purpose:   "Provides cryptographic primitives",
	}

	if version != "" {
		asset.Library = libName + " " + version
	}

	return &model.Finding{
		ID:       uuid.New().String(),
		Category: 3,
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.85,
		Module:      "libraries",
		Timestamp:   time.Now(),
	}
}

// extractVersionFromFilename tries to extract version from library filenames
// like libcrypto.so.1.1.1k, libssl.dylib.3, etc.
func extractVersionFromFilename(filename string) string {
	// Pattern: lib<name>.so.<version>
	if idx := strings.Index(filename, ".so."); idx >= 0 {
		return filename[idx+4:]
	}

	// Pattern: lib<name>.<version>.dylib (macOS)
	if strings.HasSuffix(filename, ".dylib") {
		parts := strings.Split(filename, ".")
		if len(parts) >= 3 {
			// Check if the part before .dylib is a version number
			ver := parts[len(parts)-2]
			if ver != "" && ver[0] >= '0' && ver[0] <= '9' {
				return ver
			}
		}
	}

	return ""
}

// extractVersionFromFile reads the first portion of the file and searches for version strings.
func (m *LibraryModule) extractVersionFromFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Read first 64KB for version strings
	buf := make([]byte, 64*1024)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Search for printable strings containing version info
	content := string(buf[:n])
	matches := versionRegex.FindStringSubmatch(content)
	if len(matches) >= 2 {
		return matches[1]
	}

	return ""
}
