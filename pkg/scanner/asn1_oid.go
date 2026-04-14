package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/binsections"
)

// ASN1OIDModule walks executable binaries, extracts read-only data sections,
// scans them for DER-encoded OIDs, and emits findings keyed to the crypto
// registry. This catches algorithms embedded in stripped binaries where
// symbol-based and string-based scanners miss them.
//
// Detection method: "asn1-oid". Runs only in the comprehensive profile
// because section extraction on large binaries is IO + CPU heavy (~50-200ms
// per binary). Not suited for quick/standard profiles.
type ASN1OIDModule struct {
	cfg *scannerconfig.Config
}

// NewASN1OIDModule constructs an ASN1OIDModule for the given config.
func NewASN1OIDModule(cfg *scannerconfig.Config) *ASN1OIDModule {
	return &ASN1OIDModule{cfg: cfg}
}

// Name returns the module's canonical name.
func (m *ASN1OIDModule) Name() string { return "asn1_oid" }

// Category returns the module category (passive file scanner).
func (m *ASN1OIDModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }

// ScanTargetType returns the target type this module handles.
func (m *ASN1OIDModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// Scan walks target.Path (expected to be a filesystem root), finds executable
// binaries, extracts their read-only sections, and emits a Finding for each
// classified OID.
func (m *ASN1OIDModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	root := target.Value
	if root == "" {
		return nil
	}

	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if shouldSkipOIDDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		// Cap per-file size to avoid unbounded work on huge artifacts
		// (container images, VM disks, core dumps). 500 MB is generous
		// relative to typical stripped binaries (<50 MB).
		if info.Size() > 500*1024*1024 {
			return nil
		}
		// Fast-reject non-binaries by magic. ExtractSections does this too,
		// but doing it here avoids allocating the full file descriptor path.
		if !looksLikeBinary(path) {
			return nil
		}
		m.scanBinary(ctx, path, findings)
		return nil
	})
}

// skippedSystemDirs is the set of kernel/virtual filesystem roots that
// must never be walked — they contain synthetic files that block, recurse
// infinitely, or expose sensitive state.
var skippedSystemDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
}

// shouldSkipOIDDir returns true for directories the ASN.1 OID walker must
// avoid: kernel virtual filesystems and git internals anywhere in tree.
func shouldSkipOIDDir(path string) bool {
	if skippedSystemDirs[path] {
		return true
	}
	if strings.Contains(path, "/.git/") || strings.HasSuffix(path, "/.git") {
		return true
	}
	return false
}

func (m *ASN1OIDModule) scanBinary(ctx context.Context, path string, findings chan<- *model.Finding) {
	sections, err := binsections.ExtractSections(path)
	if err != nil {
		return // not a supported binary, or unreadable
	}
	seen := make(map[string]bool) // dedupe by OID within a single binary
	for _, s := range sections {
		if ctx.Err() != nil {
			return
		}
		hits := crypto.FindOIDsInBuffer(s.Data)
		classified := crypto.ClassifyFoundOIDs(hits)
		for _, c := range classified {
			if seen[c.OID] {
				continue
			}
			seen[c.OID] = true
			select {
			case <-ctx.Done():
				return
			case findings <- buildFinding(path, s.Name, c):
			}
		}
	}
}

func buildFinding(path, sectionName string, c crypto.ClassifiedOID) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: c.Entry.Algorithm,
		KeySize:   c.Entry.KeySize,
		Library:   filepath.Base(path),
		Function:  functionForFamily(c.Entry.Family),
		OID:       c.OID,
		PQCStatus: string(c.Entry.Status),
	}
	return &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "asn1-oid",
			Evidence:        sectionName,
		},
		CryptoAsset: asset,
		Confidence:  0.95, // OID match is high-confidence by construction
		Module:      "asn1_oid",
		Timestamp:   time.Now().UTC(),
	}
}

// functionForFamily maps an OID family to a coarse cryptographic function
// label. Returns "" when the family doesn't map cleanly.
func functionForFamily(family string) string {
	switch family {
	case "RSA", "ECDSA", "EdDSA", "DSA", "ML-DSA", "SLH-DSA", "Falcon":
		return "Digital signature"
	case "SHA", "SHA3", "MD5", "Hash":
		return "Hash"
	case "AES", "DES", "3DES", "ChaCha20":
		return "Symmetric encryption"
	case "ECDH", "DH", "ML-KEM", "KEM":
		return "Key agreement"
	}
	return ""
}

// looksLikeBinary performs a 4-byte magic check to quickly reject
// non-binaries during the filesystem walk.
func looksLikeBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var head [4]byte
	n, _ := f.Read(head[:])
	if n < 2 {
		return false
	}
	// ELF
	if n >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		return true
	}
	// Mach-O (single arch, 64 or 32 bit, either endian, or fat)
	if n >= 4 {
		magicHead := [4]byte{head[0], head[1], head[2], head[3]}
		for _, magic := range [][4]byte{
			{0xCF, 0xFA, 0xED, 0xFE},
			{0xFE, 0xED, 0xFA, 0xCF},
			{0xCE, 0xFA, 0xED, 0xFE},
			{0xCA, 0xFE, 0xBA, 0xBE},
		} {
			if magicHead == magic {
				return true
			}
		}
	}
	// PE (MZ header)
	if head[0] == 'M' && head[1] == 'Z' {
		return true
	}
	return false
}
