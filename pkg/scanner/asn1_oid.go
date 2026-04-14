package scanner

import (
	"context"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/scanner/internal/binsections"
	"github.com/amiryahaya/triton/pkg/store"
)

// ASN1OIDModule walks executable binaries, extracts read-only data sections,
// scans them for DER-encoded OIDs, and emits findings keyed to the crypto
// registry. This catches algorithms embedded in stripped binaries where
// symbol-based and string-based scanners miss them.
//
// Detection method: "asn1-oid". Gated to the comprehensive profile in
// internal/scannerconfig because section extraction on large binaries is
// IO + CPU heavy (~50-200ms per binary).
type ASN1OIDModule struct {
	cfg   *scannerconfig.Config
	store store.Store
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

// SetStore wires the incremental-scan store (StoreAware). Matches BinaryModule.
func (m *ASN1OIDModule) SetStore(s store.Store) { m.store = s }

// Scan walks target.Value using the shared walkTarget helper (inherits depth
// limits, exclude patterns, max file size, symlink skip, and incremental
// hash-based skip when a store is attached), then for each file whose magic
// bytes match a supported binary format extracts read-only sections and emits
// a Finding per classified OID.
func (m *ASN1OIDModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "" {
		return nil
	}

	return walkTarget(walkerConfig{
		ctx:       ctx,
		target:    target,
		config:    m.cfg,
		matchFile: binsections.LooksLikeBinary,
		store:     m.store,
		processFile: func(ctx context.Context, _ fsadapter.FileReader, path string) error {
			m.scanBinary(ctx, path, findings)
			return nil
		},
	})
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
	if crypto.IsCompositeOID(c.OID) {
		asset.IsHybrid = true
		asset.ComponentAlgorithms = crypto.CompositeComponents(c.Entry.Algorithm)
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
