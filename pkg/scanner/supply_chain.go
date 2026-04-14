package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// SupplyChainModule scans CI/CD provenance and signing artifacts:
//
//   - SLSA provenance: .slsa.json attestation files
//   - in-toto: .link files with signature method extraction
//   - Sigstore/Fulcio: TUF root.json trust roots, key type extraction
//   - GitHub Actions: workflow YAML for OIDC token usage, cosign,
//     SLSA generator references
//
// Reports signing algorithms and trust anchors for PQC migration
// planning. Never extracts private keys or secrets.
type SupplyChainModule struct {
	config      *scannerconfig.Config
	store       store.Store
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewSupplyChainModule constructs a SupplyChainModule.
func NewSupplyChainModule(cfg *scannerconfig.Config) *SupplyChainModule {
	return &SupplyChainModule{config: cfg}
}

func (m *SupplyChainModule) Name() string                         { return "supply_chain" }
func (m *SupplyChainModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *SupplyChainModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *SupplyChainModule) SetStore(s store.Store)               { m.store = s }
func (m *SupplyChainModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func (m *SupplyChainModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses matching provenance/signing files.
func (m *SupplyChainModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isSupplyChainFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			data, err := reader.ReadFile(ctx, path)
			if err != nil {
				return nil
			}
			results := m.parseFile(path, data)
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

// isSupplyChainFile matches CI/CD provenance and signing artifacts.
func isSupplyChainFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// SLSA provenance
	if strings.HasSuffix(base, ".slsa.json") || strings.HasSuffix(base, ".slsa.jsonl") {
		return true
	}

	// in-toto link files
	if strings.HasSuffix(base, ".link") {
		return true
	}

	// in-toto layout under .in-toto/
	if strings.Contains(lower, "/.in-toto/") {
		return true
	}

	// Sigstore / TUF trust roots
	if strings.Contains(lower, "/sigstore/") || strings.Contains(lower, "/.sigstore/") {
		return true
	}
	if base == "trusted_root.json" {
		return true
	}

	// GitHub Actions workflows
	if strings.Contains(lower, ".github/workflows/") &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser.
func (m *SupplyChainModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(base, ".slsa.json") || strings.HasSuffix(base, ".slsa.jsonl"):
		return m.parseSLSAProvenance(path, data)
	case strings.HasSuffix(base, ".link"):
		return m.parseInTotoLink(path, data)
	case strings.Contains(lower, "/sigstore/") || strings.Contains(lower, "/.sigstore/") || base == "trusted_root.json":
		return m.parseSigstoreTrustRoot(path, data)
	case strings.Contains(lower, ".github/workflows/"):
		return m.parseGHAWorkflow(path, data)
	case strings.Contains(lower, "/.in-toto/"):
		return m.parseInTotoLink(path, data)
	}
	return nil
}

// --- SLSA provenance ---

// parseSLSAProvenance extracts attestation metadata from SLSA provenance files.
func (m *SupplyChainModule) parseSLSAProvenance(path string, data []byte) []*model.Finding {
	var envelope struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil
	}
	if !strings.Contains(envelope.PredicateType, "slsa.dev/provenance") {
		return nil
	}

	algo := "DSSE" // Dead Simple Signing Envelope — SLSA's signing format
	return []*model.Finding{m.supplyChainFinding(path, "SLSA provenance attestation", algo,
		fmt.Sprintf("SLSA provenance (%s) in %s", envelope.PredicateType, filepath.Base(path)))}
}

// --- in-toto ---

// inTotoSignatureMethodMap maps in-toto signature method names to canonical algorithms.
var inTotoSignatureMethodMap = map[string]string{
	"ed25519":             "Ed25519",
	"rsassa-pss-sha256":   "RSA-PSS",
	"rsassa-pss-sha384":   "RSA-PSS",
	"rsassa-pss-sha512":   "RSA-PSS",
	"ecdsa-sha2-nistp256": "ECDSA-P256",
	"ecdsa-sha2-nistp384": "ECDSA-P384",
	"ecdsa-sha2-nistp521": "ECDSA-P521",
	"rsa-pkcs1v15-sha256": "RSA",
	"rsa-pkcs1v15-sha384": "RSA",
	"rsa-pkcs1v15-sha512": "RSA",
}

// parseInTotoLink extracts signature algorithms from in-toto link/layout files.
func (m *SupplyChainModule) parseInTotoLink(path string, data []byte) []*model.Finding {
	var doc struct {
		Signatures []struct {
			KeyID  string `json:"keyid"`
			Method string `json:"method"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if len(doc.Signatures) == 0 {
		return nil
	}

	var out []*model.Finding
	seen := make(map[string]bool)
	for _, sig := range doc.Signatures {
		method := strings.ToLower(sig.Method)
		if method == "" || seen[method] {
			continue
		}
		seen[method] = true

		algo := sig.Method
		if canonical, ok := inTotoSignatureMethodMap[method]; ok {
			algo = canonical
		}
		out = append(out, m.supplyChainFinding(path, "in-toto link signature", algo,
			fmt.Sprintf("in-toto signature method %s in %s", sig.Method, filepath.Base(path))))
	}
	return out
}

// --- Sigstore / Fulcio TUF trust root ---

// tufKeyTypeMap maps TUF key types to canonical algorithm names.
var tufKeyTypeMap = map[string]string{
	"ecdsa-sha2-nistp256": "ECDSA-P256",
	"ecdsa-sha2-nistp384": "ECDSA-P384",
	"ed25519":             "Ed25519",
	"rsa":                 "RSA",
}

// parseSigstoreTrustRoot extracts key types from TUF root.json trust roots.
func (m *SupplyChainModule) parseSigstoreTrustRoot(path string, data []byte) []*model.Finding {
	var root struct {
		Signed struct {
			Type string `json:"_type"`
			Keys map[string]struct {
				KeyType string `json:"keytype"`
			} `json:"keys"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	if root.Signed.Type != "root" || len(root.Signed.Keys) == 0 {
		return nil
	}

	var out []*model.Finding
	seen := make(map[string]bool)
	for _, key := range root.Signed.Keys {
		kt := strings.ToLower(key.KeyType)
		if kt == "" || seen[kt] {
			continue
		}
		seen[kt] = true

		algo := key.KeyType
		if canonical, ok := tufKeyTypeMap[kt]; ok {
			algo = canonical
		}
		out = append(out, m.supplyChainFinding(path, "Sigstore TUF trust root key", algo,
			fmt.Sprintf("TUF root key type %s in %s", key.KeyType, filepath.Base(path))))
	}
	return out
}

// --- GitHub Actions OIDC ---

// parseGHAWorkflow looks for crypto-relevant patterns in GitHub Actions workflows:
// - id-token: write (OIDC token generation)
// - sigstore/cosign-installer usage
// - slsa-framework/slsa-github-generator usage
func (m *SupplyChainModule) parseGHAWorkflow(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "gha-workflow", sc.Err()) }()

	base := filepath.Base(path)
	hasOIDC := false
	hasCosign := false
	hasSLSA := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)

		if strings.Contains(lower, "id-token") && strings.Contains(lower, "write") {
			hasOIDC = true
		}
		if strings.Contains(lower, "sigstore/cosign") || strings.Contains(lower, "cosign-installer") {
			hasCosign = true
		}
		if strings.Contains(lower, "slsa-framework/slsa-github-generator") || strings.Contains(lower, "slsa-verifier") {
			hasSLSA = true
		}
	}

	if hasOIDC {
		out = append(out, m.supplyChainFinding(path, "GitHub Actions OIDC token", "OIDC",
			fmt.Sprintf("id-token: write in %s", base)))
	}
	if hasCosign {
		out = append(out, m.supplyChainFinding(path, "Sigstore cosign usage", "Sigstore-ECDSA",
			fmt.Sprintf("cosign action in %s", base)))
	}
	if hasSLSA {
		out = append(out, m.supplyChainFinding(path, "SLSA provenance generator", "DSSE",
			fmt.Sprintf("SLSA generator in %s", base)))
	}

	return out
}

// --- finding builder ---

func (m *SupplyChainModule) supplyChainFinding(path, function, algorithm, purpose string) *model.Finding {
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
		Module:      "supply_chain",
		Timestamp:   time.Now(),
	}
}
