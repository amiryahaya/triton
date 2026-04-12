package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// FIDO2Module scans for FIDO2/WebAuthn credential storage and
// configuration:
//
//   - pam-u2f: /etc/Yubico/u2f_keys — COSE algorithm types per user
//   - WebAuthn RP configs: pubKeyCredParams algorithm preferences
//   - FIDO metadata: presence detection for metadata blobs
//
// Reports which COSE algorithms are in use for PQC migration
// planning. Never extracts credential private keys.
type FIDO2Module struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewFIDO2Module constructs a FIDO2Module.
func NewFIDO2Module(cfg *scannerconfig.Config) *FIDO2Module {
	return &FIDO2Module{config: cfg}
}

func (m *FIDO2Module) Name() string                         { return "fido2" }
func (m *FIDO2Module) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *FIDO2Module) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *FIDO2Module) SetStore(s store.Store)               { m.store = s }

func (m *FIDO2Module) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree for FIDO2/WebAuthn files.
func (m *FIDO2Module) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isFIDO2File,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
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

// isFIDO2File matches FIDO2/WebAuthn config and credential files.
func isFIDO2File(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// pam-u2f key files
	if base == "u2f_keys" {
		return true
	}
	// PAM FIDO2 config
	if strings.Contains(lower, "/pam.d/") && strings.Contains(base, "u2f") {
		return true
	}

	// WebAuthn RP configs
	if strings.Contains(lower, "webauthn") && strings.HasSuffix(base, ".json") {
		return true
	}

	// FIDO metadata
	if strings.Contains(lower, "/fido") &&
		(strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".jwt")) {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser.
func (m *FIDO2Module) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case base == "u2f_keys":
		return m.parsePamU2FKeys(path, data)
	case strings.Contains(lower, "webauthn") && strings.HasSuffix(base, ".json"):
		return m.parseWebAuthnConfig(path, data)
	}
	return nil
}

// --- pam-u2f ---

// coseTypeMap maps pam-u2f COSE type strings to canonical algorithm names.
var coseTypeMap = map[string]string{
	"es256": "ECDSA-P256",
	"es384": "ECDSA-P384",
	"es512": "ECDSA-P521",
	"eddsa": "Ed25519",
	"rs256": "RSA",
	"rs384": "RSA",
	"rs512": "RSA",
	"ps256": "RSA-PSS",
	"ps384": "RSA-PSS",
	"ps512": "RSA-PSS",
}

// parsePamU2FKeys extracts COSE algorithm types from pam-u2f key files.
// Format: username:KeyHandle,PublicKey,CoseType[,Options]
func (m *FIDO2Module) parsePamU2FKeys(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "pam-u2f", sc.Err()) }()

	seen := make(map[string]bool)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on colon to get username:credentials
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		creds := line[colon+1:]
		// Credentials are comma-separated: handle,pubkey,coseType[,options]
		parts := strings.Split(creds, ",")
		if len(parts) < 3 {
			continue
		}
		coseType := strings.ToLower(strings.TrimSpace(parts[2]))
		if coseType == "" || seen[coseType] {
			continue
		}
		seen[coseType] = true

		algo := coseType
		if canonical, ok := coseTypeMap[coseType]; ok {
			algo = canonical
		}
		out = append(out, m.fido2Finding(path, "FIDO2/U2F credential", algo,
			fmt.Sprintf("pam-u2f %s credential in %s", coseType, filepath.Base(path))))
	}
	return out
}

// --- WebAuthn RP config ---

// coseAlgMap maps COSE algorithm identifiers to canonical names.
// See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
var coseAlgMap = map[int]string{
	-7:   "ECDSA-P256", // ES256
	-8:   "Ed25519",    // EdDSA
	-35:  "ECDSA-P384", // ES384
	-36:  "ECDSA-P521", // ES512
	-257: "RSA",        // RS256
	-258: "RSA",        // RS384
	-259: "RSA",        // RS512
	-37:  "RSA-PSS",    // PS256
	-38:  "RSA-PSS",    // PS384
	-39:  "RSA-PSS",    // PS512
}

// parseWebAuthnConfig extracts pubKeyCredParams from WebAuthn RP configs.
func (m *FIDO2Module) parseWebAuthnConfig(path string, data []byte) []*model.Finding {
	var conf struct {
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil
	}
	if len(conf.PubKeyCredParams) == 0 {
		return nil
	}

	var out []*model.Finding
	seen := make(map[int]bool)
	for _, p := range conf.PubKeyCredParams {
		if seen[p.Alg] {
			continue
		}
		seen[p.Alg] = true

		algo := fmt.Sprintf("COSE-%d", p.Alg)
		if canonical, ok := coseAlgMap[p.Alg]; ok {
			algo = canonical
		}
		out = append(out, m.fido2Finding(path, "WebAuthn credential algorithm", algo,
			fmt.Sprintf("WebAuthn pubKeyCredParams alg %d in %s", p.Alg, filepath.Base(path))))
	}
	return out
}

// --- finding builder ---

func (m *FIDO2Module) fido2Finding(path, function, algorithm, purpose string) *model.Finding {
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
		Module:      "fido2",
		Timestamp:   time.Now(),
	}
}
