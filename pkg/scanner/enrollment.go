package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// EnrollmentModule scans certificate enrollment configuration:
//
//   - Certbot/ACME: account keys (JWK), renewal configs (key_type/key_size)
//   - step-ca (Smallstep): CA config (key type, provisioners)
//   - EST/SCEP: client configuration files (presence detection)
//
// Reports key algorithms used in enrollment workflows for PQC
// migration planning. Never extracts private key values.
type EnrollmentModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewEnrollmentModule constructs an EnrollmentModule.
func NewEnrollmentModule(cfg *scannerconfig.Config) *EnrollmentModule {
	return &EnrollmentModule{config: cfg}
}

func (m *EnrollmentModule) Name() string                         { return "enrollment" }
func (m *EnrollmentModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *EnrollmentModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *EnrollmentModule) SetStore(s store.Store)               { m.store = s }

func (m *EnrollmentModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses matching enrollment configs.
func (m *EnrollmentModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isEnrollmentFile,
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

// isEnrollmentFile matches certificate enrollment config files.
func isEnrollmentFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Certbot / Let's Encrypt — account keys and renewal configs only.
	// PEM files are handled by the certificate module; cli.conf is not
	// crypto-relevant.
	if strings.Contains(lower, "/letsencrypt/") && base == "private_key.json" {
		return true
	}
	if strings.Contains(lower, "/letsencrypt/renewal/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// step-ca / Smallstep
	if strings.Contains(lower, "/step/") &&
		(strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".conf")) {
		return true
	}

	// EST client
	if strings.Contains(lower, "/est/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// SCEP
	if strings.Contains(lower, "/scep/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser.
func (m *EnrollmentModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "/letsencrypt/") && base == "private_key.json":
		return m.parseCertbotAccountKey(path, data)
	case strings.Contains(lower, "/letsencrypt/renewal/") && strings.HasSuffix(base, ".conf"):
		return m.parseCertbotRenewal(path, data)
	case strings.Contains(lower, "/step/") && strings.HasSuffix(base, ".json"):
		return m.parseStepCAConfig(path, data)
	}
	// EST/SCEP configs are presence-only for now
	return nil
}

// --- Certbot / ACME ---

// certbotKeyTypeMap maps certbot key_type values to canonical algorithm names.
var certbotKeyTypeMap = map[string]string{
	"rsa":   "RSA",
	"ecdsa": "ECDSA",
}

// certbotCurveMap maps ECDSA key sizes to curve names.
var certbotCurveMap = map[int]string{
	256: "ECDSA-P256",
	384: "ECDSA-P384",
	521: "ECDSA-P521",
}

// parseCertbotRenewal extracts key type and size from certbot renewal configs.
func (m *EnrollmentModule) parseCertbotRenewal(path string, data []byte) []*model.Finding {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "certbot-renewal", sc.Err()) }()

	base := filepath.Base(path)
	var keyType string
	var keySize int

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])

		switch key {
		case "key_type":
			keyType = val
		case "key_size":
			if ks, err := strconv.Atoi(val); err == nil {
				keySize = ks
			}
		}
	}

	if keyType == "" {
		return nil
	}

	algo := keyType
	if canonical, ok := certbotKeyTypeMap[strings.ToLower(keyType)]; ok {
		algo = canonical
	}
	// For ECDSA, resolve curve from key_size
	if strings.EqualFold(keyType, "ecdsa") && keySize > 0 {
		if curve, ok := certbotCurveMap[keySize]; ok {
			algo = curve
		}
	}

	finding := m.enrollmentFinding(path, "ACME certificate key type", algo,
		fmt.Sprintf("certbot key_type=%s in %s", keyType, base))
	if keySize > 0 {
		finding.CryptoAsset.KeySize = keySize
	}
	return []*model.Finding{finding}
}

// --- Certbot account key (JWK) ---

// jwkCurveMap maps JWK curve names to canonical algorithm names.
var jwkCurveMap = map[string]string{
	"P-256": "ECDSA-P256",
	"P-384": "ECDSA-P384",
	"P-521": "ECDSA-P521",
}

// parseCertbotAccountKey extracts the key type from a certbot account JWK.
func (m *EnrollmentModule) parseCertbotAccountKey(path string, data []byte) []*model.Finding {
	var jwk struct {
		KTY string `json:"kty"`
		CRV string `json:"crv"`
	}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil
	}
	if jwk.KTY == "" {
		return nil
	}

	algo := jwk.KTY
	switch strings.ToUpper(jwk.KTY) {
	case "EC":
		if curve, ok := jwkCurveMap[jwk.CRV]; ok {
			algo = curve
		} else {
			algo = "ECDSA"
		}
	case "RSA":
		algo = "RSA"
	case "OKP":
		algo = "Ed25519" // OKP is typically Ed25519
	}

	return []*model.Finding{m.enrollmentFinding(path, "ACME account key", algo,
		fmt.Sprintf("certbot account key (%s) in %s", jwk.KTY, filepath.Base(path)))}
}

// --- step-ca / Smallstep ---

// parseStepCAConfig extracts key type and provisioners from step-ca config.
func (m *EnrollmentModule) parseStepCAConfig(path string, data []byte) []*model.Finding {
	var conf struct {
		KTY string `json:"kty"`
		CRV string `json:"crv"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil
	}
	if conf.KTY == "" {
		return nil
	}

	algo := conf.KTY
	switch strings.ToUpper(conf.KTY) {
	case "EC":
		if curve, ok := jwkCurveMap[conf.CRV]; ok {
			algo = curve
		} else {
			algo = "ECDSA"
		}
	case "RSA":
		algo = "RSA"
	case "OKP":
		algo = "Ed25519"
	}

	return []*model.Finding{m.enrollmentFinding(path, "step-ca key type", algo,
		fmt.Sprintf("step-ca CA key (%s) in %s", conf.KTY, filepath.Base(path)))}
}

// --- finding builder ---

func (m *EnrollmentModule) enrollmentFinding(path, function, algorithm, purpose string) *model.Finding {
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
		Module:      "enrollment",
		Timestamp:   time.Now(),
	}
}
