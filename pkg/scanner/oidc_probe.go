package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

var oidcAlgoTokenMap = map[string]string{
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"PS256": "RSA-PSS", "PS384": "RSA-PSS", "PS512": "RSA-PSS",
	"ES256": "ECDSA-P256", "ES384": "ECDSA-P384", "ES512": "ECDSA-P521",
	"EdDSA": "Ed25519",
}

var crvToAlgorithm = map[string]string{
	"P-256": "ECDSA-P256", "P-384": "ECDSA-P384", "P-521": "ECDSA-P521",
	"Ed25519": "Ed25519", "Ed448": "Ed448",
}

var crvToKeySize = map[string]int{
	"P-256": 256, "P-384": 384, "P-521": 521,
	"Ed25519": 256, "Ed448": 456,
}

func normalizeJWAAlgorithm(alg, kty, crv string) string {
	if alg != "" {
		if canonical, ok := oidcAlgoTokenMap[alg]; ok {
			if alg == "EdDSA" && crv != "" {
				if crvAlgo, ok := crvToAlgorithm[crv]; ok {
					return crvAlgo
				}
			}
			return canonical
		}
		return "UNKNOWN"
	}
	switch kty {
	case "RSA":
		return "RSA"
	case "EC":
		if canonical, ok := crvToAlgorithm[crv]; ok {
			return canonical
		}
		return "UNKNOWN"
	case "OKP":
		if canonical, ok := crvToAlgorithm[crv]; ok {
			return canonical
		}
		return "UNKNOWN"
	}
	return "UNKNOWN"
}

type oidcDiscovery struct {
	JwksURI                       string   `json:"jwks_uri"`
	IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthSigningAlg   []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserinfoSigningAlgValues      []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValues []string `json:"request_object_signing_alg_values_supported"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	X   string `json:"x"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

// rsaStdKeySizes lists standard RSA key sizes in ascending order.
// We round the decoded modulus bit-length up to the nearest standard size.
var rsaStdKeySizes = []int{512, 1024, 1536, 2048, 3072, 4096, 8192}

func deriveKeySize(k jwkKey) int {
	switch k.Kty {
	case "RSA":
		if k.N == "" {
			return 0
		}
		decoded, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(decoded) == 0 {
			return 0
		}
		// Compute significant bit length (leading zeros in first byte are excluded).
		sigBits := (len(decoded)-1)*8 + bits.Len8(decoded[0])
		// Round up to the nearest standard RSA key size.
		for _, std := range rsaStdKeySizes {
			if sigBits <= std {
				return std
			}
		}
		// Larger than any standard size — return raw byte count × 8 rounded to 512.
		return ((sigBits + 511) / 512) * 512
	case "EC", "OKP":
		if size, ok := crvToKeySize[k.Crv]; ok {
			return size
		}
	}
	return 0
}

const (
	oidcFetchTimeout   = 15 * time.Second
	oidcMaxResponseLen = 1 << 20 // 1 MB
	oidcMaxRedirects   = 3
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OIDCProbeModule probes OIDC identity provider endpoints for cryptographic assets.
type OIDCProbeModule struct {
	config      *scannerconfig.Config
	httpClient  httpDoer
	lastScanned int64
	lastMatched int64
}

// NewOIDCProbeModule creates a new OIDCProbeModule with a default HTTP client.
func NewOIDCProbeModule(cfg *scannerconfig.Config) *OIDCProbeModule {
	return &OIDCProbeModule{
		config: cfg,
		httpClient: &http.Client{
			Timeout: oidcFetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= oidcMaxRedirects {
					return fmt.Errorf("oidc_probe: too many redirects")
				}
				return nil
			},
		},
	}
}

func (m *OIDCProbeModule) Name() string                         { return "oidc_probe" }
func (m *OIDCProbeModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *OIDCProbeModule) ScanTargetType() model.ScanTargetType { return model.TargetNetwork }

// FileStats returns the number of endpoints scanned and findings matched.
func (m *OIDCProbeModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan probes the OIDC discovery document and JWKS endpoint of a network target.
// target.Value must be a full URL (e.g., "https://idp.example.com").
func (m *OIDCProbeModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Type != model.TargetNetwork {
		return nil
	}
	endpoint := target.Value
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
		return nil
	}

	atomic.AddInt64(&m.lastScanned, 1)

	discoveryURL := strings.TrimRight(endpoint, "/") + "/.well-known/openid-configuration"
	disc, err := m.fetchDiscovery(ctx, discoveryURL)
	if err != nil {
		return nil
	}

	advertisedAlgos := m.collectAdvertisedAlgos(disc)
	coveredAlgos := make(map[string]bool)

	if disc.JwksURI != "" {
		jwks, err := m.fetchJWKS(ctx, disc.JwksURI)
		if err == nil {
			for _, key := range jwks.Keys {
				if strings.EqualFold(key.Use, "enc") {
					continue
				}
				algo := normalizeJWAAlgorithm(key.Alg, key.Kty, key.Crv)
				keySize := deriveKeySize(key)
				coveredAlgos[algo] = true

				asset := &model.CryptoAsset{
					Algorithm: algo,
					KeySize:   keySize,
					Purpose:   "signing",
					Function:  "OIDC token signing",
				}
				crypto.ClassifyCryptoAsset(asset)
				m.emitFinding(ctx, endpoint, asset, "network-probe", 0.90, findings)
				atomic.AddInt64(&m.lastMatched, 1)
			}
		}
	}

	for _, jwaAlg := range advertisedAlgos {
		if strings.EqualFold(jwaAlg, "none") {
			continue
		}
		canonical := normalizeJWAAlgorithm(jwaAlg, "", "")
		if coveredAlgos[canonical] {
			continue
		}
		coveredAlgos[canonical] = true

		asset := &model.CryptoAsset{
			Algorithm: canonical,
			Purpose:   "signing",
			Function:  "OIDC advertised algorithm (no deployed key)",
		}
		crypto.ClassifyCryptoAsset(asset)
		m.emitFinding(ctx, endpoint, asset, "configuration", 0.60, findings)
	}

	if strings.HasPrefix(endpoint, "http://") {
		asset := &model.CryptoAsset{
			Algorithm:         "NONE",
			Purpose:           "transport",
			Function:          "OIDC discovery over insecure HTTP",
			ComplianceWarning: "OIDC discovery document served without TLS",
		}
		m.emitFinding(ctx, endpoint, asset, "configuration", 0.50, findings)
	}

	return nil
}

func (m *OIDCProbeModule) emitFinding(ctx context.Context, endpoint string, asset *model.CryptoAsset, method string, confidence float64, findings chan<- *model.Finding) {
	select {
	case findings <- &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 8,
		Source: model.FindingSource{
			Type:            "network",
			Endpoint:        endpoint,
			DetectionMethod: method,
		},
		CryptoAsset: asset,
		Confidence:  confidence,
		Module:      "oidc_probe",
		Timestamp:   time.Now(),
	}:
	case <-ctx.Done():
	}
}

func (m *OIDCProbeModule) fetchDiscovery(ctx context.Context, url string) (*oidcDiscovery, error) {
	body, err := m.httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	var disc oidcDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return nil, fmt.Errorf("oidc_probe: parse discovery: %w", err)
	}
	return &disc, nil
}

func (m *OIDCProbeModule) fetchJWKS(ctx context.Context, url string) (*jwkSet, error) {
	body, err := m.httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	var jwks jwkSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("oidc_probe: parse jwks: %w", err)
	}
	return &jwks, nil
}

func (m *OIDCProbeModule) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc_probe: %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, oidcMaxResponseLen))
}

func (m *OIDCProbeModule) collectAdvertisedAlgos(disc *oidcDiscovery) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range [][]string{
		disc.IDTokenSigningAlgValues,
		disc.TokenEndpointAuthSigningAlg,
		disc.UserinfoSigningAlgValues,
		disc.RequestObjectSigningAlgValues,
	} {
		for _, alg := range list {
			if !seen[alg] {
				seen[alg] = true
				out = append(out, alg)
			}
		}
	}
	return out
}
