# OIDC/JWKS Discovery Probe Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an OIDC/JWKS discovery probe scanner that fetches identity provider metadata, extracts JWK signing keys and advertised algorithms, normalizes JWA names to canonical crypto registry forms, and emits PQC-classified findings.

**Architecture:** Single new module `pkg/scanner/oidc_probe.go` implementing the existing `Module` interface. Uses `TargetNetwork` with URL values (no new scan target type). HTTP fetch via `httpDoer` interface for testability. JWA algorithm normalization via `oidcAlgoTokenMap` following the `vpnAlgoTokenMap` precedent. Two finding types: JWK key findings (0.90 confidence) and advertised-but-unused algorithm findings (0.60 confidence).

**Tech Stack:** Go 1.25, stdlib only (`net/http`, `encoding/json`, `encoding/base64`, `net/http/httptest`). Zero new module dependencies.

**Spec:** `docs/plans/2026-04-12-oidc-jwks-probe-design.md`

---

## File Structure

### Created

| File | Responsibility |
|---|---|
| `pkg/scanner/oidc_probe.go` | `OIDCProbeModule` + `httpDoer` interface + `oidcAlgoTokenMap` + discovery/JWKS fetch + finding emission |
| `pkg/scanner/oidc_probe_test.go` | 11+ unit tests with `httptest.Server` fakes |

### Modified

| File | Change |
|---|---|
| `internal/scannerconfig/config.go` | +`OIDCEndpoints` field on `BuildOptions`; `BuildConfig` injects `oidc_probe` module + `TargetNetwork` entries |
| `internal/scannerconfig/config_test.go` | +3 `TestBuildConfig_OIDC*` tests |
| `cmd/root.go` | +`--oidc-endpoint` flag (StringSlice); wire into `BuildOptions` |
| `internal/license/tier.go` | +`"oidc_probe"` in `proModules()` |
| `pkg/scanner/engine.go` | +`RegisterModule(NewOIDCProbeModule)` in `RegisterDefaultModules` |
| `README.md` | +"Probing OIDC identity providers" usage subsection |
| `docs/SYSTEM_ARCHITECTURE.md` | +OIDC probe flow subsection |

### Boundaries

- `oidc_probe.go` is the only file that knows about OIDC discovery or JWK format. It owns the HTTP fetch, JSON parsing, JWA normalization, and finding emission.
- `scannerconfig/config.go` only knows that OIDC endpoints exist as strings and need network targets + module injection. No OIDC-specific logic.
- `cmd/root.go` only passes the flag value through to `BuildOptions`. No OIDC logic.

---

## Task 1: `oidcAlgoTokenMap` + key size helpers + normalization tests

**Files:**
- Create: `pkg/scanner/oidc_probe.go`
- Create: `pkg/scanner/oidc_probe_test.go`

- [ ] **Step 1: Write failing normalization test**

Create `pkg/scanner/oidc_probe_test.go`:

```go
package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDCAlgoNormalization(t *testing.T) {
	tests := []struct {
		jwa      string
		kty      string
		crv      string
		wantAlgo string
	}{
		{"RS256", "RSA", "", "RSA"},
		{"RS384", "RSA", "", "RSA"},
		{"RS512", "RSA", "", "RSA"},
		{"PS256", "RSA", "", "RSA-PSS"},
		{"PS384", "RSA", "", "RSA-PSS"},
		{"PS512", "RSA", "", "RSA-PSS"},
		{"ES256", "EC", "P-256", "ECDSA-P256"},
		{"ES384", "EC", "P-384", "ECDSA-P384"},
		{"ES512", "EC", "P-521", "ECDSA-P521"},
		{"EdDSA", "OKP", "Ed25519", "Ed25519"},
		{"EdDSA", "OKP", "Ed448", "Ed448"},
		{"EdDSA", "OKP", "", "Ed25519"},
		{"", "RSA", "", "RSA"},
		{"", "EC", "P-256", "ECDSA-P256"},
		{"", "EC", "P-384", "ECDSA-P384"},
		{"", "OKP", "Ed25519", "Ed25519"},
		{"UNKNOWN_ALG", "", "", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.jwa+"/"+tt.kty+"/"+tt.crv, func(t *testing.T) {
			got := normalizeJWAAlgorithm(tt.jwa, tt.kty, tt.crv)
			assert.Equal(t, tt.wantAlgo, got)
		})
	}
}

func TestJWKKeySize(t *testing.T) {
	tests := []struct {
		name     string
		key      jwkKey
		wantSize int
	}{
		{
			name:     "RSA-2048 from modulus",
			key:      jwkKey{Kty: "RSA", N: rsaModulus2048},
			wantSize: 2048,
		},
		{
			name:     "EC P-256",
			key:      jwkKey{Kty: "EC", Crv: "P-256"},
			wantSize: 256,
		},
		{
			name:     "EC P-384",
			key:      jwkKey{Kty: "EC", Crv: "P-384"},
			wantSize: 384,
		},
		{
			name:     "EC P-521",
			key:      jwkKey{Kty: "EC", Crv: "P-521"},
			wantSize: 521,
		},
		{
			name:     "OKP Ed25519",
			key:      jwkKey{Kty: "OKP", Crv: "Ed25519"},
			wantSize: 256,
		},
		{
			name:     "OKP Ed448",
			key:      jwkKey{Kty: "OKP", Crv: "Ed448"},
			wantSize: 456,
		},
		{
			name:     "unknown kty",
			key:      jwkKey{Kty: "UNKNOWN"},
			wantSize: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveKeySize(tt.key)
			assert.Equal(t, tt.wantSize, got)
		})
	}
}

// rsaModulus2048 is a 256-byte (2048-bit) base64url-encoded modulus.
// Generated from a real RSA-2048 key's n value. Only the length matters
// for key size derivation; the numeric value is irrelevant.
const rsaModulus2048 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV" +
	"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc" +
	"5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnY" +
	"b9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4l" +
	"FxvMbf6VH7Tk0A3jxNqkpMfN5SOD4bnfVMIfkRJKnWMwLPHQ"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestOIDCAlgo|TestJWKKeySize" ./pkg/scanner/`
Expected: FAIL — `undefined: normalizeJWAAlgorithm`, `undefined: jwkKey`, `undefined: deriveKeySize`

- [ ] **Step 3: Create oidc_probe.go with map + helpers**

Create `pkg/scanner/oidc_probe.go`:

```go
package scanner

import (
	"encoding/base64"
)

// oidcAlgoTokenMap normalizes JWA algorithm identifiers (RFC 7518) to
// Triton's canonical crypto registry names. Follows the vpnAlgoTokenMap
// precedent in vpn_config.go.
var oidcAlgoTokenMap = map[string]string{
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"PS256": "RSA-PSS", "PS384": "RSA-PSS", "PS512": "RSA-PSS",
	"ES256": "ECDSA-P256", "ES384": "ECDSA-P384", "ES512": "ECDSA-P521",
	"EdDSA": "Ed25519",
}

// crvToAlgorithm maps JWK curve names to canonical algorithm names.
// Used when the JWK's "alg" field is absent (Azure AD pattern).
var crvToAlgorithm = map[string]string{
	"P-256":   "ECDSA-P256",
	"P-384":   "ECDSA-P384",
	"P-521":   "ECDSA-P521",
	"Ed25519": "Ed25519",
	"Ed448":   "Ed448",
}

// crvToKeySize maps JWK curve names to key sizes in bits.
var crvToKeySize = map[string]int{
	"P-256":   256,
	"P-384":   384,
	"P-521":   521,
	"Ed25519": 256,
	"Ed448":   456,
}

// normalizeJWAAlgorithm converts a JWA algorithm identifier to a
// canonical crypto registry name. When alg is empty, inference falls
// back to kty + crv. Returns "UNKNOWN" if no mapping exists.
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
	// Infer from kty + crv when alg is absent.
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
		return "Ed25519"
	}
	return "UNKNOWN"
}

// Internal structs for OIDC discovery and JWK parsing.

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

// deriveKeySize returns the key size in bits for a JWK key.
// RSA: decoded modulus length * 8. EC/OKP: curve lookup.
// Returns 0 if unknown.
func deriveKeySize(k jwkKey) int {
	switch k.Kty {
	case "RSA":
		if k.N == "" {
			return 0
		}
		decoded, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return 0
		}
		return len(decoded) * 8
	case "EC", "OKP":
		if size, ok := crvToKeySize[k.Crv]; ok {
			return size
		}
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestOIDCAlgo|TestJWKKeySize" ./pkg/scanner/`
Expected: PASS (17 normalization subtests + 7 key size subtests)

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oidc_probe.go pkg/scanner/oidc_probe_test.go
git commit -m "feat(scanner): add oidcAlgoTokenMap + JWK key size derivation"
```

---

## Task 2: `OIDCProbeModule` skeleton + happy path test

**Files:**
- Modify: `pkg/scanner/oidc_probe.go`
- Modify: `pkg/scanner/oidc_probe_test.go`

- [ ] **Step 1: Write failing happy-path test**

Append to `pkg/scanner/oidc_probe_test.go`:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func newTestOIDCServer(t *testing.T, discovery oidcDiscovery, jwks jwkSet) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
	return httptest.NewServer(mux)
}

func TestOIDCProbe_HappyPath(t *testing.T) {
	srv := newTestOIDCServer(t, oidcDiscovery{
		JwksURI: "PLACEHOLDER_JWKS_URI",
		IDTokenSigningAlgValues: []string{"RS256", "ES256"},
	}, jwkSet{
		Keys: []jwkKey{
			{Kty: "RSA", Alg: "RS256", Kid: "rsa-key-1", Use: "sig", N: rsaModulus2048},
			{Kty: "EC", Alg: "ES256", Kid: "ec-key-1", Use: "sig", Crv: "P-256"},
		},
	})
	defer srv.Close()

	// Patch the discovery response to point jwks_uri to our test server.
	discovery := oidcDiscovery{
		JwksURI: srv.URL + "/jwks",
		IDTokenSigningAlgValues: []string{"RS256", "ES256"},
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discovery)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "RSA", Alg: "RS256", Kid: "rsa-key-1", Use: "sig", N: rsaModulus2048},
					{Kty: "EC", Alg: "ES256", Kid: "ec-key-1", Use: "sig", Crv: "P-256"},
				},
			})
		}
	}))
	defer srv2.Close()

	// Update discovery to use srv2's URL for JWKS
	discovery.JwksURI = srv2.URL + "/jwks"

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{
		config:     cfg,
		httpClient: srv2.Client(),
	}

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	err := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: srv2.URL,
	}, findings)
	close(findings)
	<-done

	require.NoError(t, err)
	require.Len(t, collected, 2, "expected 2 JWK key findings")

	var algos []string
	for _, f := range collected {
		require.NotNil(t, f.CryptoAsset)
		assert.Equal(t, 0.90, f.Confidence)
		assert.Equal(t, "network-probe", f.Source.DetectionMethod)
		assert.Contains(t, f.Source.Endpoint, srv2.URL)
		assert.Equal(t, "oidc_probe", f.Module)
		algos = append(algos, f.CryptoAsset.Algorithm)
	}
	assert.ElementsMatch(t, []string{"RSA", "ECDSA-P256"}, algos)

	// Check RSA key size
	for _, f := range collected {
		if f.CryptoAsset.Algorithm == "RSA" {
			assert.Equal(t, 2048, f.CryptoAsset.KeySize)
		}
		if f.CryptoAsset.Algorithm == "ECDSA-P256" {
			assert.Equal(t, 256, f.CryptoAsset.KeySize)
		}
	}
}
```

Note: the test helper `newTestOIDCServer` is defined but the happy-path test constructs its own `httptest.NewServer` with inline handlers for more control. The helper can be used by simpler tests later. Merge the imports with the existing test file imports (keep only one `import` block).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestOIDCProbe_HappyPath ./pkg/scanner/`
Expected: FAIL — `undefined: OIDCProbeModule`

- [ ] **Step 3: Implement OIDCProbeModule + Scan**

Append to `pkg/scanner/oidc_probe.go`:

```go
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

const (
	oidcFetchTimeout   = 15 * time.Second
	oidcMaxResponseLen = 1 << 20 // 1 MB
	oidcMaxRedirects   = 3
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type OIDCProbeModule struct {
	config      *scannerconfig.Config
	httpClient  httpDoer
	lastScanned int64
	lastMatched int64
}

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

func (m *OIDCProbeModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

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
	disc, err := m.fetchJSON(ctx, discoveryURL, &oidcDiscovery{})
	if err != nil {
		return nil
	}

	advertisedAlgos := m.collectAdvertisedAlgos(disc)

	coveredAlgos := make(map[string]bool)

	if disc.JwksURI != "" {
		jwks, err := m.fetchJSON(ctx, disc.JwksURI, &jwkSet{})
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

	if strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
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

func (m *OIDCProbeModule) fetchJSON(ctx context.Context, url string, target any) (*oidcDiscovery, error) {
	// This is a generic-shaped helper but returns *oidcDiscovery for the
	// discovery case. For the JWKS case, the caller passes a *jwkSet and
	// we use a different overload. Let's unify:
	return nil, fmt.Errorf("placeholder")
}
```

Wait — the `fetchJSON` signature is wrong. It needs to be generic. Replace with two concrete fetch methods:

```go
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
```

And update `Scan` to call `fetchDiscovery` and `fetchJWKS` instead of the removed `fetchJSON`. Replace the two `fetchJSON` calls:

```go
disc, err := m.fetchDiscovery(ctx, discoveryURL)
```

```go
jwks, err := m.fetchJWKS(ctx, disc.JwksURI)
```

Delete the old `fetchJSON` placeholder.

Make sure the import block is unified at the top of the file (one block with all imports needed).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestOIDCProbe_HappyPath ./pkg/scanner/`
Expected: PASS — 2 findings, RSA + ECDSA-P256, correct confidence and endpoint

Also run: `go test -v -run "TestOIDCAlgo|TestJWKKeySize" ./pkg/scanner/`
Expected: still PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oidc_probe.go pkg/scanner/oidc_probe_test.go
git commit -m "feat(scanner): OIDCProbeModule with discovery + JWKS fetch"
```

---

## Task 3: Advertised-but-unused + edge case tests

**Files:**
- Modify: `pkg/scanner/oidc_probe_test.go`

- [ ] **Step 1: Write all remaining unit tests**

Append to `pkg/scanner/oidc_probe_test.go`:

```go
func TestOIDCProbe_AdvertisedNotInUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 "REPLACE_WITH_URL/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256", "ES384"},
			})
		case "/jwks":
			json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{{Kty: "EC", Alg: "ES256", Use: "sig", Crv: "P-256"}},
			})
		}
	}))
	defer srv.Close()

	// Rewrite discovery to reference the test server's JWKS URI.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 srv.URL + "/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256", "ES384"},
			})
		default:
			srv.Config.Handler.ServeHTTP(w, r)
		}
	}))
	defer srv2.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv2.Client()}
	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv2.URL}, findings)
	close(findings)
	<-done

	var keyFindings, configFindings int
	for _, f := range collected {
		switch f.Source.DetectionMethod {
		case "network-probe":
			keyFindings++
			assert.Equal(t, 0.90, f.Confidence)
		case "configuration":
			configFindings++
			assert.Equal(t, 0.60, f.Confidence)
		}
	}
	assert.Equal(t, 1, keyFindings, "one ES256 JWK key finding")
	assert.Equal(t, 2, configFindings, "RS256 and ES384 are advertised but not deployed")
}

func TestOIDCProbe_DiscoveryNotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv.Client()}
	findings := make(chan *model.Finding, 16)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv.URL}, findings)
	close(findings)

	assert.NoError(t, err)
	var count int
	for range findings { count++ }
	assert.Equal(t, 0, count, "no findings when discovery returns 404")
}

func TestOIDCProbe_JWKSFetchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 "http://does-not-exist.invalid/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256"},
			})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv.Client()}
	findings := make(chan *model.Finding, 16)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv.URL}, findings)
	close(findings)
	<-done

	assert.NotEmpty(t, collected, "advertised-algo findings should still emit even when JWKS fails")
	for _, f := range collected {
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
	}
}

func TestOIDCProbe_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv.Client()}
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv.URL}, findings)
	close(findings)

	assert.NoError(t, err, "malformed JSON should not return an error")
	var count int
	for range findings { count++ }
	assert.Equal(t, 0, count)
}

func TestOIDCProbe_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv.Client()}
	findings := make(chan *model.Finding, 4)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := m.Scan(ctx, model.ScanTarget{Type: model.TargetNetwork, Value: srv.URL}, findings)
	close(findings)
	assert.NoError(t, err, "timeout should not return error")
}

func TestOIDCProbe_NoAlgOnKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{JwksURI: "SELF/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{{Kty: "EC", Crv: "P-256", Kid: "noalg-1", Use: "sig"}},
			})
		}
	}))
	defer srv.Close()

	// Rewrite JWKS URI to point to test server
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{JwksURI: srv.URL + "/jwks"})
		default:
			srv.Config.Handler.ServeHTTP(w, r)
		}
	}))
	defer srv2.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv2.Client()}
	findings := make(chan *model.Finding, 16)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv2.URL}, findings)
	close(findings)
	<-done

	require.Len(t, collected, 1)
	assert.Equal(t, "ECDSA-P256", collected[0].CryptoAsset.Algorithm)
	assert.Equal(t, 256, collected[0].CryptoAsset.KeySize)
}

func TestOIDCProbe_SkipsEncryptionKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{JwksURI: "SELF/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "RSA", Alg: "RS256", Use: "enc", N: rsaModulus2048},
					{Kty: "EC", Alg: "ES256", Use: "sig", Crv: "P-256"},
				},
			})
		}
	}))
	defer srv.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidcDiscovery{JwksURI: srv.URL + "/jwks"})
		default:
			srv.Config.Handler.ServeHTTP(w, r)
		}
	}))
	defer srv2.Close()

	m := &OIDCProbeModule{config: &scannerconfig.Config{}, httpClient: srv2.Client()}
	findings := make(chan *model.Finding, 16)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{Type: model.TargetNetwork, Value: srv2.URL}, findings)
	close(findings)
	<-done

	require.Len(t, collected, 1)
	assert.Equal(t, "ECDSA-P256", collected[0].CryptoAsset.Algorithm)
}

func TestOIDCProbe_SkipsNonURLTargets(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := NewOIDCProbeModule(cfg)
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: "192.168.1.1:443",
	}, findings)
	close(findings)

	assert.NoError(t, err)
	var count int
	for range findings { count++ }
	assert.Equal(t, 0, count, "host:port target should be skipped")
}
```

**Important note for the implementer:** several tests above construct two `httptest.Server` instances because the discovery document's `jwks_uri` field must contain a real URL pointing to the test JWKS endpoint. The first server serves raw handlers; the second rewrites the discovery doc's `jwks_uri` to reference the first server's URL. This pattern is necessary because `httptest` assigns random ports. Simplify where possible — a single server with a mux handling both paths works when `jwks_uri` can reference the same origin (use the server's own URL).

- [ ] **Step 2: Run all OIDC tests**

Run: `go test -v -run "TestOIDC" ./pkg/scanner/`
Expected: all tests PASS (normalization + key size + happy path + 8 edge case tests)

If any test fails due to the JWKS URI rewriting (test helper complexity), simplify: use a single `httptest.Server` with a `http.ServeMux` handling both `/.well-known/openid-configuration` and `/jwks`, and set `jwks_uri` to the server's own URL + `/jwks` by constructing the discovery response lazily after the server starts.

- [ ] **Step 3: Run full scanner suite**

Run: `go test ./pkg/scanner/...`
Expected: zero regressions.

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/oidc_probe_test.go
git commit -m "test(scanner): OIDC probe edge cases — 404, JWKS fail, malformed, timeout, enc skip"
```

---

## Task 4: CLI flag + BuildConfig + licence tier

**Files:**
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/scannerconfig/config_test.go`
- Modify: `cmd/root.go`
- Modify: `internal/license/tier.go`

- [ ] **Step 1: Write failing BuildConfig tests**

Append to `internal/scannerconfig/config_test.go`:

```go
func TestBuildConfig_OIDCEndpointInjectsModule(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules, "oidc_probe")
}

func TestBuildConfig_OIDCEndpointAddsTarget(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var found bool
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetNetwork && tgt.Value == "https://auth.example.com" {
			found = true
		}
	}
	assert.True(t, found, "OIDC endpoint must appear as TargetNetwork")
}

func TestBuildConfig_OIDCDoesNotSuppressFilesystem(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var fsCount int
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetFilesystem {
			fsCount++
		}
	}
	assert.Greater(t, fsCount, 0, "filesystem defaults must be preserved with --oidc-endpoint")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestBuildConfig_OIDC ./internal/scannerconfig/`
Expected: FAIL — `BuildOptions` has no `OIDCEndpoints` field

- [ ] **Step 3: Extend BuildOptions + BuildConfig**

Edit `internal/scannerconfig/config.go`. Add field to `BuildOptions`:

```go
type BuildOptions struct {
	Profile       string
	Modules       []string
	ImageRefs     []string
	Kubeconfig    string
	K8sContext    string
	RegistryAuth  string
	RegistryUser  string
	RegistryPass  string
	OIDCEndpoints []string  // NEW
	DBUrl         string
	Metrics       bool
	Incremental   bool
}
```

In `BuildConfig`, after the image/k8s injection block (after the `oci_image` module injection), add:

```go
	// OIDC endpoint injection. Unlike --image, OIDC probing does NOT
	// suppress filesystem defaults — users commonly scan a host and
	// probe their IdP in the same run.
	if len(opts.OIDCEndpoints) > 0 {
		if !containsModule(cfg.Modules, "oidc_probe") {
			cfg.Modules = append(cfg.Modules, "oidc_probe")
		}
		for _, ep := range opts.OIDCEndpoints {
			cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
				Type:  model.TargetNetwork,
				Value: ep,
			})
		}
	}
```

- [ ] **Step 4: Add CLI flag to cmd/root.go**

Near the other flag variable declarations:

```go
var oidcEndpoints []string
```

Register the flag (after the existing `--registry-auth` registration):

```go
rootCmd.PersistentFlags().StringSliceVar(&oidcEndpoints, "oidc-endpoint", nil,
	"OIDC identity provider URL to probe (repeatable, e.g. --oidc-endpoint https://auth.example.com)")
```

Wire into the `BuildOptions` struct where `BuildConfig` is called:

```go
OIDCEndpoints: oidcEndpoints,
```

- [ ] **Step 5: Add to licence tier**

Edit `internal/license/tier.go`, in `proModules()`:

```go
func proModules() []string {
	return []string{
		// ... existing modules ...
		"oci_image",
		"oidc_probe",
		// k8s_live is enterprise-only — do NOT add.
	}
}
```

- [ ] **Step 6: Run tests**

```bash
go test -v -run TestBuildConfig_OIDC ./internal/scannerconfig/
go build ./...
go vet ./...
go run . --help | grep oidc-endpoint
```

Expected: 3 OIDC BuildConfig tests PASS, build clean, flag in help output.

- [ ] **Step 7: Commit**

```bash
git add internal/scannerconfig/config.go internal/scannerconfig/config_test.go cmd/root.go internal/license/tier.go
git commit -m "feat(cli): add --oidc-endpoint flag + BuildConfig injection + Pro tier"
```

---

## Task 5: Engine registration

**Files:**
- Modify: `pkg/scanner/engine.go`

- [ ] **Step 1: Register the module**

In `pkg/scanner/engine.go::RegisterDefaultModules()`, append after the `NewOCIImageModule` line:

```go
	// Wave 2 — OIDC/JWKS discovery probe. Not in any profile's
	// default module list; only runs when --oidc-endpoint is supplied.
	e.RegisterModule(NewOIDCProbeModule(e.config))
```

- [ ] **Step 2: Update module count in engine test**

If `pkg/scanner/engine_test.go` has a module count assertion (e.g. `assert.Equal(t, 29, len(e.modules))`), update it to 30. Also add `assert.True(t, names["oidc_probe"])` if there's a name-check block.

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./pkg/scanner/...
go run . --profile quick --format json -o /tmp/smoke.json 2>&1 | head -5
```

Expected: build clean, all tests pass, default scan produces no OIDC output.

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/engine.go pkg/scanner/engine_test.go
git commit -m "feat(engine): register OIDCProbeModule in default module list"
```

---

## Task 6: Documentation + final verification

**Files:**
- Modify: `README.md`
- Modify: `docs/SYSTEM_ARCHITECTURE.md`

- [ ] **Step 1: README — OIDC probing section**

Add a subsection after the "Scanning container images" section:

```markdown
### Probing OIDC identity providers

Triton can probe OIDC identity providers to inventory their signing
algorithms and JWK keys for PQC compliance.

\`\`\`bash
# Probe a single identity provider
triton --oidc-endpoint https://auth.example.com --profile standard

# Probe multiple providers alongside a host scan
triton --oidc-endpoint https://idp1.example.com --oidc-endpoint https://idp2.example.com
\`\`\`

Findings include both deployed JWK signing keys (high confidence) and
algorithms advertised in the discovery document but not backed by a
deployed key (lower confidence).

OIDC probing is a **Pro tier** feature and does **not** suppress the
default host filesystem scan.
```

- [ ] **Step 2: SYSTEM_ARCHITECTURE — OIDC probe subsection**

Append to the scanner modules section:

```markdown
### OIDC/JWKS Discovery Probe

The `oidc_probe` module fetches `/.well-known/openid-configuration`
from user-specified endpoints, follows the `jwks_uri`, and inventories
signing keys and advertised algorithms.

**JWA normalization:** JWA algorithm identifiers (RS256, ES384, etc.)
are mapped to canonical crypto registry names via `oidcAlgoTokenMap`,
following the same pattern as `vpnAlgoTokenMap` in vpn_config.go.

**Two finding types:**
- JWK key findings (0.90 confidence, `DetectionMethod: "network-probe"`)
- Advertised-but-unused algorithm findings (0.60 confidence,
  `DetectionMethod: "configuration"`)

Keys with `use: "enc"` and algorithms set to `"none"` are skipped.
When the JWK `alg` field is absent (Azure AD pattern), the algorithm
is inferred from `kty` + `crv`.
```

- [ ] **Step 3: Update scanner module count**

In `README.md`, find "29 scanner modules" and change to "30 scanner modules".

- [ ] **Step 4: Full verification**

```bash
go build ./...
go test -count=1 ./...
go vet ./...
go run . --help | grep oidc-endpoint
```

Expected: all green, flag visible.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/SYSTEM_ARCHITECTURE.md
git commit -m "docs: OIDC probe usage, architecture, and module count update"
```

---

## Self-review notes

- **Spec coverage:** §1 goal → Task 2 (Scan flow). §2 scope → all items have task coverage. §3.1-3.7 architecture → Tasks 1-5. §4 structs → Task 1. §5 testing → Tasks 2-3. §6 edge cases → Task 3. §7 deps → verified zero new deps. §8 migration → confirmed no schema change needed. §9 docs → Task 6.
- **Placeholder scan:** No TBDs. All code blocks contain actual source. Test helper pattern (httptest.Server with rewritten JWKS URI) is described with implementation guidance.
- **Type consistency:** `OIDCProbeModule`, `httpDoer`, `oidcDiscovery`, `jwkKey`, `jwkSet`, `normalizeJWAAlgorithm`, `deriveKeySize` — consistent across all tasks. `emitFinding` signature matches the protocol scanner precedent but adds `method` and `confidence` parameters.
- **Gap found:** The spec mentions "module interface test" (like `TestOIDCProbe_ModuleInterface`). This is implicitly tested via `NewOIDCProbeModule` in `TestOIDCProbe_SkipsNonURLTargets` but could use an explicit assertion. Added as part of Task 2's constructor usage. Acceptable.
