package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestOIDCAlgoNormalization(t *testing.T) {
	tests := []struct {
		jwa, kty, crv, want string
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
			assert.Equal(t, tt.want, normalizeJWAAlgorithm(tt.jwa, tt.kty, tt.crv))
		})
	}
}

func TestJWKKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  jwkKey
		want int
	}{
		{"RSA-2048", jwkKey{Kty: "RSA", N: rsaModulus2048}, 2048},
		{"EC P-256", jwkKey{Kty: "EC", Crv: "P-256"}, 256},
		{"EC P-384", jwkKey{Kty: "EC", Crv: "P-384"}, 384},
		{"EC P-521", jwkKey{Kty: "EC", Crv: "P-521"}, 521},
		{"OKP Ed25519", jwkKey{Kty: "OKP", Crv: "Ed25519"}, 256},
		{"OKP Ed448", jwkKey{Kty: "OKP", Crv: "Ed448"}, 456},
		{"unknown", jwkKey{Kty: "UNKNOWN"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deriveKeySize(tt.key))
		})
	}
}

// rsaModulus2048 is a 256-byte base64url-encoded RSA modulus (2048 bits).
const rsaModulus2048 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV" +
	"T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc" +
	"5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnY" +
	"b9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4l" +
	"FxvMbf6VH7Tk0A3jxNqkpMfN5SOD4bnfVMIfkRJKnWMwLPHQ"

func TestOIDCProbe_HappyPath(t *testing.T) {
	// Use a TLS test server to avoid triggering the insecure-HTTP warning finding.
	// The discovery doc's jwks_uri must reference the server's own URL,
	// so we capture it after the server starts.
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 srvURL + "/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256"},
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "RSA", Alg: "RS256", Kid: "rsa-1", Use: "sig", N: rsaModulus2048},
					{Kty: "EC", Alg: "ES256", Kid: "ec-1", Use: "sig", Crv: "P-256"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := &scannerconfig.Config{Profile: "standard"}
	// srv.Client() is pre-configured to trust the test server's TLS certificate.
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

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
		Value: srv.URL,
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
		assert.Contains(t, f.Source.Endpoint, srv.URL)
		assert.Equal(t, "oidc_probe", f.Module)
		assert.Equal(t, 8, f.Category)
		algos = append(algos, f.CryptoAsset.Algorithm)
	}
	assert.ElementsMatch(t, []string{"RSA", "ECDSA-P256"}, algos)

	for _, f := range collected {
		if f.CryptoAsset.Algorithm == "RSA" {
			assert.Equal(t, 2048, f.CryptoAsset.KeySize)
		}
		if f.CryptoAsset.Algorithm == "ECDSA-P256" {
			assert.Equal(t, 256, f.CryptoAsset.KeySize)
		}
	}
}

// TestOIDCProbe_AdvertisedNotInUse — discovery advertises RS256+ES256+ES384,
// JWKS has only one ES256 key. Expect 1 JWK key finding (ES256, confidence 0.90)
// + 2 advertised findings (RS256+ES384, confidence 0.60, method "configuration").
func TestOIDCProbe_AdvertisedNotInUse(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 srvURL + "/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256", "ES384"},
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "EC", Alg: "ES256", Kid: "ec-1", Use: "sig", Crv: "P-256"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)

	require.Len(t, collected, 3, "expected 1 JWK + 2 advertised findings")

	var jwkFindings, advFindings []*model.Finding
	for _, f := range collected {
		if f.Confidence == 0.90 {
			jwkFindings = append(jwkFindings, f)
		} else {
			advFindings = append(advFindings, f)
		}
	}

	require.Len(t, jwkFindings, 1, "expected 1 JWK key finding")
	assert.Equal(t, "ECDSA-P256", jwkFindings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "network-probe", jwkFindings[0].Source.DetectionMethod)

	require.Len(t, advFindings, 2, "expected 2 advertised-only findings")
	var advAlgos []string
	for _, f := range advFindings {
		assert.Equal(t, 0.60, f.Confidence)
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
		advAlgos = append(advAlgos, f.CryptoAsset.Algorithm)
	}
	assert.ElementsMatch(t, []string{"RSA", "ECDSA-P384"}, advAlgos)
}

// TestOIDCProbe_DiscoveryNotFound — server returns 404 for everything.
// Expect: no error, zero findings.
func TestOIDCProbe_DiscoveryNotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)
	assert.Empty(t, collected, "expected zero findings when discovery returns 404")
}

// TestOIDCProbe_JWKSFetchFails — discovery returns valid doc with a jwks_uri
// pointing to a URL that returns 500. Advertised-algo findings should still emit.
func TestOIDCProbe_JWKSFetchFails(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI:                 srvURL + "/jwks",
				IDTokenSigningAlgValues: []string{"RS256", "ES256"},
			})
		case "/jwks":
			http.Error(w, "internal server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)

	// No JWK key findings (JWKS fetch failed), but advertised algos should appear.
	assert.NotEmpty(t, collected, "expected advertised-algo findings even when JWKS fails")
	for _, f := range collected {
		assert.Equal(t, 0.60, f.Confidence, "all findings should be advertised (0.60)")
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
	}
	var algos []string
	for _, f := range collected {
		algos = append(algos, f.CryptoAsset.Algorithm)
	}
	assert.ElementsMatch(t, []string{"RSA", "ECDSA-P256"}, algos)
}

// TestOIDCProbe_MalformedJSON — server returns invalid JSON for discovery.
// Expect: no error, zero findings.
func TestOIDCProbe_MalformedJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{this is not valid json`))
	}))
	defer srv.Close()

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)
	assert.Empty(t, collected, "expected zero findings on malformed JSON")
}

// TestOIDCProbe_Timeout — server handler sleeps 5 seconds, context has 100ms timeout.
// Expect: clean termination, no error.
func TestOIDCProbe_Timeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	err := m.Scan(ctx, model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: srv.URL,
	}, findings)
	close(findings)
	<-done

	require.NoError(t, err, "Scan must not return an error on timeout")
	assert.Empty(t, collected, "expected zero findings on context timeout")
}

// TestOIDCProbe_NoAlgOnKey — JWKS has one key with no `alg` field.
// Algorithm should be inferred from kty+crv. Key size should be 256.
func TestOIDCProbe_NoAlgOnKey(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI: srvURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "EC", Crv: "P-256", Kid: "noalg", Use: "sig"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)

	require.Len(t, collected, 1, "expected 1 finding for the key with no alg field")
	f := collected[0]
	assert.Equal(t, "ECDSA-P256", f.CryptoAsset.Algorithm, "algorithm should be inferred from crv=P-256")
	assert.Equal(t, 256, f.CryptoAsset.KeySize)
	assert.Equal(t, 0.90, f.Confidence)
}

// TestOIDCProbe_SkipsEncryptionKeys — JWKS has two keys: one enc (RSA) and one sig (EC).
// Only the sig key should produce a finding.
func TestOIDCProbe_SkipsEncryptionKeys(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscovery{
				JwksURI: srvURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwkSet{
				Keys: []jwkKey{
					{Kty: "RSA", Alg: "RSA-OAEP", Kid: "enc-1", Use: "enc", N: rsaModulus2048},
					{Kty: "EC", Alg: "ES256", Kid: "sig-1", Use: "sig", Crv: "P-256"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: srv.Client()}

	collected := oidcScan(t, m, srv.URL)

	require.Len(t, collected, 1, "expected only the sig key finding, enc key must be skipped")
	assert.Equal(t, "ECDSA-P256", collected[0].CryptoAsset.Algorithm)
}

// TestOIDCProbe_SkipsNonURLTargets — host:port format should produce zero findings
// (that format is for protocol scanner, not OIDC probe).
func TestOIDCProbe_SkipsNonURLTargets(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OIDCProbeModule{config: cfg, httpClient: http.DefaultClient}

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
		Value: "192.168.1.1:443",
	}, findings)
	close(findings)
	<-done

	require.NoError(t, err)
	assert.Empty(t, collected, "host:port target should produce zero findings")
}

// oidcScan is a test helper that runs OIDCProbeModule.Scan and returns all findings.
func oidcScan(t *testing.T, m *OIDCProbeModule, endpoint string) []*model.Finding {
	t.Helper()
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
		Value: endpoint,
	}, findings)
	close(findings)
	<-done
	require.NoError(t, err)
	return collected
}
