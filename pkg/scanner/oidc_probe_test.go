package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
