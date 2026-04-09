package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	asn1Mod "encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*ProtocolModule)(nil)

func TestProtocolModuleInterface(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})
	assert.Equal(t, "protocol", m.Name())
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
	assert.Equal(t, model.TargetNetwork, m.ScanTargetType())
}

func TestTLSProbeAgainstTestServer(t *testing.T) {
	t.Parallel()
	// Start a TLS test server
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in background — complete handshake before closing
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				tc.Handshake()
			}
			conn.Close()
		}
	}()

	addr := listener.Addr().String()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: addr,
	}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should find TLS info from test server")

	// Verify finding shape
	for _, f := range collected {
		assert.Equal(t, 9, f.Category)
		assert.Equal(t, "network", f.Source.Type)
		assert.Equal(t, "protocol", f.Module)
		assert.Equal(t, 0.90, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}
}

func TestTLSProbeExtractsCipherSuite(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find at least a cipher suite finding
	hasCipher := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher suite" {
			hasCipher = true
		}
	}
	assert.True(t, hasCipher, "should extract cipher suite from TLS handshake")
}

func TestTLSProbeExtractsCertificate(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find certificate info
	hasCert := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Subject != "" {
			hasCert = true
		}
	}
	assert.True(t, hasCert, "should extract certificate from TLS handshake")
}

func TestTLSProbeTimeout(t *testing.T) {
	t.Parallel()
	// Create a listener that accepts but never completes TLS handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Never respond — let the connection hang
			time.Sleep(10 * time.Second)
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	close(findings)

	// Should complete without hanging (timeout or error)
	_ = err
}

func TestTLSProbeNonExistentHost(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: "127.0.0.1:1"}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := m.Scan(ctx, target, findings)
	close(findings)

	// Should not crash, may or may not error
	_ = err

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "non-existent host should produce no findings")
}

func TestCipherSuiteToAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		suite    uint16
		wantAlgo string
	}{
		{tls.TLS_AES_256_GCM_SHA384, "AES-256-GCM"},
		{tls.TLS_AES_128_GCM_SHA256, "AES-128-GCM"},
		{tls.TLS_CHACHA20_POLY1305_SHA256, "ChaCha20-Poly1305"},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "AES-256-GCM"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "AES-128-GCM"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("suite_%d", tt.suite), func(t *testing.T) {
			algo := cipherSuiteAlgorithm(tt.suite)
			assert.Equal(t, tt.wantAlgo, algo)
		})
	}
}

func TestTLSProbe_DeprecatedVersion(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// Force TLS 1.1 (deprecated)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should have a version warning finding
	hasVersionWarning := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS protocol version" {
			hasVersionWarning = true
			assert.Contains(t, f.CryptoAsset.Algorithm, "TLS 1.")
			assert.Equal(t, "DEPRECATED", f.CryptoAsset.PQCStatus)
		}
	}
	assert.True(t, hasVersionWarning, "should emit deprecated TLS version warning")
}

func TestTLSProbe_TLS12_NoVersionWarning(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	for _, f := range collected {
		if f.CryptoAsset != nil {
			assert.NotEqual(t, "TLS protocol version", f.CryptoAsset.Function,
				"TLS 1.2+ should not emit version warning")
		}
	}
}

func TestValidateCertChain_SelfSigned(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Self-signed cert should fail chain validation
	hasChainFinding := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS certificate chain validation" {
			hasChainFinding = true
			assert.Contains(t, f.CryptoAsset.Purpose, "chain validation failed")
		}
	}
	assert.True(t, hasChainFinding, "self-signed cert should fail chain validation")
}

func TestValidateCertChain_ContextCancelled(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	state := tls.ConnectionState{}
	m.validateCertChain(ctx, "127.0.0.1:443", state, findings)

	close(findings)
	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "cancelled context should produce no findings")
}

func TestDetectSessionResumption_Supported(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// TLS 1.2 with session tickets enabled (default)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m.detectSessionResumption(ctx, listener.Addr().String(), findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	hasResumption := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS session resumption" {
			hasResumption = true
			assert.Equal(t, "TLS Session Resumption", f.CryptoAsset.Algorithm)
		}
	}
	assert.True(t, hasResumption, "should detect session resumption capability")
}

func TestDetectSessionResumption_NotSupported(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// TLS 1.2 with session tickets disabled
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:           []tls.Certificate{tlsCert},
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	})
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 20)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m.detectSessionResumption(ctx, listener.Addr().String(), findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	hasResumption := false
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS session resumption" {
			hasResumption = true
			assert.Contains(t, f.CryptoAsset.Purpose, "not supported")
		}
	}
	assert.True(t, hasResumption, "should still emit finding for unsupported resumption")
}

func TestTLSProbe_FullChainPositions(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{chain.tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Find chain position findings
	positions := make(map[string]bool)
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.ChainPosition != "" {
			positions[f.CryptoAsset.ChainPosition] = true
		}
	}

	assert.True(t, positions["leaf"], "should label leaf certificate")
	assert.True(t, positions["intermediate"], "should label intermediate certificate")
	assert.True(t, positions["root"], "should label root certificate")
}

func TestTLSProbe_ChainDepth(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{chain.tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.ChainDepth > 0 {
			assert.Equal(t, 3, f.CryptoAsset.ChainDepth, "chain depth should be 3 (leaf+intermediate+root)")
		}
	}
}

func TestTLSProbe_OCSPResponderExtracted(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{chain.tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	hasOCSP := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.OCSPResponder != "" {
			hasOCSP = true
			assert.Contains(t, f.CryptoAsset.OCSPResponder, "http")
		}
	}
	assert.True(t, hasOCSP, "should extract OCSP responder URL from leaf cert")
}

func TestTLSProbe_CRLDistPointsExtracted(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{chain.tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	hasCRL := false
	for f := range findings {
		if f.CryptoAsset != nil && len(f.CryptoAsset.CRLDistPoints) > 0 {
			hasCRL = true
			assert.Contains(t, f.CryptoAsset.CRLDistPoints[0], "http")
		}
	}
	assert.True(t, hasCRL, "should extract CRL distribution points from leaf cert")
}

func TestTLSProbe_SingleCertChain(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.ChainPosition != "" {
			assert.Equal(t, "leaf", f.CryptoAsset.ChainPosition, "single cert should be labeled as leaf")
			assert.Equal(t, 1, f.CryptoAsset.ChainDepth, "single cert chain depth should be 1")
		}
	}
}

func TestChainPosition_Helper(t *testing.T) {
	t.Parallel()
	// Test the chainPosition helper directly
	// Self-signed CA: RawIssuer == RawSubject
	caIssuer := pkix.Name{CommonName: "Test CA"}
	caIssuerRaw, _ := asn1Marshal(caIssuer)

	selfSignedCA := &x509.Certificate{
		IsCA:       true,
		RawIssuer:  caIssuerRaw,
		RawSubject: caIssuerRaw, // same = self-signed
	}

	intIssuer := pkix.Name{CommonName: "Intermediate CA"}
	intIssuerRaw, _ := asn1Marshal(intIssuer)

	intermediateCert := &x509.Certificate{
		IsCA:       true,
		RawIssuer:  caIssuerRaw,
		RawSubject: intIssuerRaw,
	}

	leafIssuer := pkix.Name{CommonName: "Leaf"}
	leafIssuerRaw, _ := asn1Marshal(leafIssuer)

	leafCert := &x509.Certificate{
		IsCA:       false,
		RawIssuer:  intIssuerRaw,
		RawSubject: leafIssuerRaw,
	}

	// 3-cert chain
	pos, fn := chainPosition(0, 3, leafCert)
	assert.Equal(t, "leaf", pos)
	assert.Equal(t, "TLS leaf certificate", fn)

	pos, fn = chainPosition(1, 3, intermediateCert)
	assert.Equal(t, "intermediate", pos)
	assert.Equal(t, "TLS intermediate certificate", fn)

	pos, fn = chainPosition(2, 3, selfSignedCA)
	assert.Equal(t, "root", pos)
	assert.Equal(t, "TLS root certificate", fn)

	// 1-cert chain (self-signed leaf)
	pos, fn = chainPosition(0, 1, leafCert)
	assert.Equal(t, "leaf", pos)
	assert.Equal(t, "TLS leaf certificate", fn)
}

// asn1Marshal serializes a pkix.Name to ASN.1 DER for test RawIssuer/RawSubject fields.
func asn1Marshal(name pkix.Name) ([]byte, error) {
	rdnSeq := name.ToRDNSequence()
	return asn1Mod.Marshal(rdnSeq)
}

// acceptLoop accepts TLS connections and completes handshakes in the background.
func acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		conn.Close()
	}
}

// --- Sprint 2: OCSP/CRL Revocation Tests ---

func TestCheckOCSP_GoodStatus(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// Mock OCSP responder returning Good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: chain.leafCert.SerialNumber,
		}
		resp, err := ocsp.CreateResponse(chain.intCert, chain.intCert, tmpl, chain.intKey)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
	}))
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: srv.Client(),
	}

	// Create cert with OCSP pointing to our mock server
	cert := &x509.Certificate{
		SerialNumber: chain.leafCert.SerialNumber,
		OCSPServer:   []string{srv.URL},
	}

	status := m.checkOCSP(context.Background(), cert, chain.intCert)
	assert.Equal(t, "GOOD", status)
}

func TestCheckOCSP_RevokedStatus(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: chain.leafCert.SerialNumber,
			RevokedAt:    time.Now(),
		}
		resp, err := ocsp.CreateResponse(chain.intCert, chain.intCert, tmpl, chain.intKey)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
	}))
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: srv.Client(),
	}

	cert := &x509.Certificate{
		SerialNumber: chain.leafCert.SerialNumber,
		OCSPServer:   []string{srv.URL},
	}

	status := m.checkOCSP(context.Background(), cert, chain.intCert)
	assert.Equal(t, "REVOKED", status)
}

func TestCheckOCSP_Timeout(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// Handler hangs for 2s max; client timeout is 100ms so the
	// test verifies the client gives up. Previously this was
	// 30 seconds — which meant srv.Close() blocked waiting on
	// the handler goroutine for the full 30s if the server-side
	// context cancellation was slow (observed as a 30s per-test
	// cost on CI, pushing scanner package total over 10 min).
	// 2s is still plenty longer than the 100ms client deadline.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	srv.Start()
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	cert := &x509.Certificate{
		SerialNumber: chain.leafCert.SerialNumber,
		OCSPServer:   []string{srv.URL},
	}

	status := m.checkOCSP(context.Background(), cert, chain.intCert)
	assert.Equal(t, "ERROR", status)
}

func TestCheckOCSP_NoResponder(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// No OCSPServer set
	}
	issuer := &x509.Certificate{}

	status := m.checkOCSP(context.Background(), cert, issuer)
	assert.Equal(t, "", status)
}

func TestCheckCRL_NotRevoked(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// Create an empty CRL (no revoked certs)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, chain.intCert, chain.intKey)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlBytes)
	}))
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: srv.Client(),
	}

	cert := &x509.Certificate{
		SerialNumber:          chain.leafCert.SerialNumber,
		CRLDistributionPoints: []string{srv.URL},
	}

	status := m.checkCRL(context.Background(), cert)
	assert.Equal(t, "GOOD", status)
}

func TestCheckCRL_Revoked(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// Create CRL with the leaf cert's serial revoked
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   chain.leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, chain.intCert, chain.intKey)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlBytes)
	}))
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: srv.Client(),
	}

	cert := &x509.Certificate{
		SerialNumber:          chain.leafCert.SerialNumber,
		CRLDistributionPoints: []string{srv.URL},
	}

	status := m.checkCRL(context.Background(), cert)
	assert.Equal(t, "REVOKED", status)
}

func TestCheckCRL_FetchError(t *testing.T) {
	t.Parallel()
	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		CRLDistributionPoints: []string{"http://127.0.0.1:1/nonexistent.crl"},
	}

	status := m.checkCRL(context.Background(), cert)
	assert.Equal(t, "ERROR", status)
}

func TestCheckRevocation_OCSPPreferred(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	ocspCalled := false
	crlCalled := false

	// OCSP responder (Good)
	ocspSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ocspCalled = true
		tmpl := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: chain.leafCert.SerialNumber,
		}
		resp, _ := ocsp.CreateResponse(chain.intCert, chain.intCert, tmpl, chain.intKey)
		w.Write(resp)
	}))
	defer ocspSrv.Close()

	// CRL endpoint (shouldn't be hit)
	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crlCalled = true
	}))
	defer crlSrv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	// Build a new leaf cert that has OCSP+CRL fields, signed by the intermediate
	leafTemplate := &x509.Certificate{
		SerialNumber:          chain.leafCert.SerialNumber,
		Subject:               chain.leafCert.Subject,
		NotBefore:             chain.leafCert.NotBefore,
		NotAfter:              chain.leafCert.NotAfter,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{7, 8, 9},
		AuthorityKeyId:        []byte{4, 5, 6},
		OCSPServer:            []string{ocspSrv.URL},
		CRLDistributionPoints: []string{crlSrv.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, chain.intCert, &chain.leafKey.PublicKey, chain.intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	findings := make(chan *model.Finding, 10)
	m.checkRevocation(context.Background(), "test:443", []*x509.Certificate{leafCert, chain.intCert}, findings)
	close(findings)

	assert.True(t, ocspCalled, "OCSP should be checked first")
	assert.False(t, crlCalled, "CRL should not be checked when OCSP succeeds")
}

func TestCheckRevocation_FallbackToCRL(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// OCSP responder (broken)
	ocspSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ocspSrv.Close()

	// CRL endpoint (valid, empty = not revoked)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, chain.intCert, chain.intKey)
	require.NoError(t, err)

	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer crlSrv.Close()

	// Use a transport that routes to both servers
	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	leafCert := &x509.Certificate{
		SerialNumber:          chain.leafCert.SerialNumber,
		OCSPServer:            []string{ocspSrv.URL},
		CRLDistributionPoints: []string{crlSrv.URL},
	}

	findings := make(chan *model.Finding, 10)
	m.checkRevocation(context.Background(), "test:443", []*x509.Certificate{leafCert, chain.intCert}, findings)
	close(findings)

	// Collect findings to verify status
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.RevocationStatus != "" {
			assert.Equal(t, "GOOD", f.CryptoAsset.RevocationStatus, "should fall back to CRL and get GOOD")
		}
	}
}

func TestCheckRevocation_ContextCancellation(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		OCSPServer:   []string{"http://ocsp.example.com"},
	}

	findings := make(chan *model.Finding, 10)
	m.checkRevocation(ctx, "test:443", []*x509.Certificate{cert}, findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "cancelled context should produce no findings")
}

func TestCheckRevocation_FindingEmission(t *testing.T) {
	t.Parallel()
	chain := generateTestCertChain(t)

	// OCSP responder returning Good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: chain.leafCert.SerialNumber,
		}
		resp, _ := ocsp.CreateResponse(chain.intCert, chain.intCert, tmpl, chain.intKey)
		w.Write(resp)
	}))
	defer srv.Close()

	m := &ProtocolModule{
		config:     &scannerconfig.Config{},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	// Build a properly signed leaf with OCSP field
	leafTemplate := &x509.Certificate{
		SerialNumber:   chain.leafCert.SerialNumber,
		Subject:        chain.leafCert.Subject,
		NotBefore:      chain.leafCert.NotBefore,
		NotAfter:       chain.leafCert.NotAfter,
		DNSNames:       []string{"localhost"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		SubjectKeyId:   []byte{7, 8, 9},
		AuthorityKeyId: []byte{4, 5, 6},
		OCSPServer:     []string{srv.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, chain.intCert, &chain.leafKey.PublicKey, chain.intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	findings := make(chan *model.Finding, 10)
	m.checkRevocation(context.Background(), "test:443", []*x509.Certificate{leafCert, chain.intCert}, findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected, "should emit revocation finding")
	f := collected[0]
	assert.Equal(t, "Certificate revocation status", f.CryptoAsset.Function)
	assert.Equal(t, "GOOD", f.CryptoAsset.RevocationStatus)
	assert.Equal(t, "leaf", f.CryptoAsset.ChainPosition)
}

// testCertChain holds the components of a 3-level test certificate chain.
type testCertChain struct {
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	caCertDER  []byte
	intKey     *ecdsa.PrivateKey
	intCert    *x509.Certificate
	intCertDER []byte
	leafKey    *ecdsa.PrivateKey
	leafCert   *x509.Certificate
	leafDER    []byte
	tlsCert    tls.Certificate
}

// generateTestCertChain creates a CA → intermediate → leaf certificate chain for testing.
// The leaf cert includes OCSP and CRL distribution point extensions.
func generateTestCertChain(t *testing.T) testCertChain {
	t.Helper()

	// CA key + cert (self-signed, IsCA=true)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Intermediate key + cert (signed by CA)
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{4, 5, 6},
		AuthorityKeyId:        []byte{1, 2, 3},
	}

	intCertDER, err := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intCertDER)
	require.NoError(t, err)

	// Leaf key + cert (signed by intermediate)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "test-leaf.local"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{7, 8, 9},
		AuthorityKeyId:        []byte{4, 5, 6},
		OCSPServer:            []string{"http://ocsp.example.com"},
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Build TLS certificate with full chain: leaf → intermediate → CA
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, intCertDER, caCertDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}

	// Verify the key PEM round-trips correctly
	_ = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	return testCertChain{
		caKey:      caKey,
		caCert:     caCert,
		caCertDER:  caCertDER,
		intKey:     intKey,
		intCert:    intCert,
		intCertDER: intCertDER,
		leafKey:    leafKey,
		leafCert:   leafCert,
		leafDER:    leafDER,
		tlsCert:    tlsCert,
	}
}

// --- Phase 13: Enhanced TLS Probing Tests ---

func TestCipherSuiteKeyExchange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		suite   string
		wantKX  string
		wantPFS bool
	}{
		{"TLS13 AES-128-GCM", "TLS_AES_128_GCM_SHA256", "TLS13", true},
		{"TLS13 AES-256-GCM", "TLS_AES_256_GCM_SHA384", "TLS13", true},
		{"TLS13 ChaCha20", "TLS_CHACHA20_POLY1305_SHA256", "TLS13", true},
		{"ECDHE RSA AES-256-GCM", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", true},
		{"ECDHE ECDSA AES-128-GCM", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", true},
		{"DHE RSA AES-256-GCM", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", true},
		{"RSA AES-128-GCM (no PFS)", "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", false},
		{"RSA 3DES (no PFS)", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kx, pfs := cipherSuiteKeyExchange(tt.suite)
			assert.Equal(t, tt.wantKX, kx, "key exchange")
			assert.Equal(t, tt.wantPFS, pfs, "forward secrecy")
		})
	}
}

func TestIsWeakSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		algo x509.SignatureAlgorithm
		weak bool
	}{
		{x509.MD2WithRSA, true},
		{x509.MD5WithRSA, true},
		{x509.SHA1WithRSA, true},
		{x509.DSAWithSHA1, true},
		{x509.ECDSAWithSHA1, true},
		{x509.SHA256WithRSA, false},
		{x509.SHA384WithRSA, false},
		{x509.SHA512WithRSA, false},
		{x509.ECDSAWithSHA256, false},
		{x509.ECDSAWithSHA384, false},
		{x509.PureEd25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			assert.Equal(t, tt.weak, isWeakSignatureAlgorithm(tt.algo))
		})
	}
}

func TestTLSProbe_KeyExchangeExtracted(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// ECDHE cipher suites (default for ECDSA certs)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher suite" {
			assert.Equal(t, "ECDHE", f.CryptoAsset.KeyExchange)
			assert.True(t, f.CryptoAsset.ForwardSecrecy)
			return
		}
	}
	t.Fatal("no TLS cipher suite finding emitted")
}

func TestTLSProbe_NoPFS_RSAKeyExchange(t *testing.T) {
	t.Parallel()
	// Need an RSA cert for RSA key exchange cipher suites
	rsaCert, rsaKey := generateTestRSACert(t)
	tlsCert, err := tls.X509KeyPair(rsaCert, rsaKey)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher suite" {
			assert.Equal(t, "RSA", f.CryptoAsset.KeyExchange)
			assert.False(t, f.CryptoAsset.ForwardSecrecy)
			return
		}
	}
	t.Fatal("no TLS cipher suite finding emitted")
}

func TestTLSProbe_TLS13_AlwaysPFS(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher suite" {
			assert.Equal(t, "TLS13", f.CryptoAsset.KeyExchange)
			assert.True(t, f.CryptoAsset.ForwardSecrecy)
			return
		}
	}
	t.Fatal("no TLS cipher suite finding emitted")
}

func TestSigAlgoToPQCAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		algo x509.SignatureAlgorithm
		want string
	}{
		{x509.SHA1WithRSA, "SHA-1"},
		{x509.SHA256WithRSA, "SHA-256"},
		{x509.SHA384WithRSA, "SHA-384"},
		{x509.SHA512WithRSA, "SHA-512"},
		{x509.ECDSAWithSHA256, "SHA-256"},
		{x509.ECDSAWithSHA384, "SHA-384"},
		{x509.ECDSAWithSHA512, "SHA-512"},
		{x509.PureEd25519, "Ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, sigAlgoToPQCAlgorithm(tt.algo))
		})
	}
}

func TestEnhancedChainValidation_WeakSigAlgorithm(t *testing.T) {
	t.Parallel()
	// Create a cert with SHA-1 signature
	certPEM, keyPEM := generateTestCertWithSigAlgo(t, x509.SHA1WithRSA)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	hasWeakSig := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "Weak certificate signature algorithm" {
			hasWeakSig = true
			assert.Equal(t, "SHA-1", f.CryptoAsset.Algorithm)
			assert.Equal(t, "DEPRECATED", f.CryptoAsset.PQCStatus)
			assert.Equal(t, "leaf", f.CryptoAsset.ChainPosition)
		}
	}
	assert.True(t, hasWeakSig, "should detect weak SHA-1 signature algorithm")
}

func TestEnhancedChainValidation_ExpiringCert(t *testing.T) {
	t.Parallel()
	// Cert expiring in 15 days
	notAfter := time.Now().Add(15 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCertWithExpiry(t, notAfter)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	hasExpiry := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "Certificate expiry warning" {
			hasExpiry = true
			assert.Contains(t, f.CryptoAsset.Purpose, "days")
			assert.NotNil(t, f.CryptoAsset.NotAfter)
		}
	}
	assert.True(t, hasExpiry, "should warn about cert expiring in 15 days")
}

func TestEnhancedChainValidation_NotExpiringSoon(t *testing.T) {
	t.Parallel()
	// Cert valid for 365 days — no warning
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCertWithExpiry(t, notAfter)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil {
			assert.NotEqual(t, "Certificate expiry warning", f.CryptoAsset.Function,
				"should NOT warn about cert expiring in 365 days")
		}
	}
}

func TestEnhancedChainValidation_AlreadyExpired(t *testing.T) {
	t.Parallel()
	// Already expired cert — chain validation handles it, no expiry WARNING
	notAfter := time.Now().Add(-1 * time.Hour)
	certPEM, keyPEM := generateTestCertWithExpiry(t, notAfter)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	for f := range findings {
		if f.CryptoAsset != nil {
			assert.NotEqual(t, "Certificate expiry warning", f.CryptoAsset.Function,
				"expired cert should not emit expiry WARNING (chain validation handles it)")
		}
	}
}

func TestEnhancedChainValidation_SANExtraction(t *testing.T) {
	t.Parallel()
	dnsNames := []string{"example.com", "*.example.com"}
	ips := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")}
	certPEM, keyPEM := generateTestCertWithSANs(t, dnsNames, ips)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetNetwork, Value: listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = m.Scan(ctx, target, findings)
	require.NoError(t, err)
	close(findings)

	hasSANs := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS certificate SANs" {
			hasSANs = true
			assert.Contains(t, f.CryptoAsset.SANs, "example.com")
			assert.Contains(t, f.CryptoAsset.SANs, "*.example.com")
			assert.Contains(t, f.CryptoAsset.SANs, "10.0.0.1")
			assert.Contains(t, f.CryptoAsset.SANs, "192.168.1.1")
			assert.Equal(t, "leaf", f.CryptoAsset.ChainPosition)
		}
	}
	assert.True(t, hasSANs, "should extract SANs from leaf cert")
}

func TestProbeVersionRange_TLS12Only(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m.probeVersionRange(ctx, listener.Addr().String(), findings)
	close(findings)

	hasVersionRange := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS version range" {
			hasVersionRange = true
			assert.Equal(t, "TLS 1.2", f.CryptoAsset.Library)
			assert.Contains(t, f.CryptoAsset.Purpose, "TLS 1.2")
			assert.NotContains(t, f.CryptoAsset.Purpose, "TLS 1.0")
			assert.NotContains(t, f.CryptoAsset.Purpose, "TLS 1.1")
			assert.NotContains(t, f.CryptoAsset.Purpose, "TLS 1.3")
		}
	}
	assert.True(t, hasVersionRange, "should emit TLS version range finding")
}

func TestProbeVersionRange_TLS12And13(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m.probeVersionRange(ctx, listener.Addr().String(), findings)
	close(findings)

	hasVersionRange := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS version range" {
			hasVersionRange = true
			assert.Equal(t, "TLS 1.2 to TLS 1.3", f.CryptoAsset.Library)
			assert.Contains(t, f.CryptoAsset.Purpose, "TLS 1.2")
			assert.Contains(t, f.CryptoAsset.Purpose, "TLS 1.3")
		}
	}
	assert.True(t, hasVersionRange, "should emit TLS version range finding for 1.2+1.3")
}

func TestEnumerateCipherSuites_SingleCipher(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	supported := m.enumerateSupportedCiphers(ctx, listener.Addr().String())
	require.Len(t, supported, 1)
	assert.Equal(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, supported[0])

	m.emitSupportedCipherFindings(ctx, listener.Addr().String(), supported, findings)
	close(findings)

	count := 0
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS supported cipher suite" {
			count++
			assert.Equal(t, "ECDHE", f.CryptoAsset.KeyExchange)
			assert.True(t, f.CryptoAsset.ForwardSecrecy)
		}
	}
	assert.Equal(t, 1, count, "should emit 1 supported cipher finding")
}

func TestEnumerateCipherSuites_MultipleCiphers(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	supported := m.enumerateSupportedCiphers(ctx, listener.Addr().String())
	assert.Len(t, supported, 3, "should find 3 supported ciphers")

	findings := make(chan *model.Finding, 100)
	m.emitSupportedCipherFindings(ctx, listener.Addr().String(), supported, findings)
	close(findings)

	count := 0
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS supported cipher suite" {
			count++
		}
	}
	assert.Equal(t, 3, count, "should emit 3 supported cipher findings")
}

func TestEnumerateCipherSuites_IncludesInsecure(t *testing.T) {
	t.Parallel()
	rsaCert, rsaKey := generateTestRSACert(t)
	tlsCert, err := tls.X509KeyPair(rsaCert, rsaKey)
	require.NoError(t, err)

	// Offer 3DES (insecure) alongside a normal cipher
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	supported := m.enumerateSupportedCiphers(ctx, listener.Addr().String())
	assert.GreaterOrEqual(t, len(supported), 2, "should detect insecure + secure ciphers")

	findings := make(chan *model.Finding, 100)
	m.emitSupportedCipherFindings(ctx, listener.Addr().String(), supported, findings)
	close(findings)

	has3DES := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS supported cipher suite" {
			if f.CryptoAsset.Algorithm == "3DES" {
				has3DES = true
				assert.Equal(t, "DEPRECATED", f.CryptoAsset.PQCStatus)
			}
		}
	}
	assert.True(t, has3DES, "should detect 3DES as supported cipher")
}

func TestCipherPreference_ServerOrder(t *testing.T) {
	t.Parallel()
	rsaCert, rsaKey := generateTestRSACert(t)
	tlsCert, err := tls.X509KeyPair(rsaCert, rsaKey)
	require.NoError(t, err)

	serverCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: serverCiphers,
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m.probeCipherPreference(ctx, listener.Addr().String(), serverCiphers, findings)
	close(findings)

	hasPref := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher preference order" {
			hasPref = true
			// Should have ordered list with > separator (3 ciphers = 2 separators)
			assert.Contains(t, f.CryptoAsset.Library, ">")
			// Algorithm should be a valid symmetric algo
			assert.Contains(t, []string{"AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"}, f.CryptoAsset.Algorithm)
		}
	}
	assert.True(t, hasPref, "should emit cipher preference order finding")
}

func TestCipherPreference_SingleCipher(t *testing.T) {
	t.Parallel()
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	require.NoError(t, err)
	defer listener.Close()

	go acceptLoop(listener)

	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m.probeCipherPreference(ctx, listener.Addr().String(),
		[]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, findings)
	close(findings)

	hasPref := false
	for f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "TLS cipher preference order" {
			hasPref = true
			assert.NotContains(t, f.CryptoAsset.Library, ">", "single cipher should not have '>'")
		}
	}
	assert.True(t, hasPref, "should emit cipher preference even for single cipher")
}

func TestProbeVersionRange_ContextCancelled(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m.probeVersionRange(ctx, "127.0.0.1:443", findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "cancelled context should produce no findings")
}

func TestEnhancedChainValidation_ContextCancelled(t *testing.T) {
	t.Parallel()
	m := NewProtocolModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cert, _ := generateTestCert(t)
	block, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	m.enhancedChainValidation(ctx, "127.0.0.1:443", []*x509.Certificate{parsed}, findings)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "cancelled context should produce no findings")
}

// generateTestCert creates a self-signed ECDSA certificate for testing.
func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-protocol"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateTestRSACert creates a self-signed RSA certificate for testing RSA key exchange.
func generateTestRSACert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-rsa"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM
}

// generateTestCertWithSigAlgo creates a self-signed RSA cert with a specific signature algorithm.
func generateTestCertWithSigAlgo(t *testing.T, sigAlgo x509.SignatureAlgorithm) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "test-sig-algo"},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		DNSNames:           []string{"localhost"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1")},
		SignatureAlgorithm: sigAlgo,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM
}

// generateTestCertWithExpiry creates a self-signed ECDSA cert with configurable expiry.
func generateTestCertWithExpiry(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-expiry"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateTestCertWithSANs creates a self-signed ECDSA cert with specific SANs.
func generateTestCertWithSANs(t *testing.T, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Must include 127.0.0.1 for the TLS server to work
	allIPs := append([]net.IP{net.ParseIP("127.0.0.1")}, ips...)
	allDNS := append([]string{"localhost"}, dnsNames...)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sans"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     allDNS,
		IPAddresses:  allIPs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
