package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*ProtocolModule)(nil)

func TestProtocolModuleInterface(t *testing.T) {
	m := NewProtocolModule(&config.Config{})
	assert.Equal(t, "protocol", m.Name())
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
	assert.Equal(t, model.TargetNetwork, m.ScanTargetType())
}

func TestTLSProbeAgainstTestServer(t *testing.T) {
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

	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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
	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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
	m := NewProtocolModule(&config.Config{})
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

	m := NewProtocolModule(&config.Config{})
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
	cert, key := generateTestCert(t)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	// TLS 1.2 with session tickets disabled
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{tlsCert},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS12,
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

	m := NewProtocolModule(&config.Config{})
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
