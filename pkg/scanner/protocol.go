package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

const defaultProbeTimeout = 5 * time.Second

// ProtocolModule performs active TLS handshake probing to extract cipher suites
// and certificate information from network endpoints.
type ProtocolModule struct {
	config *config.Config
}

func NewProtocolModule(cfg *config.Config) *ProtocolModule {
	return &ProtocolModule{config: cfg}
}

func (m *ProtocolModule) Name() string {
	return "protocol"
}

func (m *ProtocolModule) Category() model.ModuleCategory {
	return model.CategoryActiveNetwork
}

func (m *ProtocolModule) ScanTargetType() model.ScanTargetType {
	return model.TargetNetwork
}

// Scan probes a network target with a TLS handshake and extracts crypto information.
// The target.Value should be a host:port address (e.g., "192.168.1.1:443").
func (m *ProtocolModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	addr := target.Value
	if addr == "" {
		return nil
	}

	return m.probeTLS(ctx, addr, findings)
}

// emitFinding creates and sends a protocol finding with standard fields.
func (m *ProtocolModule) emitFinding(ctx context.Context, addr string, asset *model.CryptoAsset, findings chan<- *model.Finding) error {
	crypto.ClassifyCryptoAsset(asset)

	select {
	case findings <- &model.Finding{
		ID:       uuid.New().String(),
		Category: 9,
		Source: model.FindingSource{
			Type:     "network",
			Endpoint: addr,
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "protocol",
		Timestamp:   time.Now(),
	}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// probeTLS performs a TLS handshake and extracts cipher suite and certificate info.
func (m *ProtocolModule) probeTLS(ctx context.Context, addr string, findings chan<- *model.Finding) error {
	dialer := &net.Dialer{Timeout: defaultProbeTimeout}

	// Use context deadline if shorter than default
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < defaultProbeTimeout {
			dialer.Timeout = remaining
		}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,            // We're probing, not validating trust
		MinVersion:         tls.VersionTLS10, // Accept deprecated versions to detect them
	})
	if err != nil {
		return nil // Connection failed — not a TLS service or unreachable
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()

	// Extract cipher suite
	cipherAlgo := cipherSuiteAlgorithm(state.CipherSuite)
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	tlsVersion := tlsVersionName(state.Version)

	if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:        uuid.New().String(),
		Function:  "TLS cipher suite",
		Algorithm: cipherAlgo,
		Library:   cipherName,
		Purpose:   fmt.Sprintf("Negotiated cipher for %s (%s)", addr, tlsVersion),
	}, findings); err != nil {
		return err
	}

	// Emit warning for deprecated TLS versions
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "TLS protocol version",
			Algorithm: tlsVersion,
			Purpose:   fmt.Sprintf("Deprecated TLS version negotiated by %s", addr),
		}, findings); err != nil {
			return err
		}
	}

	// Extract certificate info from peer certificates
	for _, cert := range state.PeerCertificates {
		keySize := 0
		algoName := ""
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = pub.N.BitLen()
			algoName = fmt.Sprintf("RSA-%d", keySize)
		case *ecdsa.PublicKey:
			keySize = pub.Curve.Params().BitSize
			algoName = fmt.Sprintf("ECDSA-P%d", keySize)
		case ed25519.PublicKey:
			keySize = 256
			algoName = "Ed25519"
		default:
			algoName = cert.PublicKeyAlgorithm.String()
		}

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter

		if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:           uuid.New().String(),
			Function:     "TLS server certificate",
			Algorithm:    algoName,
			KeySize:      keySize,
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    &notBefore,
			NotAfter:     &notAfter,
			IsCA:         cert.IsCA,
			Purpose:      fmt.Sprintf("Certificate presented by %s", addr),
		}, findings); err != nil {
			return err
		}
	}

	// Validate certificate chain against system roots
	m.validateCertChain(ctx, addr, state, findings)

	// Detect session resumption support
	m.detectSessionResumption(ctx, addr, findings)

	return nil
}

// validateCertChain validates the peer certificate chain against the system root store.
func (m *ProtocolModule) validateCertChain(ctx context.Context, addr string, state tls.ConnectionState, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	if len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]

	roots, err := x509.SystemCertPool()
	if err != nil {
		// System cert pool unavailable — skip validation
		return
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       host,
	})
	if verifyErr != nil {
		algoName := leaf.PublicKeyAlgorithm.String()
		switch pub := leaf.PublicKey.(type) {
		case *rsa.PublicKey:
			algoName = fmt.Sprintf("RSA-%d", pub.N.BitLen())
		case *ecdsa.PublicKey:
			algoName = fmt.Sprintf("ECDSA-P%d", pub.Curve.Params().BitSize)
		case ed25519.PublicKey:
			algoName = "Ed25519"
		}

		_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "TLS certificate chain validation",
			Algorithm: algoName,
			Purpose:   fmt.Sprintf("Certificate chain validation failed for %s: %v", addr, verifyErr),
		}, findings)
	}
}

// detectSessionResumption checks whether the server supports TLS session resumption.
func (m *ProtocolModule) detectSessionResumption(ctx context.Context, addr string, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	dialer := &net.Dialer{Timeout: defaultProbeTimeout}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < defaultProbeTimeout {
			dialer.Timeout = remaining
		}
	}

	cache := tls.NewLRUClientSessionCache(1)

	// First connection — populate session cache
	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify:  true,
		MinVersion:          tls.VersionTLS10,
		ClientSessionCache: cache,
	})
	if err != nil {
		return
	}
	_ = conn1.Close()

	// Second connection — attempt resumption
	conn2, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify:  true,
		MinVersion:          tls.VersionTLS10,
		ClientSessionCache: cache,
	})
	if err != nil {
		return
	}
	state := conn2.ConnectionState()
	_ = conn2.Close()

	mechanism := "not supported"
	if state.DidResume {
		mechanism = "session ticket"
	}

	_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:        uuid.New().String(),
		Function:  "TLS session resumption",
		Algorithm: "TLS Session Resumption",
		Purpose:   fmt.Sprintf("Session resumption %s for %s", mechanism, addr),
	}, findings)
}

// cipherSuiteAlgorithm extracts the primary symmetric algorithm from a TLS cipher suite.
func cipherSuiteAlgorithm(suite uint16) string {
	name := tls.CipherSuiteName(suite)
	upper := strings.ToUpper(name)

	switch {
	case strings.Contains(upper, "AES_256_GCM"):
		return "AES-256-GCM"
	case strings.Contains(upper, "AES_128_GCM"):
		return "AES-128-GCM"
	case strings.Contains(upper, "AES_256_CBC"):
		return "AES-256-CBC"
	case strings.Contains(upper, "AES_128_CBC"):
		return "AES-128-CBC"
	case strings.Contains(upper, "CHACHA20"):
		return "ChaCha20-Poly1305"
	case strings.Contains(upper, "3DES"):
		return "3DES"
	case strings.Contains(upper, "RC4"):
		return "RC4"
	default:
		return "TLS"
	}
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}
