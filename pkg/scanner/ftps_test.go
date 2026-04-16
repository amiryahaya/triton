package scanner

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check.
var _ Module = (*FTPSModule)(nil)

// generateFTPSTestCert generates a self-signed ECDSA certificate for FTPS tests.
func generateFTPSTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ftps-test.example.com",
			Organization: []string{"FTPS Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return tlsCert
}

// TestFTPS_Name verifies the module's Name() method.
func TestFTPS_Name(t *testing.T) {
	t.Parallel()
	m := NewFTPSModule(&scannerconfig.Config{})
	assert.Equal(t, "ftps", m.Name())
}

// TestFTPS_Category verifies the module's Category() method.
func TestFTPS_Category(t *testing.T) {
	t.Parallel()
	m := NewFTPSModule(&scannerconfig.Config{})
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
}

// TestFTPS_ScanTargetType verifies the module's ScanTargetType() method.
func TestFTPS_ScanTargetType(t *testing.T) {
	t.Parallel()
	m := NewFTPSModule(&scannerconfig.Config{})
	assert.Equal(t, model.TargetNetwork, m.ScanTargetType())
}

// TestFTPS_SkipsLocalTarget verifies that a generic "local" target is skipped.
func TestFTPS_SkipsLocalTarget(t *testing.T) {
	t.Parallel()
	m := NewFTPSModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: "local",
	}
	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)
	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}
	assert.Empty(t, got, "no findings expected for local target")
}

// TestFTPS_ExplicitAuthTLS sets up a mock FTP server that:
//   - Sends a "220 FTP Ready" banner
//   - Accepts "AUTH TLS" and responds "234 ..."
//   - Upgrades to TLS using a self-signed certificate
//
// The module should emit at least one finding containing the server
// certificate subject.
func TestFTPS_ExplicitAuthTLS(t *testing.T) {
	t.Parallel()

	tlsCert := generateFTPSTestCert(t)

	// Plain TCP listener for the FTP control channel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Server goroutine: banner → AUTH TLS → 234 → TLS upgrade
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send 220 banner.
		_, _ = conn.Write([]byte("220 FTP Ready\r\n"))

		// Read client commands until AUTH TLS.
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "AUTH TLS" || line == "AUTH SSL" {
				break
			}
		}

		// Respond 234 to trigger TLS upgrade.
		_, _ = conn.Write([]byte("234 AUTH TLS OK\r\n"))

		// Upgrade to TLS.
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		})
		_ = tlsConn.Handshake()
		// Keep alive until client closes.
		buf := make([]byte, 1)
		_, _ = tlsConn.Read(buf)
	}()

	addr := ln.Addr().String()
	m := NewFTPSModule(&scannerconfig.Config{})

	// Use injectable dialer so we hit our mock directly at the correct addr.
	m.dialer = func(ctx context.Context, network, dialAddr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: addr,
	}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)

	close(findings)
	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	require.NotEmpty(t, got, "expected at least one finding from explicit FTPS")

	// At least one finding should contain the certificate subject.
	subjectFound := false
	for _, f := range got {
		if f.CryptoAsset != nil && f.CryptoAsset.Subject != "" {
			subjectFound = true
		}
	}
	assert.True(t, subjectFound, "expected a finding with non-empty certificate Subject")

	// All findings should be attributed to the "ftps" module.
	for _, f := range got {
		assert.Equal(t, "ftps", f.Module)
		assert.Equal(t, "network", f.Source.Type)
	}
}

// TestFTPS_Rejection verifies that when AUTH TLS is rejected the module
// still returns no error and emits no certificate findings.
func TestFTPS_Rejection(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Server: send 220, respond 502 to AUTH TLS, then close.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 FTP Ready\r\n"))

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "AUTH TLS" || line == "AUTH SSL" {
				break
			}
		}
		_, _ = conn.Write([]byte("502 Command not implemented\r\n"))
	}()

	addr := ln.Addr().String()
	m := NewFTPSModule(&scannerconfig.Config{})

	// Inject dialer for explicit FTPS and make implicit FTPS (port 990) fail fast.
	m.dialer = func(ctx context.Context, network, dialAddr string) (net.Conn, error) {
		// Only succeed for the mock server address; fail everything else
		// (e.g. the implicit FTPS port-990 attempt).
		if dialAddr == addr {
			return net.Dial("tcp", addr)
		}
		return nil, &net.OpError{Op: "dial", Err: &net.AddrError{Err: "connection refused", Addr: dialAddr}}
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{
		Type:  model.TargetNetwork,
		Value: addr,
	}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err, "rejection of AUTH TLS should not return an error")

	close(findings)
	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	// No certificate findings should be emitted.
	for _, f := range got {
		assert.Empty(t, f.CryptoAsset.Subject, "no certificate subject expected after AUTH TLS rejection")
	}
}
