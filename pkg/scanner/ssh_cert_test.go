package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check.
var _ Module = (*SSHCertModule)(nil)

// startMockSSHServer starts a minimal SSH server that accepts one connection,
// completes the SSH handshake, then closes. Returns the server address and a
// cleanup function.
func startMockSSHServer(t *testing.T, hostSigner ssh.Signer) (addr string, cleanup func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverConfig := &ssh.ServerConfig{
		// Accept any client key for testing purposes.
		NoClientAuth: true,
	}
	serverConfig.AddHostKey(hostSigner)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return // listener closed
		}
		// Complete the SSH handshake then close — we only need the handshake
		// to expose the host key to the client's HostKeyCallback.
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(ssh.UnknownChannelType, "not supported")
			}
		}()
		_ = sshConn.Close()
	}()

	return l.Addr().String(), func() {
		_ = l.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

// generateRSASigner creates an RSA SSH signer with the given bit size.
func generateRSASigner(t *testing.T, bits int) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// generateEd25519Signer creates an Ed25519 SSH signer.
func generateEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// generateECDSASigner creates an ECDSA SSH signer for the given curve.
func generateECDSASigner(t *testing.T, curve elliptic.Curve) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// collectFindings drains the findings channel into a slice.
func collectSSHFindings(t *testing.T, m *SSHCertModule, target model.ScanTarget) []*model.Finding {
	t.Helper()
	ch := make(chan *model.Finding, 32)
	err := m.Scan(context.Background(), target, ch)
	require.NoError(t, err)
	close(ch)
	var findings []*model.Finding
	for f := range ch {
		findings = append(findings, f)
	}
	return findings
}

// ---- Interface compliance ----

func TestSSHCert_Name(t *testing.T) {
	t.Parallel()
	m := NewSSHCertModule(&scannerconfig.Config{})
	assert.Equal(t, "ssh_cert", m.Name())
}

func TestSSHCert_Category(t *testing.T) {
	t.Parallel()
	m := NewSSHCertModule(&scannerconfig.Config{})
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
}

func TestSSHCert_ScanTargetType(t *testing.T) {
	t.Parallel()
	m := NewSSHCertModule(&scannerconfig.Config{})
	assert.Equal(t, model.TargetNetwork, m.ScanTargetType())
}

// ---- Functional tests ----

func TestSSHCert_RSAHostKey(t *testing.T) {
	t.Parallel()
	signer := generateRSASigner(t, 2048)
	addr, cleanup := startMockSSHServer(t, signer)
	defer cleanup()

	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: addr, Type: model.TargetNetwork})

	require.NotEmpty(t, findings, "expected at least one finding for RSA host key")

	var keyFinding *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "RSA" {
			keyFinding = f
			break
		}
	}
	require.NotNil(t, keyFinding, "expected RSA host key finding")
	assert.Equal(t, 2048, keyFinding.CryptoAsset.KeySize)
	assert.Equal(t, 9, keyFinding.Category)
	assert.Equal(t, "ssh_cert", keyFinding.Module)
	assert.Equal(t, "network", keyFinding.Source.Type)
	assert.Equal(t, addr, keyFinding.Source.Endpoint)
}

func TestSSHCert_Ed25519HostKey(t *testing.T) {
	t.Parallel()
	signer := generateEd25519Signer(t)
	addr, cleanup := startMockSSHServer(t, signer)
	defer cleanup()

	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: addr, Type: model.TargetNetwork})

	require.NotEmpty(t, findings, "expected at least one finding for Ed25519 host key")

	var keyFinding *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "Ed25519" {
			keyFinding = f
			break
		}
	}
	require.NotNil(t, keyFinding, "expected Ed25519 host key finding")
	assert.Equal(t, 256, keyFinding.CryptoAsset.KeySize)
	assert.Equal(t, 9, keyFinding.Category)
	assert.Equal(t, "ssh_cert", keyFinding.Module)
}

func TestSSHCert_ECDSAHostKey(t *testing.T) {
	t.Parallel()
	signer := generateECDSASigner(t, elliptic.P256())
	addr, cleanup := startMockSSHServer(t, signer)
	defer cleanup()

	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: addr, Type: model.TargetNetwork})

	require.NotEmpty(t, findings)

	var keyFinding *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "ECDSA-P256" {
			keyFinding = f
			break
		}
	}
	require.NotNil(t, keyFinding, "expected ECDSA-P256 host key finding")
	assert.Equal(t, 256, keyFinding.CryptoAsset.KeySize)
}

func TestSSHCert_SkipsLocalTarget(t *testing.T) {
	t.Parallel()
	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: "local", Type: model.TargetNetwork})
	assert.Empty(t, findings, "local target should produce no findings")
}

func TestSSHCert_SkipsEmptyTarget(t *testing.T) {
	t.Parallel()
	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: "", Type: model.TargetNetwork})
	assert.Empty(t, findings, "empty target should produce no findings")
}

func TestSSHCert_DefaultsToPort22(t *testing.T) {
	t.Parallel()
	// Provide just a hostname with no port — we expect the module to add :22.
	// Use a known-unreachable loopback address so the connection fails fast
	// without emitting findings (no findings expected for unreachable host).
	m := NewSSHCertModule(&scannerconfig.Config{})
	// Use a dialer that records the address it was called with.
	var dialedAddr string
	m.dialer = func(_ context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		// Fail immediately so the scan doesn't block.
		return nil, io.EOF
	}
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: "192.0.2.1", Type: model.TargetNetwork})
	assert.Empty(t, findings)
	assert.Equal(t, "192.0.2.1:22", dialedAddr, "expected default SSH port 22")
}

func TestSSHCert_OpenSSHCertificate(t *testing.T) {
	t.Parallel()

	// Generate a CA key and a host key.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)

	hostPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	hostPub, err := ssh.NewPublicKey(&hostPriv.PublicKey)
	require.NoError(t, err)

	// Create a host certificate signed by the CA.
	cert := &ssh.Certificate{
		CertType:    ssh.HostCert,
		Key:         hostPub,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(24 * time.Hour).Unix()),
		Serial:      42,
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))

	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)
	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	require.NoError(t, err)

	addr, cleanup := startMockSSHServer(t, certSigner)
	defer cleanup()

	m := NewSSHCertModule(&scannerconfig.Config{})
	findings := collectSSHFindings(t, m, model.ScanTarget{Value: addr, Type: model.TargetNetwork})

	require.NotEmpty(t, findings)

	// Should emit both a host key finding and a certificate finding.
	var certFinding *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "SSH host certificate" {
			certFinding = f
			break
		}
	}
	require.NotNil(t, certFinding, "expected SSH host certificate finding")
	assert.Equal(t, "RSA", certFinding.CryptoAsset.Algorithm)
	assert.Equal(t, 2048, certFinding.CryptoAsset.KeySize)
	assert.Equal(t, "Ed25519", certFinding.CryptoAsset.Issuer, "CA key type should be in Issuer field")
	assert.Equal(t, "42", certFinding.CryptoAsset.SerialNumber)
	assert.NotNil(t, certFinding.CryptoAsset.NotBefore)
	assert.NotNil(t, certFinding.CryptoAsset.NotAfter)
}
