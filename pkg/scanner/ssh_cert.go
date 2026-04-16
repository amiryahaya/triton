package scanner

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

const sshDialTimeout = 5 * time.Second

// SSHCertModule connects to SSH servers and extracts the host key.
// When the server presents an OpenSSH certificate, it also parses the
// certificate validity window, CA key type, and serial number.
//
// Targets must be network targets with an explicit host or host:port value.
// The generic "local" target is skipped. Port 22 is used when no port is
// specified.
type SSHCertModule struct {
	config *scannerconfig.Config
	// dialer is injectable for testing. NewSSHCertModule sets it to the
	// production TCP dialer.
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSSHCertModule returns an SSHCertModule ready for production use.
func NewSSHCertModule(cfg *scannerconfig.Config) *SSHCertModule {
	m := &SSHCertModule{config: cfg}
	m.dialer = m.defaultDial
	return m
}

func (m *SSHCertModule) Name() string                         { return "ssh_cert" }
func (m *SSHCertModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *SSHCertModule) ScanTargetType() model.ScanTargetType { return model.TargetNetwork }

// defaultDial is the production TCP dialer: 5 s timeout, bounded by the
// context deadline if earlier.
func (m *SSHCertModule) defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	timeout := sshDialTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// Scan probes the SSH server at target.Value and emits findings for the host
// key (and certificate, when applicable).
func (m *SSHCertModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	addr := strings.TrimSpace(target.Value)
	if addr == "" || addr == "local" {
		return nil
	}

	// Ensure we have a port.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}

	return m.probeSSH(ctx, addr, findings)
}

// probeSSH dials the SSH server, captures the host key via the handshake, and
// emits findings.
func (m *SSHCertModule) probeSSH(ctx context.Context, addr string, findings chan<- *model.Finding) error {
	var capturedKey ssh.PublicKey

	clientCfg := &ssh.ClientConfig{
		User: "triton-scanner",
		// HostKeyCallback captures the server's host key presentation without
		// validating trust — we're auditing, not authenticating.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			capturedKey = key
			return nil
		},
		Timeout: sshDialTimeout,
		// No auth methods: we bail out after the key exchange anyway.
		Auth: []ssh.AuthMethod{},
	}

	conn, err := m.dialer(ctx, "tcp", addr)
	if err != nil {
		return nil // unreachable host — not an error for the scan
	}

	// Perform the SSH handshake. The returned *ssh.Client is never used for
	// further interaction; we only need it to trigger the HostKeyCallback.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		// Handshake failed (auth rejection is expected and fine — the callback
		// fires before auth). Any other error means the remote is not a valid
		// SSH server or the context was cancelled.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	defer func() { _ = sshConn.Close() }()
	// Drain server channels and global requests so the peer doesn't block.
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.UnknownChannelType, "scanner")
		}
	}()

	if capturedKey == nil {
		return nil
	}

	return m.emitKeyFindings(ctx, addr, capturedKey, findings)
}

// emitKeyFindings classifies the SSH public key and emits the appropriate
// findings. When the key is an OpenSSH certificate, an additional finding is
// emitted with certificate metadata.
func (m *SSHCertModule) emitKeyFindings(ctx context.Context, addr string, key ssh.PublicKey, findings chan<- *model.Finding) error {
	// Distinguish between a plain public key and an OpenSSH certificate.
	if cert, ok := key.(*ssh.Certificate); ok {
		return m.emitCertFindings(ctx, addr, cert, findings)
	}

	return m.emitHostKeyFinding(ctx, addr, key, "SSH host key", findings)
}

// emitHostKeyFinding creates and sends a finding for a plain SSH host key.
func (m *SSHCertModule) emitHostKeyFinding(ctx context.Context, addr string, key ssh.PublicKey, function string, findings chan<- *model.Finding) error {
	algo, keySize := sshKeyAlgorithmAndSize(key)
	asset := &model.CryptoAsset{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Function: function,
		Algorithm: algo,
		KeySize:  keySize,
		Purpose:  fmt.Sprintf("SSH host key presented by %s", addr),
	}
	crypto.ClassifyCryptoAsset(asset)

	return m.sendFinding(ctx, addr, asset, findings)
}

// emitCertFindings emits one finding for the certified host key and one for
// the certificate metadata itself.
func (m *SSHCertModule) emitCertFindings(ctx context.Context, addr string, cert *ssh.Certificate, findings chan<- *model.Finding) error {
	// Finding 1 — the underlying host key (subject key).
	if err := m.emitHostKeyFinding(ctx, addr, cert.Key, "SSH host key (certified)", findings); err != nil {
		return err
	}

	// Finding 2 — the certificate wrapper with validity and CA info.
	algo, keySize := sshKeyAlgorithmAndSize(cert.Key)
	caAlgo, _ := sshPublicKeyAlgorithmAndSize(cert.SignatureKey)

	validAfter := time.Unix(int64(cert.ValidAfter), 0).UTC()
	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()

	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "SSH host certificate",
		Algorithm:    algo,
		KeySize:      keySize,
		Issuer:       caAlgo, // CA key type encoded as Issuer for display
		SerialNumber: fmt.Sprintf("%d", cert.Serial),
		NotBefore:    &validAfter,
		NotAfter:     &validBefore,
		Purpose:      fmt.Sprintf("OpenSSH host certificate presented by %s (CA: %s)", addr, caAlgo),
	}
	crypto.ClassifyCryptoAsset(asset)

	return m.sendFinding(ctx, addr, asset, findings)
}

// sendFinding emits a Finding on the channel, respecting context cancellation.
func (m *SSHCertModule) sendFinding(ctx context.Context, addr string, asset *model.CryptoAsset, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryNetwork,
		Source: model.FindingSource{
			Type:     "network",
			Endpoint: addr,
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      m.Name(),
		Timestamp:   time.Now(),
	}
	select {
	case findings <- f:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// sshKeyAlgorithmAndSize returns (algorithmName, keyBits) for an SSH public key.
// It delegates to sshPublicKeyAlgorithmAndSize after unwrapping certificates.
func sshKeyAlgorithmAndSize(key ssh.PublicKey) (string, int) {
	// Unwrap certificate to the underlying key.
	if cert, ok := key.(*ssh.Certificate); ok {
		return sshPublicKeyAlgorithmAndSize(cert.Key)
	}
	return sshPublicKeyAlgorithmAndSize(key)
}

// sshPublicKeyAlgorithmAndSize maps an ssh.PublicKey to its canonical algorithm
// name (as used in the crypto registry) and key size in bits.
func sshPublicKeyAlgorithmAndSize(key ssh.PublicKey) (string, int) {
	switch key.Type() {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		if cryptoKey, ok := key.(ssh.CryptoPublicKey); ok {
			if rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey); ok {
				return "RSA", rsaKey.N.BitLen()
			}
		}
		return "RSA", 0
	case ssh.KeyAlgoECDSA256:
		return "ECDSA-P256", 256
	case ssh.KeyAlgoECDSA384:
		return "ECDSA-P384", 384
	case ssh.KeyAlgoECDSA521:
		return "ECDSA-P521", 521
	case ssh.KeyAlgoED25519:
		return "Ed25519", 256
	case ssh.KeyAlgoDSA:
		if cryptoKey, ok := key.(ssh.CryptoPublicKey); ok {
			// DSA keys carry the key length in their underlying struct.
			// We access it via reflection-free type assertion.
			_ = cryptoKey.CryptoPublicKey() // ensure unwrap works
		}
		return "DSA", 1024 // DSA in SSH is always 1024-bit
	default:
		// Fall back to the raw SSH key type string for unknown algorithms.
		return key.Type(), 0
	}
}

