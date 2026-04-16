package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsutil"
)

// FTPSModule connects to FTP servers, upgrades to TLS via AUTH TLS (explicit
// FTPS on port 21), and if that fails attempts implicit FTPS on port 990.
// It extracts the server certificate chain and negotiated cipher suite.
//
// Explicit FTPS (RFC 4217) is the preferred path: plain TCP connection on
// port 21, "AUTH TLS" command exchange, then TLS upgrade.  Implicit FTPS
// connects directly over TLS on port 990 without a command exchange.
//
// The module handles TargetNetwork scan targets that carry an explicit
// host:port address.  Generic "local" targets and targets without a colon
// separator default to port 21 for the explicit path.
type FTPSModule struct {
	config *scannerconfig.Config
	// dialer is injectable for testing.  In production code NewFTPSModule
	// sets it to a plain net.Dialer that respects the context deadline.
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewFTPSModule constructs an FTPSModule ready for production use.
func NewFTPSModule(cfg *scannerconfig.Config) *FTPSModule {
	m := &FTPSModule{config: cfg}
	m.dialer = m.defaultDial
	return m
}

func (m *FTPSModule) Name() string                         { return "ftps" }
func (m *FTPSModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *FTPSModule) ScanTargetType() model.ScanTargetType { return model.TargetNetwork }

// defaultDial is the production dialer: plain TCP with a 5 s timeout bounded
// by the context deadline.
func (m *FTPSModule) defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	const dialTimeout = 5 * time.Second
	timeout := dialTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// Scan tries explicit FTPS then implicit FTPS against the target.
func (m *FTPSModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if ctx == nil {
		ctx = context.Background()
	}

	addr := strings.TrimSpace(target.Value)
	if addr == "" || addr == "local" {
		return nil
	}

	// Normalise: if no port, default to 21.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr has no port — use default FTP port.
		host = addr
		port = "21"
		addr = net.JoinHostPort(host, port)
	}

	// 1. Try explicit FTPS (AUTH TLS on the control port).
	emitted, err := m.probeExplicit(ctx, addr, findings)
	if err != nil {
		return err
	}
	if emitted {
		return nil
	}

	// 2. Fall back to implicit FTPS on port 990.
	implicitAddr := net.JoinHostPort(host, "990")
	if port == "990" {
		// Caller already targeted port 990 — treat as implicit.
		implicitAddr = addr
	}
	return m.probeImplicit(ctx, implicitAddr, findings)
}

// probeExplicit attempts explicit FTPS (AUTH TLS) and returns (true, nil)
// when it successfully negotiated TLS and emitted findings, or (false, nil)
// when the server refused/didn't respond to AUTH TLS.
func (m *FTPSModule) probeExplicit(ctx context.Context, addr string, findings chan<- *model.Finding) (bool, error) {
	conn, err := m.dialer(ctx, "tcp", addr)
	if err != nil {
		return false, nil // unreachable — not an error, just skip
	}
	// connOwned tracks whether conn is still responsible for closing the
	// underlying TCP connection. Once we hand ownership to tlsConn we must
	// not close conn separately (tls.Client wraps and owns it).
	connOwned := true
	defer func() {
		if connOwned {
			_ = conn.Close()
		}
	}()

	// Expect the 220 banner.
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return false, nil
	}

	// Send AUTH TLS.
	if _, err = conn.Write([]byte("AUTH TLS\r\n")); err != nil {
		return false, nil
	}

	// Read response.
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, nil
	}
	if !strings.HasPrefix(resp, "234") {
		// Server rejected AUTH TLS (e.g. 502 Command not implemented).
		return false, nil
	}

	// Upgrade the plain connection to TLS. From this point tlsConn owns conn.
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we audit, not validate trust
		MinVersion:         tls.VersionTLS10,
	})
	if err = tlsConn.Handshake(); err != nil {
		return false, nil
	}
	connOwned = false // tlsConn owns the connection now
	defer func() { _ = tlsConn.Close() }()

	state := tlsConn.ConnectionState()
	return true, m.emitChainFindings(ctx, addr, state, "explicit FTPS (AUTH TLS)", findings)
}

// probeImplicit attempts implicit FTPS by dialling addr and wrapping the
// connection in TLS immediately (no FTP command exchange).
func (m *FTPSModule) probeImplicit(ctx context.Context, addr string, findings chan<- *model.Finding) error {
	conn, err := m.dialer(ctx, "tcp", addr)
	if err != nil {
		return nil // unreachable — not an error
	}
	// connOwned tracks whether conn is still responsible for closing the
	// underlying TCP connection. Once we hand ownership to tlsConn we must
	// not close conn separately (tls.Client wraps and owns it).
	connOwned := true
	defer func() {
		if connOwned {
			_ = conn.Close()
		}
	}()

	// Wrap conn in TLS immediately (no FTP command exchange for implicit FTPS).
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we audit, not validate trust
		MinVersion:         tls.VersionTLS10,
	})
	if err = tlsConn.Handshake(); err != nil {
		return nil
	}
	connOwned = false // tlsConn owns the connection now
	defer func() { _ = tlsConn.Close() }()

	state := tlsConn.ConnectionState()
	return m.emitChainFindings(ctx, addr, state, "implicit FTPS", findings)
}

// emitChainFindings emits one finding per certificate in the chain plus one
// finding for the negotiated cipher suite.
func (m *FTPSModule) emitChainFindings(ctx context.Context, addr string, state tls.ConnectionState, probeKind string, findings chan<- *model.Finding) error {
	// --- Cipher suite finding ---
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	cipherAlgo := cipherSuiteAlgorithm(state.CipherSuite)
	tlsVer := tlsVersionName(state.Version)
	kx, pfs := cipherSuiteKeyExchange(cipherName)

	cipherAsset := &model.CryptoAsset{
		ID:             uuid.Must(uuid.NewV7()).String(),
		Function:       "TLS cipher suite",
		Algorithm:      cipherAlgo,
		Library:        cipherName,
		Purpose:        fmt.Sprintf("Negotiated cipher for %s (%s, %s)", addr, probeKind, tlsVer),
		KeyExchange:    kx,
		ForwardSecrecy: pfs,
	}
	crypto.ClassifyCryptoAsset(cipherAsset)
	if err := m.sendFinding(ctx, addr, cipherAsset, findings); err != nil {
		return err
	}

	// --- Certificate chain ---
	chainEntries := tlsutil.WalkCertChain(state.PeerCertificates)
	for i, entry := range chainEntries {
		cert := entry.Cert
		algoName, keySize := certPublicKeyInfo(cert)

		function := "TLS certificate"
		if entry.Position == "leaf" {
			function = "TLS server certificate"
		}

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter

		certAsset := &model.CryptoAsset{
			ID:            uuid.Must(uuid.NewV7()).String(),
			Function:      function,
			Algorithm:     algoName,
			KeySize:       keySize,
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			SerialNumber:  cert.SerialNumber.String(),
			NotBefore:     &notBefore,
			NotAfter:      &notAfter,
			IsCA:          cert.IsCA,
			Purpose:       fmt.Sprintf("Certificate at chain position %d for %s (%s)", i, addr, probeKind),
			ChainPosition: entry.Position,
			ChainDepth:    len(chainEntries),
		}
		if len(entry.SANs) > 0 {
			certAsset.SANs = entry.SANs
		}
		crypto.ClassifyCryptoAsset(certAsset)
		if err := m.sendFinding(ctx, addr, certAsset, findings); err != nil {
			return err
		}
	}
	return nil
}

// sendFinding sends a classified Finding to the findings channel, honouring
// context cancellation.
func (m *FTPSModule) sendFinding(ctx context.Context, addr string, asset *model.CryptoAsset, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryNetwork,
		Source: model.FindingSource{
			Type:            "network",
			Endpoint:        addr,
			DetectionMethod: "ftps-probe",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      "ftps",
		Timestamp:   time.Now(),
	}
	select {
	case findings <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
