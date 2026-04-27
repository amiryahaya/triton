package portscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// extractTLSCert dials ip:port with TLS, extracts the leaf certificate.
// Returns nil on any failure — TLS extraction is best-effort.
func extractTLSCert(ctx context.Context, ip string, port int, timeout time.Duration) *scanrunner.TLSCertInfo {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil
	}
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // intentional audit scan
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close() //nolint:errcheck
		return nil
	}
	conn := tlsConn
	defer conn.Close() //nolint:errcheck

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]

	info := &scanrunner.TLSCertInfo{
		Subject:      leaf.Subject.CommonName,
		Issuer:       leaf.Issuer.CommonName,
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		SANs:         leaf.DNSNames,
		SerialNumber: leaf.SerialNumber.String(),
		IsSelfSigned: leaf.Issuer.String() == leaf.Subject.String(),
	}

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.Algorithm = "ECDSA"
		info.KeyBits = pub.Params().BitSize
	default:
		info.Algorithm = fmt.Sprintf("%T", leaf.PublicKey)
	}
	return info
}
