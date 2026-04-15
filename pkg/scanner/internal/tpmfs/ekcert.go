package tpmfs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

// maxEKCertSize caps file reads to prevent runaway allocations on a
// pathological /sys/.../endorsement_key_cert file. 64 KB is far above
// any realistic EK cert (typical: 1–2 KB).
const maxEKCertSize = 64 * 1024

// ReadEKCert reads a DER-encoded endorsement-key certificate from path,
// parses it via crypto/x509, and returns a typed EKCert. Missing files
// return (nil, nil) — EK cert absence is not a failure. Parse errors
// are surfaced to the caller.
func ReadEKCert(path string) (*EKCert, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tpmfs: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	der, err := io.ReadAll(io.LimitReader(f, maxEKCertSize))
	if err != nil {
		return nil, fmt.Errorf("tpmfs: read %s: %w", path, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tpmfs: parse EK cert: %w", err)
	}
	algo, size := publicKeyInfo(cert.PublicKey)
	return &EKCert{
		RawDER:    der,
		Algorithm: algo,
		KeySize:   size,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
	}, nil
}

// publicKeyInfo extracts algorithm name + key size from a parsed public key.
func publicKeyInfo(pub interface{}) (algo string, size int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}
