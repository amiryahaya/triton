package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// certPublicKeyInfo extracts the algorithm name and key size from an X.509 certificate's public key.
// This is a shared helper used by certstore, ldap, and protocol modules.
func certPublicKeyInfo(cert *x509.Certificate) (algoName string, keySize int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := pub.N.BitLen()
		return fmt.Sprintf("RSA-%d", size), size
	case *ecdsa.PublicKey:
		size := pub.Curve.Params().BitSize
		return fmt.Sprintf("ECDSA-P%d", size), size
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}
