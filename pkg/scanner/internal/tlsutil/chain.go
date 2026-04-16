// Package tlsutil provides shared utilities for TLS certificate chain analysis
// used by the protocol scanner and future FTPS/TLS-observer modules.
package tlsutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// ChainEntry holds the analysis result for a single certificate in a TLS chain.
type ChainEntry struct {
	// Cert is the original parsed certificate.
	Cert *x509.Certificate

	// Position is one of "leaf", "intermediate", or "root".
	Position string

	// WeakSignature is true when the signing algorithm is considered weak
	// (MD2, MD5, SHA-1 variants).
	WeakSignature bool

	// WeakSigAlgo is the PQC-registry name of the weak algorithm (e.g. "SHA-1").
	// Only meaningful when WeakSignature is true.
	WeakSigAlgo string

	// ExpiryWarning is true when the certificate is still valid but expires
	// within the next 30 days.
	ExpiryWarning bool

	// DaysRemaining is the number of whole days until expiry.
	// Only meaningful when ExpiryWarning is true.
	DaysRemaining int

	// SANs contains the Subject Alternative Names (DNS names + IP addresses)
	// extracted from the certificate. Only populated for the leaf (index 0).
	SANs []string
}

// WalkCertChain analyses a certificate chain and returns one ChainEntry per
// certificate. The slice ordering must match the TLS presentation order:
// index 0 = leaf, index len-1 = root (if present).
func WalkCertChain(certs []*x509.Certificate) []ChainEntry {
	if len(certs) == 0 {
		return nil
	}

	chainLen := len(certs)
	entries := make([]ChainEntry, 0, chainLen)

	for i, cert := range certs {
		e := ChainEntry{
			Cert:     cert,
			Position: chainPosition(i, chainLen, cert),
		}

		// Weak signature algorithm detection.
		if isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
			e.WeakSignature = true
			e.WeakSigAlgo = SigAlgoToPQCName(cert.SignatureAlgorithm)
		}

		// Expiry warning: cert is still valid but expires within 30 days.
		now := time.Now()
		if cert.NotAfter.After(now) {
			days := int(time.Until(cert.NotAfter).Hours() / 24)
			if days <= 30 {
				e.ExpiryWarning = true
				e.DaysRemaining = days
			}
		}

		// SAN extraction — leaf only (index 0).
		if i == 0 && (len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0) {
			sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
			sans = append(sans, cert.DNSNames...)
			for _, ip := range cert.IPAddresses {
				sans = append(sans, ip.String())
			}
			e.SANs = sans
		}

		entries = append(entries, e)
	}

	return entries
}

// CertAlgoName returns a display-friendly algorithm name derived from the
// certificate's public key type and size.
func CertAlgoName(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%d", pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// SigAlgoToPQCName maps an x509.SignatureAlgorithm to a PQC-registry algorithm
// name. This mirrors the mapping used in the main protocol scanner.
func SigAlgoToPQCName(algo x509.SignatureAlgorithm) string {
	switch algo {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return "SHA-1"
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		return "SHA-256"
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return "SHA-384"
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return "SHA-512"
	case x509.PureEd25519:
		return "Ed25519"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.MD2WithRSA:
		return "MD2"
	default:
		return algo.String()
	}
}

// chainPosition determines the position label for a certificate in its chain.
// Position is "leaf" for index 0, "root" for a self-signed CA at the tail,
// and "intermediate" for everything else.
func chainPosition(index, chainLen int, cert *x509.Certificate) string {
	switch {
	case index == 0:
		return "leaf"
	case index == chainLen-1 && cert.IsCA && isSelfSigned(cert):
		return "root"
	default:
		return "intermediate"
	}
}

// isWeakSignatureAlgorithm returns true for MD2, MD5 and SHA-1 signature
// algorithms.
func isWeakSignatureAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// isSelfSigned returns true when the certificate's issuer and subject raw bytes
// are identical.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}
