// Package ca is the Manage Server's X.509 certificate authority. It mints
// a P-256 root per Manage instance, signs agent client leaves, and issues
// a short-lived server leaf for the :8443 gateway listener.
//
// Unlike pkg/server/engine (which wraps the CA private key in XChaCha20-
// Poly1305 at rest), this package stores the key as PKCS#8 PEM plaintext.
// Deferring at-rest encryption is an explicit spec decision (§7: "plaintext,
// protected by DB access controls") to keep Batch F shippable without
// introducing a master-key bootstrap. A future hardening pass can layer
// encryption without changing callers.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// CA is a self-signed P-256 root. The CACertPEM is distributed to agents
// (inside the bundle's ca.crt) as their trust anchor for the gateway;
// CAKeyPEM signs agent and server leaves and never leaves the process.
type CA struct {
	CACertPEM  []byte
	CAKeyPEM   []byte
	instanceID string
}

// caValidity is the self-signed CA lifetime. Agents carry 1y leaves and
// can rotate; a 10y root matches internal-CA practice and keeps the
// rotation cadence manageable for operators.
const caValidity = 10 * 365 * 24 * time.Hour

// agentCertValidity is the lifetime of an issued agent leaf. Agents call
// /api/v1/gateway/agents/rotate-cert before expiry to mint a fresh
// serial; admins can also revoke independently of expiry.
const agentCertValidity = 365 * 24 * time.Hour

// Generate mints a fresh P-256 root for the given Manage instance. The
// CN embeds instanceID so operators can visually distinguish CAs across
// environments when inspecting a bundle's ca.crt.
func Generate(instanceID string) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Triton Manage CA — " + instanceID,
			Organization: []string{"Triton"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}

	return &CA{
		CACertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAKeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		instanceID: instanceID,
	}, nil
}

// SignAgentCert mints a leaf client certificate for the given agent UUID.
// The keypair is generated here and returned alongside the leaf so the
// bundle builder can ship both to the operator. CN is "agent:<uuid>" —
// the mtlsCNAuth middleware asserts this prefix on every gateway request.
// Returns (leafCertPEM, leafKeyPEM, err).
func (c *CA) SignAgentCert(agentID uuid.UUID) (leafCertPEM, leafKeyPEM []byte, err error) {
	if c == nil {
		return nil, nil, errors.New("nil CA")
	}
	caCert, caKey, err := c.parse()
	if err != nil {
		return nil, nil, err
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "agent:" + agentID.String(),
			Organization: []string{"Triton Manage Agent"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(agentCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafPriv.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign agent leaf: %w", err)
	}

	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
		nil
}

// parse decodes the CA cert + private key PEM blobs. Callers use it to
// obtain the signing material for SignAgentCert + server-leaf issuance.
func (c *CA) parse() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(c.CACertPEM)
	if cb == nil {
		return nil, nil, errors.New("CA cert PEM is invalid")
	}
	cc, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	kb, _ := pem.Decode(c.CAKeyPEM)
	if kb == nil {
		return nil, nil, errors.New("CA key PEM is invalid")
	}
	rk, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	kk, ok := rk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA: %T", rk)
	}
	return cc, kk, nil
}
