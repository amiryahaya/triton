// Package agentpush handles agent binary deployment and per-host certificate
// minting for the engine's push-based agent installation flow.
package agentpush

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// AgentCert holds the PEM-encoded certificate and key for an installed agent,
// plus the engine's own cert PEM (used as the trust root on the agent side)
// and a SHA-256 fingerprint of the agent cert for DB registration.
type AgentCert struct {
	CertPEM      []byte // agent's certificate PEM
	KeyPEM       []byte // agent's Ed25519 private key PEM
	EngineCACert []byte // engine's own cert PEM (agent uses as trust root)
	Fingerprint  string // SHA-256 hex of agent cert DER (64 chars)
}

// MintAgentCert generates an Ed25519 keypair for a host and signs a client
// certificate using the engine's private key. The engine's cert acts as a
// de-facto CA for its agents — the agent-gateway verifies with a custom
// VerifyPeerCertificate that checks issuer signature rather than full X.509
// chain validation, because the real engine cert is a leaf (no IsCA flag).
//
// The returned AgentCert.EngineCACert is the engine's own cert PEM so the
// agent can configure it as its TLS trust root.
func MintAgentCert(engineCert *x509.Certificate, engineKey crypto.Signer, hostname string) (*AgentCert, error) {
	if engineCert == nil {
		return nil, fmt.Errorf("engine certificate is nil")
	}
	if engineKey == nil {
		return nil, fmt.Errorf("engine signing key is nil")
	}
	if hostname == "" {
		return nil, fmt.Errorf("hostname is empty")
	}

	// Generate agent Ed25519 keypair.
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}

	// Random 128-bit serial number.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Triton Agent"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 90),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Sign with the engine's key. The engine cert is the "parent" even
	// though it may not have IsCA set — this is fine because we control
	// the verification logic on the agent-gateway side.
	certDER, err := x509.CreateCertificate(rand.Reader, &template, engineCert, agentPub, engineKey)
	if err != nil {
		return nil, fmt.Errorf("sign agent cert: %w", err)
	}

	// PEM-encode the agent cert.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// PEM-encode the agent private key.
	keyDER, err := x509.MarshalPKCS8PrivateKey(agentPriv)
	if err != nil {
		return nil, fmt.Errorf("marshal agent key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Engine's own cert as the trust root the agent will use.
	engineCACertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: engineCert.Raw})

	// SHA-256 fingerprint of the agent cert DER.
	fp := sha256.Sum256(certDER)
	fpHex := hex.EncodeToString(fp[:])

	return &AgentCert{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		EngineCACert: engineCACertPEM,
		Fingerprint:  fpHex,
	}, nil
}
