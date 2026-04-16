package agentpush

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testEngineKeypair creates a self-signed Ed25519 CA cert + key for testing.
// The test cert has IsCA=true so standard x509.Verify works in tests.
// Note: the real engine cert does NOT have IsCA — the agent-gateway uses a
// custom VerifyPeerCertificate that checks the raw issuer signature instead
// of full X.509 chain validation.
func testEngineKeypair(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-engine",
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func TestMintAgentCert_RoundTrip(t *testing.T) {
	engineCert, engineKey := testEngineKeypair(t)

	ac, err := MintAgentCert(engineCert, engineKey, "testhost")
	if err != nil {
		t.Fatalf("MintAgentCert: %v", err)
	}

	// Parse agent cert back.
	block, _ := pem.Decode(ac.CertPEM)
	if block == nil {
		t.Fatal("failed to decode agent cert PEM")
	}
	agentCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse agent cert: %v", err)
	}

	// CN
	if agentCert.Subject.CommonName != "testhost" {
		t.Errorf("CN = %q, want %q", agentCert.Subject.CommonName, "testhost")
	}

	// Organization
	if len(agentCert.Subject.Organization) != 1 || agentCert.Subject.Organization[0] != "Triton Agent" {
		t.Errorf("Organization = %v, want [Triton Agent]", agentCert.Subject.Organization)
	}

	// Validity ~90 days (allow 1 second of clock skew).
	validity := agentCert.NotAfter.Sub(agentCert.NotBefore)
	expectedDays := 90
	if d := int(validity.Hours() / 24); d != expectedDays {
		t.Errorf("validity = %d days, want %d", d, expectedDays)
	}

	// KeyUsage
	if agentCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing KeyUsageDigitalSignature")
	}

	// ExtKeyUsage
	if len(agentCert.ExtKeyUsage) != 1 || agentCert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", agentCert.ExtKeyUsage)
	}

	// Agent key parses as Ed25519.
	keyBlock, _ := pem.Decode(ac.KeyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode agent key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse agent key: %v", err)
	}
	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("agent key type = %T, want ed25519.PrivateKey", key)
	}

	// EngineCACert is valid PEM.
	caBlock, _ := pem.Decode(ac.EngineCACert)
	if caBlock == nil {
		t.Fatal("failed to decode engine CA cert PEM")
	}
	_, err = x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse engine CA cert: %v", err)
	}
}

func TestMintAgentCert_VerifiesAgainstEngineCert(t *testing.T) {
	engineCert, engineKey := testEngineKeypair(t)

	ac, err := MintAgentCert(engineCert, engineKey, "verifyhost")
	if err != nil {
		t.Fatalf("MintAgentCert: %v", err)
	}

	// Parse agent cert.
	block, _ := pem.Decode(ac.CertPEM)
	agentCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse agent cert: %v", err)
	}

	// Build a pool with the engine cert and verify.
	// Note: this works because our test engine cert has IsCA=true. The real
	// engine cert is a leaf (no IsCA), so the agent-gateway uses a custom
	// VerifyPeerCertificate that does raw signature verification instead of
	// full x509.Verify chain validation.
	pool := x509.NewCertPool()
	pool.AddCert(engineCert)

	_, err = agentCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("agent cert did not verify against engine cert: %v", err)
	}
}

func TestMintAgentCert_UniqueSerials(t *testing.T) {
	engineCert, engineKey := testEngineKeypair(t)
	serials := make(map[string]struct{}, 10)

	for i := 0; i < 10; i++ {
		ac, err := MintAgentCert(engineCert, engineKey, "host")
		if err != nil {
			t.Fatalf("MintAgentCert[%d]: %v", i, err)
		}

		block, _ := pem.Decode(ac.CertPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse[%d]: %v", i, err)
		}

		s := cert.SerialNumber.String()
		if _, dup := serials[s]; dup {
			t.Fatalf("duplicate serial at iteration %d: %s", i, s)
		}
		serials[s] = struct{}{}
	}
}

func TestMintAgentCert_FingerprintIsHex64(t *testing.T) {
	engineCert, engineKey := testEngineKeypair(t)

	ac, err := MintAgentCert(engineCert, engineKey, "fphost")
	if err != nil {
		t.Fatalf("MintAgentCert: %v", err)
	}

	if len(ac.Fingerprint) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(ac.Fingerprint))
	}

	// Must be valid hex.
	_, err = hex.DecodeString(ac.Fingerprint)
	if err != nil {
		t.Errorf("fingerprint is not valid hex: %v", err)
	}
}

func TestMintAgentCert_NilEngineCert(t *testing.T) {
	_, engineKey := testEngineKeypair(t)
	_, err := MintAgentCert(nil, engineKey, "host")
	if err == nil {
		t.Fatal("expected error for nil engine cert")
	}
}

func TestMintAgentCert_NilEngineKey(t *testing.T) {
	engineCert, _ := testEngineKeypair(t)
	_, err := MintAgentCert(engineCert, nil, "host")
	if err == nil {
		t.Fatal("expected error for nil engine key")
	}
}

func TestMintAgentCert_EmptyHostname(t *testing.T) {
	engineCert, engineKey := testEngineKeypair(t)
	_, err := MintAgentCert(engineCert, engineKey, "")
	if err == nil {
		t.Fatal("expected error for empty hostname")
	}
}
