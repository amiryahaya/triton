package engine

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMasterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestCA_GenerateAndSign_RoundTrip(t *testing.T) {
	master := newMasterKey(t)

	ca, err := GenerateCA(master)
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.NotEmpty(t, ca.CACertPEM)
	require.NotEmpty(t, ca.CAKeyEncrypted)
	require.Len(t, ca.CAKeyNonce, 24, "XChaCha20 uses 24-byte nonce")

	// CA cert is parseable PEM.
	block, _ := pem.Decode(ca.CACertPEM)
	require.NotNil(t, block, "CA cert PEM must decode")
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, caCert.IsCA)
	assert.Equal(t, "Triton Engine CA", caCert.Subject.CommonName)

	// Sign an engine cert.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	engCertPEM, err := ca.SignEngineCert(master, "engine-prod-01", pub)
	require.NoError(t, err)
	require.NotEmpty(t, engCertPEM)

	engBlock, _ := pem.Decode(engCertPEM)
	require.NotNil(t, engBlock, "engine cert PEM must decode")
	engCert, err := x509.ParseCertificate(engBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "engine-prod-01", engCert.Subject.CommonName)
	assert.False(t, engCert.IsCA)

	// Verify the leaf chains to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = engCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "engine cert must verify against CA")
}

// TestCA_SignLeaf_ECDSAP256 — the generic SignLeaf helper must accept an
// externally-generated ECDSA-P256 public key (the shape Manage presents
// to Report during enrolment), sign it under the engine CA, and produce a
// verifiable ClientAuth leaf with the configured CN + validity window.
func TestCA_SignLeaf_ECDSAP256(t *testing.T) {
	master := newMasterKey(t)

	ca, err := GenerateCA(master)
	require.NoError(t, err)

	// Parse the CA cert once so we can verify the leaf chains back.
	caBlock, _ := pem.Decode(ca.CACertPEM)
	require.NotNil(t, caBlock)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)

	// ECDSA-P256 — the key shape Manage generates locally before the
	// enrolment POST.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const cn = "manage:abc123:f47ac10b-58cc-4372-a567-0e02b2c3d479"
	const validity = 365 * 24 * time.Hour

	leafPEM, err := ca.SignLeaf(master, cn, validity, &priv.PublicKey)
	require.NoError(t, err)

	block, _ := pem.Decode(leafPEM)
	require.NotNil(t, block, "SignLeaf must emit parseable PEM")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, cn, leaf.Subject.CommonName)
	assert.False(t, leaf.IsCA)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth,
		"SignLeaf must set EKU=ClientAuth")
	// NotAfter within a small slop around now+validity.
	expectedNotAfter := time.Now().Add(validity)
	assert.WithinDuration(t, expectedNotAfter, leaf.NotAfter, 5*time.Minute,
		"NotAfter must reflect the requested validity")

	// Leaf chains to the CA under ClientAuth.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "SignLeaf output must verify under engine CA")
}

func TestCA_SignWithWrongMasterKey_Fails(t *testing.T) {
	master1 := newMasterKey(t)
	master2 := newMasterKey(t)

	ca, err := GenerateCA(master1)
	require.NoError(t, err)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, err = ca.SignEngineCert(master2, "engine-x", pub)
	require.Error(t, err, "decryption must fail under wrong master key")
}
