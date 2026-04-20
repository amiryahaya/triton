package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

func TestGenerateCA_RoundTrip(t *testing.T) {
	c, err := ca.Generate("instance-xyz")
	require.NoError(t, err)
	require.NotNil(t, c)

	block, _ := pem.Decode(c.CACertPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.IsCA, "CA cert must have IsCA=true")
	assert.True(t, cert.BasicConstraintsValid, "basic constraints must be valid")
	assert.Contains(t, cert.Subject.CommonName, "instance-xyz")
	assert.WithinDuration(t, time.Now().Add(10*365*24*time.Hour), cert.NotAfter, 24*time.Hour)

	keyBlock, _ := pem.Decode(c.CAKeyPEM)
	require.NotNil(t, keyBlock)
	require.Equal(t, "PRIVATE KEY", keyBlock.Type)
	_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err, "CA key must decode as PKCS#8")
}

func TestSignAgentCert_CNAndEKU(t *testing.T) {
	c, err := ca.Generate("inst")
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV7())
	leafPEM, keyPEM, err := c.SignAgentCert(agentID)
	require.NoError(t, err)
	require.NotEmpty(t, leafPEM)
	require.NotEmpty(t, keyPEM)

	block, _ := pem.Decode(leafPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, "agent:"+agentID.String(), leaf.Subject.CommonName)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.NotZero(t, leaf.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.WithinDuration(t, time.Now().Add(365*24*time.Hour), leaf.NotAfter, 24*time.Hour)
	assert.False(t, leaf.IsCA, "agent leaf must not be a CA")

	// The leaf must actually be signed by the CA — verify chain.
	caBlock, _ := pem.Decode(c.CACertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "leaf must chain to CA")

	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
}

func TestSignAgentCert_NilReceiver(t *testing.T) {
	var c *ca.CA
	_, _, err := c.SignAgentCert(uuid.Must(uuid.NewV7()))
	require.Error(t, err)
}

func TestSignAgentCert_UniqueSerials(t *testing.T) {
	c, err := ca.Generate("inst")
	require.NoError(t, err)

	leaf1PEM, _, err := c.SignAgentCert(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	leaf2PEM, _, err := c.SignAgentCert(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	b1, _ := pem.Decode(leaf1PEM)
	l1, err := x509.ParseCertificate(b1.Bytes)
	require.NoError(t, err)
	b2, _ := pem.Decode(leaf2PEM)
	l2, err := x509.ParseCertificate(b2.Bytes)
	require.NoError(t, err)

	assert.NotEqual(t, l1.SerialNumber.Text(16), l2.SerialNumber.Text(16),
		"each issued leaf must have a unique serial number")
}
