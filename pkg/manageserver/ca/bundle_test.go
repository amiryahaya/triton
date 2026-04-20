package ca_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// extractTarGz unpacks a gzip-compressed tar archive into a name → body
// map. Bundle contents are small; we read everything into memory for
// test assertions.
func extractTarGz(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		// Keep the tar header mode on a per-name basis so tests can
		// assert client.key is 0400. Tar header Mode is int64; pack
		// low + high byte so an 0o400 value survives the round trip.
		out[hdr.Name] = body
		m := hdr.Mode & 0o777
		out[hdr.Name+"__mode"] = []byte{byte(m >> 8), byte(m & 0xff)}
	}
	return out
}

func TestBuildBundle_ContainsAllFiles(t *testing.T) {
	c, err := ca.Generate("inst-1")
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV7())
	leafPEM, keyPEM, err := c.SignAgentCert(agentID)
	require.NoError(t, err)

	raw, err := ca.BuildBundle(ca.BundleInputs{
		AgentID:           agentID,
		ManageGatewayURL:  "https://localhost:8443",
		AgentKeyPEM:       keyPEM,
		AgentCertPEM:      leafPEM,
		ManageCACertPEM:   c.CACertPEM,
		PhoneHomeInterval: 60 * time.Second,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	files := extractTarGz(t, raw)

	// All four expected files present.
	require.Contains(t, files, "client.crt")
	require.Contains(t, files, "client.key")
	require.Contains(t, files, "ca.crt")
	require.Contains(t, files, "config.yaml")

	// client.crt must parse back to a cert with the expected CN.
	block, _ := pem.Decode(files["client.crt"])
	require.NotNil(t, block, "client.crt must be valid PEM")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "agent:"+agentID.String(), leaf.Subject.CommonName)

	// client.key must parse.
	kb, _ := pem.Decode(files["client.key"])
	require.NotNil(t, kb, "client.key must be valid PEM")
	_, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	require.NoError(t, err)

	// ca.crt must parse + be the root.
	cb, _ := pem.Decode(files["ca.crt"])
	require.NotNil(t, cb)
	caCert, err := x509.ParseCertificate(cb.Bytes)
	require.NoError(t, err)
	assert.True(t, caCert.IsCA)

	// config.yaml contains all three load-bearing keys.
	cfg := string(files["config.yaml"])
	assert.Contains(t, cfg, "manage_gateway_url: https://localhost:8443")
	assert.Contains(t, cfg, "agent_id: "+agentID.String())
	assert.Contains(t, cfg, "phone_home_interval: 1m0s")

	// client.key must be mode 0400 (secret).
	mode := files["client.key__mode"]
	require.Len(t, mode, 2)
	modeVal := (int64(mode[0]) << 8) | int64(mode[1])
	assert.Equal(t, int64(0o400), modeVal, "client.key must be mode 0400")
}

func TestBuildBundle_RejectsEmptyGatewayURL(t *testing.T) {
	_, err := ca.BuildBundle(ca.BundleInputs{
		AgentID:           uuid.Must(uuid.NewV7()),
		PhoneHomeInterval: 60 * time.Second,
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "manage_gateway_url"))
}

func TestBuildBundle_RejectsNonPositiveInterval(t *testing.T) {
	_, err := ca.BuildBundle(ca.BundleInputs{
		AgentID:          uuid.Must(uuid.NewV7()),
		ManageGatewayURL: "https://localhost:8443",
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone_home_interval"))
}
