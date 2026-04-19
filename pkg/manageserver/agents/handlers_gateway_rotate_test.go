//go:build integration

package agents_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGateway_RotateCert_ReturnsNewCert covers the happy path of
// /api/v1/gateway/agents/rotate-cert: the agent presents its current
// cert, the server signs a fresh leaf with a new serial (same CN,
// same UUID), and persists the new serial on manage_agents.
func TestGateway_RotateCert_ReturnsNewCert(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-01")
	client := mTLSClient(t, bundle)

	// Capture the pre-rotation serial + CN for comparison.
	oldBlock, _ := pem.Decode(bundle.clientCertPEM)
	require.NotNil(t, oldBlock)
	oldLeaf, err := x509.ParseCertificate(oldBlock.Bytes)
	require.NoError(t, err)
	oldSerial := oldLeaf.SerialNumber.Text(16)
	oldCN := oldLeaf.Subject.CommonName
	require.True(t, strings.HasPrefix(oldCN, "agent:"))

	// The agent row before rotation still carries the old serial.
	preList, err := f.AgentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, preList, 1)
	preAgent := preList[0]
	assert.Equal(t, oldSerial, preAgent.CertSerial)

	// Call rotate-cert.
	resp, err := client.Post(f.URL+"/api/v1/gateway/agents/rotate-cert",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
		ExpiresAt     string `json:"expires_at"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotEmpty(t, body.ClientCertPEM, "response must include new client cert")
	require.NotEmpty(t, body.ClientKeyPEM, "response must include new private key")
	require.NotEmpty(t, body.ExpiresAt, "response must include new expiry")

	// Parse the fresh leaf and compare against the pre-rotation one.
	newBlock, _ := pem.Decode([]byte(body.ClientCertPEM))
	require.NotNil(t, newBlock)
	newLeaf, err := x509.ParseCertificate(newBlock.Bytes)
	require.NoError(t, err)
	newSerial := newLeaf.SerialNumber.Text(16)

	assert.NotEqual(t, oldSerial, newSerial, "new leaf must have a fresh serial")
	assert.Equal(t, oldCN, newLeaf.Subject.CommonName,
		"CN must be stable across rotation — same agent, same UUID")

	// The agent row now carries the NEW serial, and GetByCertSerial
	// resolves back to the same agent.
	postAgent, err := f.AgentStore.GetByCertSerial(context.Background(), newSerial)
	require.NoError(t, err)
	assert.Equal(t, preAgent.ID, postAgent.ID,
		"rotation must update cert_serial in place — same agent row")

	// The OLD serial is no longer reachable via GetByCertSerial (the
	// UNIQUE(cert_serial) constraint guarantees only one row can carry
	// a given serial). It's NOT auto-revoked — admins can revoke the
	// old cert independently; rotation alone doesn't.
	_, err = f.AgentStore.GetByCertSerial(context.Background(), oldSerial)
	require.Error(t, err, "old serial must not resolve to an agent after rotation")
}
