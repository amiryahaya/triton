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

// TestGateway_RotateCert_OldCertStillAccepted pins the deliberate
// tradeoff spelled out in RotateCert's doc comment, plus the partial
// mitigation that PhoneHome's status-check provides.
//
// What's pinned:
//
//  1. Post-rotation (pre-revoke): the OLD cert still authenticates
//     every endpoint. MTLSCNAuth validates chain + CN prefix +
//     revocation-list membership only — it does NOT check the
//     presenting serial matches manage_agents.cert_serial. If a
//     future refactor adds that check, this test fails.
//
//  2. Post-rotation + admin-revoke: the OLD serial is NOT in the
//     revocation list (admin Revoke only touches the current
//     cert_serial on the manage_agents row). IsRevoked(oldSerial)
//     therefore still returns false — the cert CHAIN remains valid.
//     If a future Revoke walks historical serials, this assertion
//     fails.
//
//  3. Partial-mitigation observation: even though the OLD cert's
//     chain is still valid, PhoneHome rejects it post-revoke because
//     MarkActive's UPDATE is guarded by `status != 'revoked'`.
//     Endpoints that don't hit agent-status (IngestScan,
//     IngestFindings, RotateCert itself) would still accept the old
//     cert — the tradeoff is the revocation is NOT cert-level, only
//     row-level on the one behaviour that happens to read it.
//
// Re-read RotateCert's doc comment before changing this test. The
// semantics here are deliberately narrow: we document what is and
// isn't defended against, not what "should" happen in an ideal world.
func TestGateway_RotateCert_OldCertStillAccepted(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-rotate")

	// Keep the pre-rotation bundle + client alive — the test is all
	// about what the OLD cert can still do after rotation.
	oldClient := mTLSClient(t, bundle)
	oldBlock, _ := pem.Decode(bundle.clientCertPEM)
	require.NotNil(t, oldBlock)
	oldLeaf, err := x509.ParseCertificate(oldBlock.Bytes)
	require.NoError(t, err)
	oldSerial := oldLeaf.SerialNumber.Text(16)

	// Baseline: the old cert authenticates a phone-home before rotation.
	baseline, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	_ = baseline.Body.Close()
	require.Equal(t, http.StatusOK, baseline.StatusCode,
		"baseline phone-home with issued cert must succeed")

	// Rotate: exchange the cert under mTLS using the old cert.
	rotateResp, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/rotate-cert",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer func() { _ = rotateResp.Body.Close() }()
	require.Equal(t, http.StatusOK, rotateResp.StatusCode)
	var body struct {
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
	}
	require.NoError(t, json.NewDecoder(rotateResp.Body).Decode(&body))
	require.NotEmpty(t, body.ClientCertPEM)
	require.NotEmpty(t, body.ClientKeyPEM)
	newBlock, _ := pem.Decode([]byte(body.ClientCertPEM))
	require.NotNil(t, newBlock)
	newLeaf, err := x509.ParseCertificate(newBlock.Bytes)
	require.NoError(t, err)
	newSerial := newLeaf.SerialNumber.Text(16)
	require.NotEqual(t, oldSerial, newSerial, "rotation must produce a new serial")

	// (1) Pin: the OLD cert keeps working at every endpoint after
	// rotation, because MTLSCNAuth does NOT compare presenting serial
	// against manage_agents.cert_serial.
	postRotateResp, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	_ = postRotateResp.Body.Close()
	assert.Equal(t, http.StatusOK, postRotateResp.StatusCode,
		"post-rotation, old cert must still authenticate — "+
			"mtls middleware checks revocation list, not agent-row serial match")

	// The old cert also still succeeds at IngestScan — which notably
	// does NOT hit any agent-status check. If a future refactor adds
	// a status guard to IngestScan (reasonable!) and also adds the
	// OLD serial to the revocation list during rotation (arguably
	// better), both of these assertions will flip and trigger a
	// conscious design review.
	scanBody := []byte(`{
		"id":"00000000-0000-0000-0000-000000000000",
		"metadata":{"hostname":"edge-rotate","os":"linux","scanProfile":"quick","timestamp":"2026-04-19T00:00:00Z"},
		"systems":[],
		"findings":[],
		"summary":{}
	}`)
	postRotateScanResp, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/scans",
		"application/json", bytes.NewReader(scanBody))
	require.NoError(t, err)
	_ = postRotateScanResp.Body.Close()
	assert.Equal(t, http.StatusAccepted, postRotateScanResp.StatusCode,
		"post-rotation, old cert must still push scans — IngestScan has no status check")

	// Admin revoke via DELETE /api/v1/admin/agents/{id}. This reads the
	// CURRENT cert_serial off the row (now the NEW serial) and adds THAT
	// to the revocation list. The OLD serial is not touched.
	list, err := f.AgentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	agentID := list[0].ID
	require.Equal(t, newSerial, list[0].CertSerial,
		"admin view reflects the post-rotation serial")
	revokeReq, err := http.NewRequest(http.MethodDelete,
		"/api/v1/admin/agents/"+agentID.String(), nil)
	require.NoError(t, err)
	rr := &testRecorder{header: http.Header{}, body: &bytes.Buffer{}, status: 200}
	f.AdminSrv.ServeHTTP(rr, revokeReq)
	require.Equal(t, http.StatusNoContent, rr.status,
		"revoke must succeed: %s", rr.body.String())

	// Force cache refresh so the 30s TTL doesn't mask the revoke.
	require.NoError(t, f.CaStore.RefreshRevocationCache(context.Background()))

	// (2) Pin: the OLD serial is NOT in the revocation list after
	// admin revoke. Only the NEW (current) serial is. If a future
	// Revoke walks historical serials, this assertion flips.
	revokedNew, err := f.CaStore.IsRevoked(context.Background(), newSerial)
	require.NoError(t, err)
	assert.True(t, revokedNew,
		"NEW serial must be in the revocation list after admin revoke")
	revokedOld, err := f.CaStore.IsRevoked(context.Background(), oldSerial)
	require.NoError(t, err)
	assert.False(t, revokedOld,
		"OLD serial must NOT be added to the revocation list on admin revoke — "+
			"admin Revoke reads a.CertSerial (the CURRENT serial only)")

	// (3) Observation: post-revoke, the old cert still survives
	// MTLSCNAuth (because its serial is not on the revocation list),
	// but PhoneHome rejects it with 401 because MarkActive's UPDATE
	// filters out status='revoked' rows. This is the partial
	// mitigation noted in the doc comment: revocation is row-level
	// on agent-status for behaviours that happen to read it, not
	// cert-level across the full endpoint surface.
	postRevokePhoneHome, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	_ = postRevokePhoneHome.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, postRevokePhoneHome.StatusCode,
		"post-revoke, old cert's phone-home is rejected via MarkActive status check "+
			"(not via the revocation list)")

	// Meanwhile, endpoints that don't touch agent-status still accept
	// the old cert — concrete demonstration of the tradeoff. If this
	// surprises you, re-read RotateCert's doc comment before "fixing".
	postRevokeScan, err := oldClient.Post(f.URL+"/api/v1/gateway/agents/scans",
		"application/json", bytes.NewReader(scanBody))
	require.NoError(t, err)
	_ = postRevokeScan.Body.Close()
	assert.Equal(t, http.StatusAccepted, postRevokeScan.StatusCode,
		"post-revoke, old cert still pushes scans — IngestScan doesn't hit status; "+
			"the revocation-list miss on oldSerial leaves the cert chain valid")
}
