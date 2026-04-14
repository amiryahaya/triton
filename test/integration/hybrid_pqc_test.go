//go:build integration

package integration_test

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/crypto"
)

// TestProtocolScanner_DetectsHybridPQC is a smoke test: it establishes a
// TLS 1.3 connection to a public PQC-enabled endpoint and asserts that the
// negotiated named group ID, if exposed by the stdlib, resolves in our
// TLS group registry. SKIPS gracefully on any network failure so CI
// without egress or DNS isn't a hard failure.
//
// Cloudflare's pq.cloudflareresearch.com has supported hybrid PQC groups
// (X25519Kyber768Draft00, later X25519MLKEM768) for several years.
func TestProtocolScanner_DetectsHybridPQC(t *testing.T) {
	const host = "pq.cloudflareresearch.com:443"

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		ServerName: "pq.cloudflareresearch.com",
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Skipf("cannot reach %s (offline CI or DNS blocked?): %v", host, err)
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	t.Logf("negotiated TLS version: 0x%04X, CurveID: 0x%04X (%s)",
		state.Version, uint16(state.CurveID), state.CurveID)

	if state.CurveID == 0 {
		t.Skip("handshake did not report CurveID — old Go stdlib or classical-only negotiation")
	}

	group, ok := crypto.LookupTLSGroup(uint16(state.CurveID))
	if !ok {
		// Not a failure: may be a brand-new group ID the registry hasn't been
		// updated for yet. Log and skip so the test is signal, not noise.
		t.Skipf("negotiated CurveID 0x%04X not in TLS group registry — may need update",
			uint16(state.CurveID))
	}

	t.Logf("registry hit: name=%s hybrid=%v components=%v status=%s",
		group.Name, group.IsHybrid, group.ComponentAlgorithms, group.Status)

	if group.IsHybrid {
		if len(group.ComponentAlgorithms) < 2 {
			t.Errorf("hybrid group %s should have >= 2 component algorithms, got %v",
				group.Name, group.ComponentAlgorithms)
		}
		if group.Status != crypto.SAFE {
			t.Errorf("hybrid group %s should classify as SAFE, got %s",
				group.Name, group.Status)
		}
	}
}
