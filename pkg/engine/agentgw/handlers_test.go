package agentgw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/agentpush"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// selfSignedCert generates a self-signed Ed25519 cert for test use.
func selfSignedCert(t *testing.T, cn string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

// fingerprint returns the SHA-256 hex fingerprint of a cert's raw DER.
func fingerprint(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fp[:])
}

// requestWithCert creates an HTTP request whose TLS state contains the given
// peer certificate, simulating an mTLS connection.
func requestWithCert(method, path string, body []byte, cert *x509.Certificate) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return r
}

// stubRelay records heartbeat relay calls.
type stubRelay struct {
	mu    sync.Mutex
	calls []string // host IDs
	err   error
}

func (r *stubRelay) RelayHeartbeat(_ context.Context, hostID, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, hostID)
	return r.err
}

func (r *stubRelay) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// stubDispatcher records calls for test verification.
type stubDispatcher struct {
	pendingCmd      *ScanCommand
	submitCalled    bool
	submittedHostID string
	submittedBody   []byte
}

func (d *stubDispatcher) GetPendingScan(hostID string) *ScanCommand { return d.pendingCmd }
func (d *stubDispatcher) SubmitFindings(_ context.Context, hostID string, body []byte) error {
	d.submitCalled = true
	d.submittedHostID = hostID
	d.submittedBody = body
	return nil
}

// ---------------------------------------------------------------------------
// middleware tests
// ---------------------------------------------------------------------------

func TestAgentIdentityMiddleware_NoCert_401(t *testing.T) {
	mw := AgentIdentityMiddleware(nil)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	// Request without TLS at all.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if called {
		t.Fatal("handler should not have been called")
	}
}

func TestAgentIdentityMiddleware_KnownAgent_PopulatesContext(t *testing.T) {
	cert, _ := selfSignedCert(t, "test-host")
	fp := fingerprint(cert)

	store := NewInMemoryAgentStore()
	store.RegisterAgent("host-42", fp, "1.0.0")

	mw := AgentIdentityMiddleware(store)
	var got *AgentIdentity
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = AgentFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, requestWithCert("GET", "/", nil, cert))

	if got == nil {
		t.Fatal("expected agent identity in context")
	}
	if got.HostID != "host-42" {
		t.Fatalf("expected HostID=host-42, got %q", got.HostID)
	}
	if got.CertFingerprint != fp {
		t.Fatalf("expected fingerprint=%s, got %s", fp, got.CertFingerprint)
	}
}

func TestAgentIdentityMiddleware_UnknownAgent_FingerprintOnly(t *testing.T) {
	cert, _ := selfSignedCert(t, "new-agent")
	fp := fingerprint(cert)

	store := NewInMemoryAgentStore() // empty — agent not registered

	mw := AgentIdentityMiddleware(store)
	var got *AgentIdentity
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = AgentFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, requestWithCert("GET", "/", nil, cert))

	if got == nil {
		t.Fatal("expected agent identity in context")
	}
	if got.HostID != "" {
		t.Fatalf("expected empty HostID for unknown agent, got %q", got.HostID)
	}
	if got.CertFingerprint != fp {
		t.Fatalf("expected fingerprint=%s, got %s", fp, got.CertFingerprint)
	}
}

// ---------------------------------------------------------------------------
// handler tests
// ---------------------------------------------------------------------------

func TestRegister_StoresAgent(t *testing.T) {
	agentCert, _ := selfSignedCert(t, "push-target")
	fp := fingerprint(agentCert)

	store := NewInMemoryAgentStore()
	h := &Handlers{AgentStore: store}

	body, _ := json.Marshal(map[string]string{"host_id": "host-99", "version": "1.0.0"})
	req := requestWithCert("POST", "/agent/register", body, agentCert)
	req.Header.Set("Content-Type", "application/json")

	// Inject agent identity via middleware.
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{CertFingerprint: fp})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Register(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify agent is now in store.
	agent, ok := store.LookupAgentByFingerprint(fp)
	if !ok {
		t.Fatal("agent not found in store after registration")
	}
	if agent.HostID != "host-99" {
		t.Fatalf("expected HostID=host-99, got %q", agent.HostID)
	}
}

func TestHeartbeat_UnregisteredAgent_401(t *testing.T) {
	h := &Handlers{AgentStore: NewInMemoryAgentStore()}

	cert, _ := selfSignedCert(t, "unregistered")
	req := requestWithCert("POST", "/agent/heartbeat", nil, cert)
	// Identity with empty HostID — unregistered.
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		CertFingerprint: fingerprint(cert),
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Heartbeat(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHeartbeat_RegisteredAgent_204(t *testing.T) {
	store := NewInMemoryAgentStore()
	cert, _ := selfSignedCert(t, "registered-host")
	fp := fingerprint(cert)
	store.RegisterAgent("host-1", fp, "1.0.0")

	h := &Handlers{AgentStore: store}

	req := requestWithCert("POST", "/agent/heartbeat", nil, cert)
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-1",
		CertFingerprint: fp,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Heartbeat(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestHeartbeat_RelaysToPortal(t *testing.T) {
	store := NewInMemoryAgentStore()
	cert, _ := selfSignedCert(t, "relay-host")
	fp := fingerprint(cert)
	store.RegisterAgent("host-relay", fp, "1.0.0")

	relay := &stubRelay{}
	h := &Handlers{AgentStore: store, PortalRelay: relay}

	req := requestWithCert("POST", "/agent/heartbeat", nil, cert)
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-relay",
		CertFingerprint: fp,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Heartbeat(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	// The relay runs in a goroutine — wait briefly for it to execute.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relay.callCount() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if relay.callCount() != 1 {
		t.Fatalf("expected 1 relay call, got %d", relay.callCount())
	}
	relay.mu.Lock()
	if relay.calls[0] != "host-relay" {
		t.Fatalf("expected relay for host-relay, got %s", relay.calls[0])
	}
	relay.mu.Unlock()
}

func TestPollScan_NoPending_204(t *testing.T) {
	disp := &stubDispatcher{pendingCmd: nil}
	h := &Handlers{
		AgentStore:     NewInMemoryAgentStore(),
		ScanDispatcher: disp,
	}

	cert, _ := selfSignedCert(t, "host-a")
	req := requestWithCert("GET", "/agent/scan", nil, cert)
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-a",
		CertFingerprint: fingerprint(cert),
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PollScan(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestPollScan_HasCommand_200(t *testing.T) {
	disp := &stubDispatcher{
		pendingCmd: &ScanCommand{ScanProfile: "comprehensive", Paths: []string{"/opt"}},
	}
	h := &Handlers{
		AgentStore:     NewInMemoryAgentStore(),
		ScanDispatcher: disp,
	}

	cert, _ := selfSignedCert(t, "host-b")
	req := requestWithCert("GET", "/agent/scan", nil, cert)
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-b",
		CertFingerprint: fingerprint(cert),
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PollScan(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var cmd ScanCommand
	if err := json.NewDecoder(w.Body).Decode(&cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.ScanProfile != "comprehensive" {
		t.Fatalf("expected profile=comprehensive, got %q", cmd.ScanProfile)
	}
}

func TestSubmit_RelaysToDispatcher_204(t *testing.T) {
	disp := &stubDispatcher{}
	h := &Handlers{
		AgentStore:     NewInMemoryAgentStore(),
		ScanDispatcher: disp,
	}

	cert, _ := selfSignedCert(t, "host-c")
	payload := []byte(`{"findings":[]}`)
	req := requestWithCert("POST", "/agent/submit", payload, cert)
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-c",
		CertFingerprint: fingerprint(cert),
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Submit(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if !disp.submitCalled {
		t.Fatal("expected SubmitFindings to be called")
	}
	if disp.submittedHostID != "host-c" {
		t.Fatalf("expected hostID=host-c, got %q", disp.submittedHostID)
	}
}

func TestSubmit_OversizedBody_413(t *testing.T) {
	h := &Handlers{
		AgentStore:     NewInMemoryAgentStore(),
		ScanDispatcher: &stubDispatcher{},
	}

	cert, _ := selfSignedCert(t, "host-d")
	// Create a body larger than 32 MB.
	bigBody := strings.Repeat("x", 33<<20)
	req := requestWithCert("POST", "/agent/submit", []byte(bigBody), cert)
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), agentCtxKey{}, &AgentIdentity{
		HostID:          "host-d",
		CertFingerprint: fingerprint(cert),
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Submit(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// verifyAgentCert tests
// ---------------------------------------------------------------------------

func TestVerifyAgentCert_ValidSignature(t *testing.T) {
	// Generate "engine" key and self-signed cert.
	engineCert, enginePriv := selfSignedCert(t, "engine")

	// Generate "agent" cert signed by engine.
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "agent-host"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTmpl, engineCert, agentPub, enginePriv)
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := x509.ParseCertificate(agentDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyAgentCert(agentCert, engineCert); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}
}

func TestVerifyAgentCert_WrongIssuer(t *testing.T) {
	engineCert, _ := selfSignedCert(t, "engine")
	otherCert, otherPriv := selfSignedCert(t, "other-engine")

	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "rogue-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	// Signed by "other" engine, not the one we're checking against.
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTmpl, otherCert, agentPub, otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := x509.ParseCertificate(agentDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyAgentCert(agentCert, engineCert); err == nil {
		t.Fatal("expected verification to fail for wrong issuer")
	}
}

// TestVerifyAgentCert_NonCAParent_MintedCert verifies that a cert minted
// by MintAgentCert (production path) passes verifyAgentCert even though
// the engine cert lacks IsCA/BasicConstraints. This is the I2 regression
// test — Go's x509.Certificate.Verify would reject this but our raw
// Ed25519 signature check works.
func TestVerifyAgentCert_NonCAParent_MintedCert(t *testing.T) {
	// Generate a non-CA engine cert (matches production — no IsCA flag).
	engineCert, enginePriv := selfSignedCert(t, "engine-no-ca")
	if engineCert.IsCA {
		t.Fatal("selfSignedCert should not set IsCA")
	}

	// Mint an agent cert using the production MintAgentCert function.
	ac, err := agentpush.MintAgentCert(engineCert, enginePriv, "test-host")
	if err != nil {
		t.Fatalf("MintAgentCert: %v", err)
	}
	agentBlock, _ := pem.Decode(ac.CertPEM)
	if agentBlock == nil {
		t.Fatal("failed to PEM-decode agent cert")
	}
	leaf, err := x509.ParseCertificate(agentBlock.Bytes)
	if err != nil {
		t.Fatalf("parse agent cert: %v", err)
	}

	// Verify using the raw Ed25519 signature check (NOT x509.Verify
	// which would fail because the issuer is not a CA).
	if err := verifyAgentCert(leaf, engineCert); err != nil {
		t.Fatalf("verifyAgentCert failed with non-CA parent: %v", err)
	}

	// Confirm that standard x509.Verify WOULD fail (proving the custom
	// check is necessary).
	pool := x509.NewCertPool()
	pool.AddCert(engineCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("expected x509.Verify to fail for non-CA issuer (it passed — the custom check may be unnecessary)")
	}
}

// TestVerifyAgentCert_WrongKey_Fails verifies that a cert signed by
// engine A is rejected when verified against engine B.
func TestVerifyAgentCert_WrongKey_Fails(t *testing.T) {
	engineA, engineAPriv := selfSignedCert(t, "engine-A")
	engineB, _ := selfSignedCert(t, "engine-B")

	// Mint a cert with engine A's key.
	ac, err := agentpush.MintAgentCert(engineA, engineAPriv, "rogue-host")
	if err != nil {
		t.Fatalf("MintAgentCert: %v", err)
	}
	agentBlock, _ := pem.Decode(ac.CertPEM)
	leaf, _ := x509.ParseCertificate(agentBlock.Bytes)

	// Verify against engine B — should fail.
	if err := verifyAgentCert(leaf, engineB); err == nil {
		t.Fatal("expected verification to fail for wrong engine key")
	}
}
