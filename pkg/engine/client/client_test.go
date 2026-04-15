package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	srvdisc "github.com/amiryahaya/triton/pkg/server/discovery"
	"github.com/amiryahaya/triton/pkg/server/engine"
)

// newTestKeypair returns PEM-encoded (cert, key) for a throwaway
// self-signed leaf suitable for tls.X509KeyPair parsing.
func newTestKeypair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-engine"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

// writeBundle builds a real bundle via engine.BuildBundle and writes
// it to a temp file. Returns the path, the engine ID, and the portal
// URL that was baked into the manifest.
func writeBundle(t *testing.T, portalURL string) (path string, engineID uuid.UUID) {
	t.Helper()
	certPEM, keyPEM := newTestKeypair(t)
	engineID = uuid.New()
	gz, err := engine.BuildBundle(engine.BundleInputs{
		EngineID:      engineID,
		OrgID:         uuid.New(),
		Label:         "test",
		PortalURL:     portalURL,
		EngineKeyPEM:  keyPEM,
		EngineCertPEM: certPEM,
		CACertPEM:     certPEM, // reuse as stand-in CA PEM
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	path = filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, gz, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return
}

func TestNew_ParsesBundle(t *testing.T) {
	const portal = "https://portal.example.com:8443"
	path, engineID := writeBundle(t, portal)

	c, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.PortalURL != portal {
		t.Errorf("PortalURL = %q, want %q", c.PortalURL, portal)
	}
	if c.EngineID != engineID.String() {
		t.Errorf("EngineID = %q, want %q", c.EngineID, engineID.String())
	}
	if c.HTTP == nil {
		t.Fatalf("HTTP client nil")
	}
}

func TestNew_BadBundle_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.tar.gz")
	if err := os.WriteFile(path, []byte("not a tarball"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(path); err == nil {
		t.Fatalf("expected error for corrupt bundle")
	}
}

func TestNew_MissingFile_ReturnsError(t *testing.T) {
	if _, err := New("/no/such/path/bundle.tar.gz"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestEnroll_PostsToCorrectEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"engine_id":"x","status":"online"}`)
	}))
	defer ts.Close()

	path, _ := writeBundle(t, ts.URL)
	c, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/engine/enroll" {
		t.Errorf("path = %q, want /api/v1/engine/enroll", gotPath)
	}
}

func TestEnroll_BadStatus_ReturnsError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "revoked")
	}))
	defer ts.Close()

	path, _ := writeBundle(t, ts.URL)
	c, _ := New(path)
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatalf("expected error on 403")
	}
}

func TestHeartbeat_204(t *testing.T) {
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	path, _ := writeBundle(t, ts.URL)
	c, _ := New(path)
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if gotPath != "/api/v1/engine/heartbeat" {
		t.Errorf("path = %q, want /api/v1/engine/heartbeat", gotPath)
	}
}

// newDirectClient builds a *Client that bypasses bundle parsing and
// points directly at a test TLS server. Reuses the test server's
// self-signed cert as the client's trust anchor via InsecureSkipVerify
// (same pattern the real Client uses in MVP).
func newDirectClient(ts *httptest.Server) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &Client{
		PortalURL: ts.URL,
		EngineID:  "test-engine",
		HTTP: &http.Client{
			Timeout:   requestTimeout,
			Transport: tr,
		},
	}
}

func TestPollDiscovery_Returns200Job(t *testing.T) {
	jobID := uuid.New()
	orgID := uuid.New()
	engineID := uuid.New()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/engine/discoveries/poll" {
			t.Errorf("path = %q", r.URL.Path)
		}
		job := srvdisc.Job{
			ID:       jobID,
			OrgID:    orgID,
			EngineID: engineID,
			CIDRs:    []string{"10.0.0.0/24"},
			Ports:    []int{22, 443},
			Status:   srvdisc.StatusClaimed,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	got, err := c.PollDiscovery(context.Background())
	if err != nil {
		t.Fatalf("PollDiscovery: %v", err)
	}
	if got == nil {
		t.Fatalf("expected job, got nil")
		return
	}
	if got.ID != jobID {
		t.Errorf("ID = %s, want %s", got.ID, jobID)
	}
	if len(got.CIDRs) != 1 || got.CIDRs[0] != "10.0.0.0/24" {
		t.Errorf("CIDRs = %v", got.CIDRs)
	}
	if len(got.Ports) != 2 {
		t.Errorf("Ports = %v", got.Ports)
	}
}

func TestPollDiscovery_Returns204Nil(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	got, err := c.PollDiscovery(context.Background())
	if err != nil {
		t.Fatalf("PollDiscovery: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestSubmitDiscovery_PostsExpectedBody(t *testing.T) {
	jobID := uuid.New()
	var gotBody submitPayload
	var gotPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	candidates := []srvdisc.Candidate{
		{Address: net.ParseIP("10.0.0.5"), Hostname: "host-5", OpenPorts: []int{22}},
		{Address: net.ParseIP("10.0.0.6"), OpenPorts: []int{443, 8443}},
	}
	if err := c.SubmitDiscovery(context.Background(), jobID, candidates, ""); err != nil {
		t.Fatalf("SubmitDiscovery: %v", err)
	}

	wantPath := "/api/v1/engine/discoveries/" + jobID.String() + "/submit"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody.Error != "" {
		t.Errorf("Error = %q, want empty", gotBody.Error)
	}
	if len(gotBody.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(gotBody.Candidates))
	}
	if gotBody.Candidates[0].Address != "10.0.0.5" || gotBody.Candidates[0].Hostname != "host-5" {
		t.Errorf("candidates[0] = %+v", gotBody.Candidates[0])
	}
	if len(gotBody.Candidates[1].OpenPorts) != 2 {
		t.Errorf("candidates[1].OpenPorts = %v", gotBody.Candidates[1].OpenPorts)
	}
}

func TestSubmitDiscovery_WithError(t *testing.T) {
	var gotBody submitPayload
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	if err := c.SubmitDiscovery(context.Background(), uuid.New(), nil, "scan exploded"); err != nil {
		t.Fatalf("SubmitDiscovery: %v", err)
	}
	if gotBody.Error != "scan exploded" {
		t.Errorf("Error = %q", gotBody.Error)
	}
}

func TestHeartbeat_Non204_ReturnsError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	path, _ := writeBundle(t, ts.URL)
	c, _ := New(path)
	if err := c.Heartbeat(context.Background()); err == nil {
		t.Fatalf("expected error on 500")
	}
}
