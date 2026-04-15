package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

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
