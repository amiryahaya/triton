package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mtlsFakeStore implements just GetEngineByFingerprint for middleware tests.
type mtlsFakeStore struct {
	byFP map[string]Engine
}

func (s *mtlsFakeStore) GetEngineByFingerprint(_ context.Context, fp string) (Engine, error) {
	e, ok := s.byFP[fp]
	if !ok {
		return Engine{}, errors.New("not found")
	}
	return e, nil
}

// Unused Store methods to satisfy the interface; panic if accidentally called.
func (s *mtlsFakeStore) UpsertCA(context.Context, uuid.UUID, *CA) error { panic("unused") }
func (s *mtlsFakeStore) GetCA(context.Context, uuid.UUID) (*CA, error)  { panic("unused") }
func (s *mtlsFakeStore) CreateEngine(context.Context, Engine) (Engine, error) {
	panic("unused")
}
func (s *mtlsFakeStore) GetEngine(context.Context, uuid.UUID, uuid.UUID) (Engine, error) {
	panic("unused")
}
func (s *mtlsFakeStore) ListEngines(context.Context, uuid.UUID) ([]Engine, error) {
	panic("unused")
}
func (s *mtlsFakeStore) RecordFirstSeen(context.Context, uuid.UUID, string) (bool, error) {
	panic("unused")
}
func (s *mtlsFakeStore) RecordPoll(context.Context, uuid.UUID) error { panic("unused") }
func (s *mtlsFakeStore) SetStatus(context.Context, uuid.UUID, string) error {
	panic("unused")
}
func (s *mtlsFakeStore) Revoke(context.Context, uuid.UUID, uuid.UUID) error { panic("unused") }
func (s *mtlsFakeStore) MarkStaleOffline(context.Context, time.Time) error   { panic("unused") }
func (s *mtlsFakeStore) ListAllCAs(context.Context) ([][]byte, error)        { panic("unused") }

// makeLeafCert mints a throwaway self-signed cert so we can shove raw
// bytes into tls.ConnectionState.PeerCertificates for the middleware.
func makeLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-engine"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func fingerprintOf(c *x509.Certificate) string {
	fp := sha256.Sum256(c.Raw)
	return hex.EncodeToString(fp[:])
}

func TestMTLSMiddleware_NoTLS_401(t *testing.T) {
	mw := MTLSMiddleware(&mtlsFakeStore{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestMTLSMiddleware_NoPeerCerts_401(t *testing.T) {
	mw := MTLSMiddleware(&mtlsFakeStore{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestMTLSMiddleware_UnknownFingerprint_401(t *testing.T) {
	cert := makeLeafCert(t)
	mw := MTLSMiddleware(&mtlsFakeStore{byFP: map[string]Engine{}})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestMTLSMiddleware_RevokedEngine_403(t *testing.T) {
	cert := makeLeafCert(t)
	fp := fingerprintOf(cert)
	store := &mtlsFakeStore{byFP: map[string]Engine{
		fp: {ID: uuid.New(), Status: StatusRevoked},
	}}
	mw := MTLSMiddleware(store)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", rec.Code)
	}
}

func TestMTLSMiddleware_ValidCert_InvokesHandler(t *testing.T) {
	cert := makeLeafCert(t)
	fp := fingerprintOf(cert)
	engineID := uuid.New()
	store := &mtlsFakeStore{byFP: map[string]Engine{
		fp: {ID: engineID, Status: StatusOnline},
	}}
	mw := MTLSMiddleware(store)

	var seenID uuid.UUID
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if eng := EngineFromContext(r.Context()); eng != nil {
			seenID = eng.ID
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	if seenID != engineID {
		t.Fatalf("handler saw engine ID %s want %s", seenID, engineID)
	}
}
