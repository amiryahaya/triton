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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/manage_enrol"
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
func (s *mtlsFakeStore) MarkStaleOffline(context.Context, time.Time) error  { panic("unused") }
func (s *mtlsFakeStore) ListAllCAs(context.Context) ([][]byte, error)       { panic("unused") }
func (s *mtlsFakeStore) SetEncryptionPubkey(context.Context, uuid.UUID, []byte) error {
	panic("unused")
}
func (s *mtlsFakeStore) GetEncryptionPubkey(context.Context, uuid.UUID) ([]byte, error) {
	return nil, nil
}

// fakeManageStore is a tiny in-memory manage_enrol.Store.
type fakeManageStore struct {
	mu       sync.Mutex
	bySerial map[string]manage_enrol.ManageInstance
}

func newFakeManageStore() *fakeManageStore {
	return &fakeManageStore{bySerial: map[string]manage_enrol.ManageInstance{}}
}

func (f *fakeManageStore) Create(_ context.Context, mi manage_enrol.ManageInstance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bySerial[mi.CertSerial] = mi
	return nil
}

func (f *fakeManageStore) GetByCertSerial(_ context.Context, serial string) (manage_enrol.ManageInstance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mi, ok := f.bySerial[serial]
	if !ok {
		return manage_enrol.ManageInstance{}, manage_enrol.ErrNotFound
	}
	return mi, nil
}

func (f *fakeManageStore) Revoke(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for serial, mi := range f.bySerial {
		if mi.ID == id {
			mi.Status = manage_enrol.StatusRevoked
			f.bySerial[serial] = mi
		}
	}
	return nil
}

func (f *fakeManageStore) List(context.Context) ([]manage_enrol.ManageInstance, error) {
	return nil, nil
}

// makeLeafCert mints a throwaway self-signed cert with the given CN and
// serial so we can shove raw bytes into tls.ConnectionState.PeerCertificates
// for the middleware.
func makeLeafCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
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
	mw := MTLSMiddleware(&mtlsFakeStore{}, newFakeManageStore())
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

func TestMTLSMiddleware_NoPeerCerts_401(t *testing.T) {
	mw := MTLSMiddleware(&mtlsFakeStore{}, newFakeManageStore())
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
	cert := makeLeafCert(t, "engine:test", 1)
	mw := MTLSMiddleware(&mtlsFakeStore{byFP: map[string]Engine{}}, newFakeManageStore())
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
	cert := makeLeafCert(t, "engine:rev", 1)
	fp := fingerprintOf(cert)
	store := &mtlsFakeStore{byFP: map[string]Engine{
		fp: {ID: uuid.New(), Status: StatusRevoked},
	}}
	mw := MTLSMiddleware(store, newFakeManageStore())
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
	cert := makeLeafCert(t, "engine:prod", 1)
	fp := fingerprintOf(cert)
	engineID := uuid.New()
	store := &mtlsFakeStore{byFP: map[string]Engine{
		fp: {ID: engineID, Status: StatusOnline},
	}}
	mw := MTLSMiddleware(store, newFakeManageStore())

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

// TestMTLSMiddleware_ManageCN_ResolvesViaStore — a `manage:` CN resolves
// via manage_enrol.Store and stashes *ManageInstance on the context.
func TestMTLSMiddleware_ManageCN_ResolvesViaStore(t *testing.T) {
	// Serial 0x2a = "2a" via big.Int.Text(16).
	cert := makeLeafCert(t, "manage:abc123:5c0d", 0x2a)
	serial := cert.SerialNumber.Text(16)
	manageID := uuid.Must(uuid.NewV7())

	mstore := newFakeManageStore()
	_ = mstore.Create(context.Background(), manage_enrol.ManageInstance{
		ID:                manageID,
		CertSerial:        serial,
		LicenseKeyHash:    "abc123",
		TenantAttribution: "tenant-demo",
		Status:            manage_enrol.StatusActive,
	})

	mw := MTLSMiddleware(&mtlsFakeStore{}, mstore)

	var seenID uuid.UUID
	var seenTenant string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mi := ManageInstanceFromContext(r.Context()); mi != nil {
			seenID = mi.ID
			seenTenant = mi.TenantAttribution
		}
		// Engine context must remain unset on a manage: request.
		if EngineFromContext(r.Context()) != nil {
			t.Errorf("EngineFromContext unexpectedly non-nil for manage: CN")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
	if seenID != manageID {
		t.Fatalf("handler saw manage ID %s want %s", seenID, manageID)
	}
	if seenTenant != "tenant-demo" {
		t.Fatalf("handler saw tenant %q want tenant-demo", seenTenant)
	}
}

// TestMTLSMiddleware_ManageCN_RevokedRejected — revoked status → 403.
func TestMTLSMiddleware_ManageCN_RevokedRejected(t *testing.T) {
	cert := makeLeafCert(t, "manage:rev:xxx", 0xff)
	serial := cert.SerialNumber.Text(16)

	mstore := newFakeManageStore()
	_ = mstore.Create(context.Background(), manage_enrol.ManageInstance{
		ID:         uuid.Must(uuid.NewV7()),
		CertSerial: serial,
		Status:     manage_enrol.StatusRevoked,
	})

	mw := MTLSMiddleware(&mtlsFakeStore{}, mstore)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestMTLSMiddleware_ManageCN_UnknownSerial — serial not in the store → 401.
func TestMTLSMiddleware_ManageCN_UnknownSerial(t *testing.T) {
	cert := makeLeafCert(t, "manage:unknown:yyy", 1234)
	mw := MTLSMiddleware(&mtlsFakeStore{}, newFakeManageStore())
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

// TestMTLSMiddleware_UnknownCN_Rejected — CN without any recognised prefix
// → 401.
func TestMTLSMiddleware_UnknownCN_Rejected(t *testing.T) {
	cert := makeLeafCert(t, "agent:stray", 1)
	mw := MTLSMiddleware(&mtlsFakeStore{}, newFakeManageStore())
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}

// TestMTLSMiddleware_ManageStoreNil_RejectsManageCN — when manageStore is
// nil, any `manage:` CN is rejected with 401 and a clear message.
func TestMTLSMiddleware_ManageStoreNil_RejectsManageCN(t *testing.T) {
	cert := makeLeafCert(t, "manage:any:zzz", 7)
	mw := MTLSMiddleware(&mtlsFakeStore{}, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d want 401", rec.Code)
	}
}
