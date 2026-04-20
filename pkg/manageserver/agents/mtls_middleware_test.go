package agents_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// fakeCAStore is a test double for ca.Store. Only IsRevoked is hit by
// the middleware — the rest of the interface is stubbed out so the
// double still satisfies ca.Store at compile time.
type fakeCAStore struct {
	revokedSerials map[string]struct{}
	err            error
}

func (f *fakeCAStore) Bootstrap(ctx context.Context, instanceID string) (*ca.CA, error) {
	return nil, errors.New("not implemented in test double")
}
func (f *fakeCAStore) Load(ctx context.Context) (*ca.CA, error) {
	return nil, errors.New("not implemented in test double")
}
func (f *fakeCAStore) IsRevoked(ctx context.Context, serial string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	_, yes := f.revokedSerials[serial]
	return yes, nil
}
func (f *fakeCAStore) Revoke(ctx context.Context, serial string, agentID uuid.UUID, reason string) error {
	return errors.New("not implemented")
}
func (f *fakeCAStore) RefreshRevocationCache(ctx context.Context) error {
	return errors.New("not implemented")
}
func (f *fakeCAStore) IssueServerCert(ctx context.Context, hostname string) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("not implemented")
}

// makeRequestWithCert forges an http.Request with a synthetic TLS
// connection state that carries a single peer certificate (the leaf).
// No real handshake — we rely on the middleware only reading
// r.TLS.PeerCertificates.
func makeRequestWithCert(t *testing.T, cn string, serialHex string) *http.Request {
	t.Helper()
	serial, ok := new(big.Int).SetString(serialHex, 16)
	require.True(t, ok, "bad serial hex")
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: cn},
		SerialNumber: serial,
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return req
}

func TestMTLSCNAuth_HappyPath(t *testing.T) {
	store := &fakeCAStore{revokedSerials: map[string]struct{}{}}
	var seenCN string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCN = agents.CNFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := agents.MTLSCNAuth("agent:", store)
	handler := mw(next)

	req := makeRequestWithCert(t, "agent:abc", "deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "agent:abc", seenCN, "CN must be stashed in context")
}

func TestMTLSCNAuth_MissingCert(t *testing.T) {
	store := &fakeCAStore{revokedSerials: map[string]struct{}{}}
	mw := agents.MTLSCNAuth("agent:", store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should NOT run on missing cert")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Intentionally no req.TLS.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMTLSCNAuth_WrongPrefix(t *testing.T) {
	store := &fakeCAStore{revokedSerials: map[string]struct{}{}}
	mw := agents.MTLSCNAuth("agent:", store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should NOT run on wrong CN prefix")
	}))

	req := makeRequestWithCert(t, "engine:abc", "deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMTLSCNAuth_RevokedCert(t *testing.T) {
	// Serial is the big.Int.Text(16) form — lowercase hex, no 0x
	// prefix. Match what the middleware computes from the cert.
	serial := "deadbeef"
	store := &fakeCAStore{
		revokedSerials: map[string]struct{}{serial: {}},
	}
	mw := agents.MTLSCNAuth("agent:", store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should NOT run on revoked cert")
	}))

	req := makeRequestWithCert(t, "agent:abc", serial)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMTLSCNAuth_DBError_FailsClosed(t *testing.T) {
	store := &fakeCAStore{err: errors.New("db down")}
	mw := agents.MTLSCNAuth("agent:", store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should NOT run on revocation-check failure")
	}))

	req := makeRequestWithCert(t, "agent:abc", "deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a DB-down IsRevoked must fail closed, not open")
}

func TestCNFromContext_EmptyOnMissingKey(t *testing.T) {
	assert.Equal(t, "", agents.CNFromContext(context.Background()))
}
