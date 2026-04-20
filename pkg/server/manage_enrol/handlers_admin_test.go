package manage_enrol

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA is a self-contained CA implementing CAProvider using only stdlib
// crypto. Avoids importing pkg/server/engine (which would close the
// package import cycle) while still exercising real signing + chain
// verification end-to-end.
type testCA struct {
	caCert    *x509.Certificate
	caCertPEM []byte
	caKey     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Triton Test"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		caCert:    caCert,
		caCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		caKey:     priv,
	}
}

func (c *testCA) LoadCACert(_ context.Context) ([]byte, error) {
	if c == nil {
		return nil, ErrCANotBootstrapped
	}
	out := make([]byte, len(c.caCertPEM))
	copy(out, c.caCertPEM)
	return out, nil
}

func (c *testCA) SignLeaf(_ context.Context, cn string, validity time.Duration, pub crypto.PublicKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Triton"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, pub, c.caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// memManageStore is an in-memory Store for handler-level tests.
type memManageStore struct {
	mu       sync.Mutex
	bySerial map[string]ManageInstance
	byID     map[uuid.UUID]ManageInstance
}

func newMemManageStore() *memManageStore {
	return &memManageStore{
		bySerial: map[string]ManageInstance{},
		byID:     map[uuid.UUID]ManageInstance{},
	}
}

func (m *memManageStore) Create(_ context.Context, mi ManageInstance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mi.Status == "" {
		mi.Status = StatusActive
	}
	mi.EnrolledAt = time.Now()
	if _, ok := m.bySerial[mi.CertSerial]; ok {
		return fmt.Errorf("duplicate cert_serial")
	}
	m.bySerial[mi.CertSerial] = mi
	m.byID[mi.ID] = mi
	return nil
}

func (m *memManageStore) GetByCertSerial(_ context.Context, serial string) (ManageInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mi, ok := m.bySerial[serial]
	if !ok {
		return ManageInstance{}, ErrNotFound
	}
	return mi, nil
}

func (m *memManageStore) Revoke(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mi, ok := m.byID[id]; ok {
		mi.Status = StatusRevoked
		m.byID[id] = mi
		m.bySerial[mi.CertSerial] = mi
	}
	return nil
}

func (m *memManageStore) List(_ context.Context) ([]ManageInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ManageInstance, 0, len(m.byID))
	for _, mi := range m.byID {
		out = append(out, mi)
	}
	return out, nil
}

type fakeValidator struct {
	features EnrolFeatures
	tenant   string
	err      error
}

func (f *fakeValidator) Validate(context.Context, string) (EnrolFeatures, string, error) {
	return f.features, f.tenant, f.err
}

// newHandlers builds an EnrolHandlers wired against freshly-minted test
// stores. Returns the handlers, the manage store (for assertions), and the
// test CA (for chain verification).
func newHandlers(t *testing.T, v LicenseValidator) (*EnrolHandlers, *memManageStore, *testCA) {
	t.Helper()
	ca := newTestCA(t)
	mstore := newMemManageStore()
	h := &EnrolHandlers{
		CA:              ca,
		ManageStore:     mstore,
		ReportPublicURL: "https://report.test",
		LicenseClient:   v,
	}
	return h, mstore, ca
}

func newPubKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), priv
}

func postEnrol(h *EnrolHandlers, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/enrol", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Enrol(w, req)
	return w
}

// TestEnrol_HappyPath — a valid licence + valid pub key returns a gzip tar
// bundle containing client.crt, ca.crt, and config.yaml; the client.crt CN
// starts with "manage:" and chains to the test CA; a manage_instances row
// is persisted keyed on the leaf's serial.
func TestEnrol_HappyPath(t *testing.T) {
	h, mstore, ca := newHandlers(t, &fakeValidator{
		features: EnrolFeatures{Manage: true},
		tenant:   "tenant-XYZ",
	})

	pubPEM, _ := newPubKeyPEM(t)
	instanceID := uuid.Must(uuid.NewV7())
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "lic-42",
	    "public_key_pem": %q
	}`, instanceID, pubPEM)

	w := postEnrol(h, body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "application/x-gzip", w.Header().Get("Content-Type"))

	// Extract the bundle.
	gzr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	require.NoError(t, err)
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		files[hdr.Name] = data
	}
	require.Contains(t, files, "client.crt")
	require.Contains(t, files, "ca.crt")
	require.Contains(t, files, "config.yaml")

	// client.crt CN starts with "manage:" and chains to CA.
	leafBlock, _ := pem.Decode(files["client.crt"])
	require.NotNil(t, leafBlock)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(leaf.Subject.CommonName, "manage:"),
		"CN %q must start with manage:", leaf.Subject.CommonName)
	assert.Contains(t, leaf.Subject.CommonName, instanceID.String())

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "leaf must chain to the test CA")

	// ca.crt in the bundle matches the test CA.
	assert.Equal(t, ca.caCertPEM, files["ca.crt"])

	// config.yaml has the expected fields.
	cfg := string(files["config.yaml"])
	assert.Contains(t, cfg, "manage_instance_id: "+instanceID.String())
	assert.Contains(t, cfg, "report_url: https://report.test")
	assert.Contains(t, cfg, "tenant_id: tenant-XYZ")

	// manage_instances row persisted keyed on the leaf serial.
	certSerial := leaf.SerialNumber.Text(16)
	mi, err := mstore.GetByCertSerial(context.Background(), certSerial)
	require.NoError(t, err)
	assert.Equal(t, instanceID, mi.ID)
	assert.Equal(t, "tenant-XYZ", mi.TenantAttribution)
	assert.Equal(t, StatusActive, mi.Status)
}

// TestEnrol_RejectsFeatureManageFalse — features.manage=false → 403 and no
// persistence.
func TestEnrol_RejectsFeatureManageFalse(t *testing.T) {
	h, mstore, _ := newHandlers(t, &fakeValidator{
		features: EnrolFeatures{Manage: false},
	})

	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "lic",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), pubPEM)

	w := postEnrol(h, body)
	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())

	rows, err := mstore.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, rows, "no row should be inserted on 403")
}

// TestEnrol_RejectsBadInstanceID — non-UUID instance ID → 400.
func TestEnrol_RejectsBadInstanceID(t *testing.T) {
	h, _, _ := newHandlers(t, &fakeValidator{features: EnrolFeatures{Manage: true}})
	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{"manage_instance_id":"not-a-uuid","license_key":"x","public_key_pem":%q}`, pubPEM)
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestEnrol_RejectsMissingFields — empty license_key or public_key_pem → 400.
func TestEnrol_RejectsMissingFields(t *testing.T) {
	h, _, _ := newHandlers(t, &fakeValidator{features: EnrolFeatures{Manage: true}})
	body := fmt.Sprintf(`{"manage_instance_id":%q}`, uuid.Must(uuid.NewV7()).String())
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestEnrol_RejectsInvalidPubKey — malformed PEM → 400.
func TestEnrol_RejectsInvalidPubKey(t *testing.T) {
	h, _, _ := newHandlers(t, &fakeValidator{features: EnrolFeatures{Manage: true}})
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "x",
	    "public_key_pem": "garbage"
	}`, uuid.Must(uuid.NewV7()).String())
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, strings.ToLower(resp["error"]), "public_key_pem")
}

// TestEnrol_ReturnsBadGatewayOnValidatorError — licence validator error
// (network / License Server down) surfaces as 502.
func TestEnrol_ReturnsBadGatewayOnValidatorError(t *testing.T) {
	h, _, _ := newHandlers(t, &fakeValidator{err: errors.New("boom")})
	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "x",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), pubPEM)
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

// TestEnrolHandlers_NilCA_Returns500 — handler constructed with a nil CA
// field must return 500 with a descriptive error body rather than panicking
// on a nil-pointer deref inside LoadCACert.
func TestEnrolHandlers_NilCA_Returns500(t *testing.T) {
	h := &EnrolHandlers{
		CA:              nil,
		ManageStore:     newMemManageStore(),
		ReportPublicURL: "https://report.test",
		LicenseClient:   &fakeValidator{features: EnrolFeatures{Manage: true}},
	}
	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "x",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), pubPEM)
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, strings.ToLower(resp["error"]), "ca provider")
}

// TestEnrolHandlers_NilManageStore_Returns500 — handler constructed with a
// nil ManageStore must return 500 before reaching any code that would
// dereference the store (Create).
func TestEnrolHandlers_NilManageStore_Returns500(t *testing.T) {
	ca := newTestCA(t)
	h := &EnrolHandlers{
		CA:              ca,
		ManageStore:     nil,
		ReportPublicURL: "https://report.test",
		LicenseClient:   &fakeValidator{features: EnrolFeatures{Manage: true}},
	}
	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "x",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), pubPEM)
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, strings.ToLower(resp["error"]), "manage store")
}

// TestEnrol_CAProviderNotBootstrapped — LoadCACert returns
// ErrCANotBootstrapped → 409.
func TestEnrol_CAProviderNotBootstrapped(t *testing.T) {
	var nilCA *testCA // LoadCACert returns ErrCANotBootstrapped
	h := &EnrolHandlers{
		CA:              nilCA,
		ManageStore:     newMemManageStore(),
		ReportPublicURL: "https://report.test",
		LicenseClient:   &fakeValidator{features: EnrolFeatures{Manage: true}},
	}
	pubPEM, _ := newPubKeyPEM(t)
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "x",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), pubPEM)
	w := postEnrol(h, body)
	assert.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
}
