package credentials_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/credentials"
)

// stubStore is a test double for credentials.Store.
type stubStore struct {
	items      map[uuid.UUID]credentials.Credential
	hostCounts map[uuid.UUID]int64
}

func newStubStore() *stubStore {
	return &stubStore{
		items:      map[uuid.UUID]credentials.Credential{},
		hostCounts: map[uuid.UUID]int64{},
	}
}

func (s *stubStore) List(_ context.Context, tenantID uuid.UUID) ([]credentials.Credential, error) {
	var out []credentials.Credential
	for _, c := range s.items {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	if out == nil {
		out = []credentials.Credential{}
	}
	return out, nil
}
func (s *stubStore) Get(_ context.Context, id uuid.UUID) (credentials.Credential, error) {
	c, ok := s.items[id]
	if !ok {
		return credentials.Credential{}, credentials.ErrCredentialNotFound
	}
	return c, nil
}
func (s *stubStore) Create(_ context.Context, c credentials.Credential) (credentials.Credential, error) {
	s.items[c.ID] = c
	return c, nil
}
func (s *stubStore) Delete(_ context.Context, id uuid.UUID) error {
	delete(s.items, id)
	return nil
}
func (s *stubStore) Update(_ context.Context, _ uuid.UUID, _ credentials.SecretPayload) error {
	return nil
}
func (s *stubStore) CountHosts(_ context.Context, id uuid.UUID) (int64, error) {
	return s.hostCounts[id], nil
}

// stubVault is a test double for VaultRW.
type stubVault struct {
	written []string
	deleted []string
}

func (v *stubVault) Write(_ context.Context, path string, _ credentials.SecretPayload) error {
	v.written = append(v.written, path)
	return nil
}
func (v *stubVault) Delete(_ context.Context, path string) error {
	v.deleted = append(v.deleted, path)
	return nil
}

func newHandlers(store credentials.Store, vault credentials.VaultRW) *credentials.AdminHandlers {
	return credentials.NewAdminHandlers(store, vault)
}

func jsonBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func TestAdminHandlers_List(t *testing.T) {
	store := newStubStore()
	tenantID := uuid.New()
	store.items[uuid.New()] = credentials.Credential{ID: uuid.New(), TenantID: tenantID, Name: "x", AuthType: credentials.AuthTypeSSHKey}
	h := newHandlers(store, &stubVault{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d want %d", w.Code, http.StatusOK)
	}
}

func TestAdminHandlers_Create_SSHKey(t *testing.T) {
	h := newHandlers(newStubStore(), &stubVault{})
	tenantID := uuid.New()
	body := map[string]any{
		"name": "prod", "auth_type": "ssh-key",
		"username": "ubuntu", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
	}
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusCreated {
		t.Errorf("Create ssh-key: status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestAdminHandlers_Create_MissingPrivateKey(t *testing.T) {
	h := newHandlers(newStubStore(), &stubVault{})
	tenantID := uuid.New()
	body := map[string]any{"name": "x", "auth_type": "ssh-key", "username": "u"}
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing private_key: status %d want 400", w.Code)
	}
}

func TestAdminHandlers_Create_InvalidPEM(t *testing.T) {
	h := newHandlers(newStubStore(), &stubVault{})
	tenantID := uuid.New()
	body := map[string]any{"name": "x", "auth_type": "ssh-key", "username": "u", "private_key": "not-pem"}
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid PEM: status %d want 400", w.Code)
	}
}

func TestAdminHandlers_Delete_InUse(t *testing.T) {
	store := newStubStore()
	tenantID := uuid.New()
	id := uuid.New()
	store.items[id] = credentials.Credential{ID: id, TenantID: tenantID}
	store.hostCounts[id] = 2
	h := newHandlers(store, &stubVault{})
	r := httptest.NewRequest(http.MethodDelete, "/"+id.String(), nil)
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	r = credentials.WithURLParam(r, "id", id.String())
	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("delete in-use: status %d want 409", w.Code)
	}
}

func TestAdminHandlers_Delete_WrongTenant(t *testing.T) {
	store := newStubStore()
	ownerTenantID := uuid.New()
	attackerTenantID := uuid.New()
	id := uuid.New()
	store.items[id] = credentials.Credential{ID: id, TenantID: ownerTenantID}
	h := newHandlers(store, &stubVault{})
	r := httptest.NewRequest(http.MethodDelete, "/"+id.String(), nil)
	r = r.WithContext(credentials.WithTenantID(r.Context(), attackerTenantID))
	r = credentials.WithURLParam(r, "id", id.String())
	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("wrong tenant: status %d want 404", w.Code)
	}
}

func TestAdminHandlers_Create_VaultNil_Returns503(t *testing.T) {
	h := credentials.NewAdminHandlers(newStubStore(), nil)
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{}))
	r = r.WithContext(credentials.WithTenantID(r.Context(), uuid.New()))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil vault: status %d want 503", w.Code)
	}
}

func TestAdminHandlers_Create_CertificateAsPrivateKey(t *testing.T) {
	h := newHandlers(newStubStore(), &stubVault{})
	tenantID := uuid.New()
	body := map[string]any{
		"name": "x", "auth_type": "ssh-key", "username": "u",
		"private_key": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----",
	}
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
	r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("certificate as private_key: status %d want 400, body: %s", w.Code, w.Body.String())
	}
}
