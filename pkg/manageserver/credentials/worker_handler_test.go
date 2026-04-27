package credentials_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/credentials"
)

type stubReader struct {
	payload credentials.SecretPayload
	err     error
}

func (r *stubReader) Read(_ context.Context, _ string) (credentials.SecretPayload, error) {
	return r.payload, r.err
}

func TestWorkerHandler_GetSecret_OK(t *testing.T) {
	store := newStubStore()
	id := uuid.New()
	store.items[id] = credentials.Credential{
		ID:        id,
		VaultPath: "secret/data/triton/t/c",
	}
	vault := &stubReader{payload: credentials.SecretPayload{Username: "ubuntu", Password: "pw"}}
	h := credentials.NewWorkerHandler(store, vault)

	r := httptest.NewRequest(http.MethodGet, "/"+id.String(), nil)
	r = credentials.WithURLParam(r, "id", id.String())
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestWorkerHandler_GetSecret_NotFound(t *testing.T) {
	h := credentials.NewWorkerHandler(newStubStore(), &stubReader{})
	r := httptest.NewRequest(http.MethodGet, "/"+uuid.New().String(), nil)
	r = credentials.WithURLParam(r, "id", uuid.New().String())
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("not found: status %d want 404", w.Code)
	}
}
