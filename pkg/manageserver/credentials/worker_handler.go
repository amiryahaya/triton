package credentials

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// VaultReader is the narrow vault surface the worker handler needs.
type VaultReader interface {
	Read(ctx context.Context, path string) (SecretPayload, error)
}

// WorkerHandler serves GET /worker/credentials/{id}.
type WorkerHandler struct {
	store Store
	vault VaultReader
}

func NewWorkerHandler(store Store, vault VaultReader) *WorkerHandler {
	return &WorkerHandler{store: store, vault: vault}
}

// GetSecret looks up the credential metadata, fetches the secret from Vault,
// and returns the SecretPayload to the scanner subprocess.
func (h *WorkerHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	cred, err := h.store.Get(r.Context(), id)
	if errors.Is(err, ErrCredentialNotFound) {
		writeErr(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		log.Printf("credentials: worker get: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal server error")
		return
	}
	secret, err := h.vault.Read(r.Context(), cred.VaultPath)
	if err != nil {
		log.Printf("credentials: vault read %s: %v", cred.VaultPath, err)
		writeErr(w, http.StatusBadGateway, "vault unavailable")
		return
	}
	writeJSON(w, http.StatusOK, secret)
}
