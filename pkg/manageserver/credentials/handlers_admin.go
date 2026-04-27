package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// WithTenantID injects a tenant UUID into the context. Used only by tests.
// Production code path goes through injectInstanceOrg middleware.
func WithTenantID(ctx context.Context, id uuid.UUID) context.Context {
	return orgctx.WithInstanceID(ctx, id)
}

// WithURLParam injects a chi URL param into the request context. Used by tests.
func WithURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// VaultRW is the narrow vault surface AdminHandlers needs.
type VaultRW interface {
	Write(ctx context.Context, path string, payload SecretPayload) error
	Delete(ctx context.Context, path string) error
}

// AdminHandlers serves credential CRUD for the admin API.
type AdminHandlers struct {
	store Store
	vault VaultRW
}

// NewAdminHandlers constructs an AdminHandlers. vault may be nil when Vault is
// not configured — Create will return 503 in that case.
func NewAdminHandlers(store Store, vault VaultRW) *AdminHandlers {
	return &AdminHandlers{store: store, vault: vault}
}

func (h *AdminHandlers) vaultPath(tenantID, credID uuid.UUID) string {
	return fmt.Sprintf("triton/%s/credentials/%s", tenantID, credID)
}

type createReq struct {
	Name       string   `json:"name"`
	AuthType   AuthType `json:"auth_type"`
	Username   string   `json:"username"`
	PrivateKey string   `json:"private_key"`
	Passphrase string   `json:"passphrase"`
	Password   string   `json:"password"`
	UseHTTPS   bool     `json:"use_https"`
}

func (req createReq) validate() error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}
	if req.Username == "" {
		return errors.New("username is required")
	}
	switch req.AuthType {
	case AuthTypeSSHKey:
		if req.PrivateKey == "" {
			return errors.New("private_key is required for ssh-key")
		}
		validKeyHeaders := []string{
			"-----BEGIN OPENSSH PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN EC PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----",
		}
		hasKeyHeader := false
		for _, h := range validKeyHeaders {
			if strings.Contains(req.PrivateKey, h) {
				hasKeyHeader = true
				break
			}
		}
		if !hasKeyHeader {
			return errors.New("private_key must be a PEM-encoded OpenSSH, RSA, EC, or PKCS#8 private key")
		}
	case AuthTypeSSHPassword, AuthTypeWinRM:
		if req.Password == "" {
			return errors.New("password is required")
		}
	default:
		return fmt.Errorf("auth_type must be one of ssh-key|ssh-password|winrm-password")
	}
	return nil
}

func (req createReq) toPayload() SecretPayload {
	p := SecretPayload{Username: req.Username}
	switch req.AuthType {
	case AuthTypeSSHKey:
		p.PrivateKey = req.PrivateKey
		p.Passphrase = req.Passphrase
	case AuthTypeSSHPassword:
		p.Password = req.Password
	case AuthTypeWinRM:
		p.Password = req.Password
		p.UseHTTPS = req.UseHTTPS
	}
	return p
}

// List returns all credentials for the current tenant.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tenant not set")
		return
	}
	list, err := h.store.List(r.Context(), tenantID)
	if err != nil {
		internalErr(w, r, err, "list credentials")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Create validates, writes to Vault, then inserts the DB row.
func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		writeErr(w, http.StatusServiceUnavailable, "vault not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "tenant not set")
		return
	}
	credID := uuid.New()
	vaultPath := h.vaultPath(tenantID, credID)

	if err := h.vault.Write(r.Context(), vaultPath, req.toPayload()); err != nil {
		log.Printf("credentials: vault write: %v", err)
		writeErr(w, http.StatusBadGateway, "vault write failed")
		return
	}

	created, err := h.store.Create(r.Context(), Credential{
		ID:        credID,
		TenantID:  tenantID,
		Name:      strings.TrimSpace(req.Name),
		AuthType:  req.AuthType,
		VaultPath: vaultPath,
	})
	if errors.Is(err, ErrConflict) {
		_ = h.vault.Delete(r.Context(), vaultPath) // best-effort cleanup
		writeErr(w, http.StatusConflict, "credential name already exists")
		return
	}
	if err != nil {
		_ = h.vault.Delete(r.Context(), vaultPath) // best-effort cleanup
		internalErr(w, r, err, "create credential")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// Delete blocks when the credential is in use, then removes Vault secret + DB row.
func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
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
		internalErr(w, r, err, "get credential for delete")
		return
	}
	n, err := h.store.CountHosts(r.Context(), id)
	if err != nil {
		internalErr(w, r, err, "count hosts for credential")
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, fmt.Sprintf("credential in use by %d host(s)", n))
		return
	}
	if h.vault != nil {
		if err := h.vault.Delete(r.Context(), cred.VaultPath); err != nil {
			log.Printf("credentials: vault delete %s: %v (proceeding with DB delete)", cred.VaultPath, err)
		}
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		internalErr(w, r, err, "delete credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("credentials: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
