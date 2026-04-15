package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/amiryahaya/triton/pkg/server"
)

// AdminHandlers serves the /api/v1/manage/engines/* admin API. It
// owns the CA bootstrap path (first CreateEngine in an org mints the
// CA on demand) and the inline bundle response.
type AdminHandlers struct {
	Store     Store
	MasterKey []byte
	PortalURL string
}

// NewAdminHandlers wires an AdminHandlers. masterKey must be the
// 32-byte XChaCha20-Poly1305 key used for CA private-key encryption.
func NewAdminHandlers(s Store, masterKey []byte, portalURL string) *AdminHandlers {
	return &AdminHandlers{Store: s, MasterKey: masterKey, PortalURL: portalURL}
}

// --- helpers ---

func (h *AdminHandlers) orgID(r *http.Request) (uuid.UUID, bool) {
	c := server.ClaimsFromContext(r.Context())
	if c == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.Org)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- handlers ---

// CreateEngine bootstraps an engine: ensures the org CA exists, mints
// an Ed25519 keypair, signs a leaf cert, persists the engine row by
// cert fingerprint, then responds with the tar.gz bundle inline. The
// private key is never persisted server-side — if the operator loses
// the bundle, they must re-create the engine.
func (h *AdminHandlers) CreateEngine(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Label = strings.TrimSpace(body.Label)
	if body.Label == "" {
		writeErr(w, http.StatusBadRequest, "label is required")
		return
	}

	orgID, ok := h.orgID(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid org claim")
		return
	}

	// Ensure the org CA exists (bootstrap on first engine).
	ca, err := h.Store.GetCA(r.Context(), orgID)
	if err != nil {
		if !errors.Is(err, ErrCANotFound) {
			writeErr(w, http.StatusInternalServerError, "load CA: "+err.Error())
			return
		}
		ca, err = GenerateCA(h.MasterKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "generate CA: "+err.Error())
			return
		}
		if err := h.Store.UpsertCA(r.Context(), orgID, ca); err != nil {
			writeErr(w, http.StatusInternalServerError, "persist CA: "+err.Error())
			return
		}
	}

	// Generate engine Ed25519 keypair.
	enginePub, enginePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "generate engine key: "+err.Error())
		return
	}

	certPEM, err := ca.SignEngineCert(h.MasterKey, body.Label, enginePub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sign engine cert: "+err.Error())
		return
	}

	// Compute SHA-256 fingerprint of the leaf DER for mTLS lookup.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		writeErr(w, http.StatusInternalServerError, "signed cert is not valid PEM")
		return
	}
	fp := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(fp[:])

	// Marshal engine private key as PKCS#8 PEM.
	keyDER, err := x509.MarshalPKCS8PrivateKey(enginePriv)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal engine key: "+err.Error())
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Build bundle BEFORE persisting the engine row. If bundle build
	// fails, no DB row exists, so the operator can retry freely
	// without tripping the UNIQUE(org_id, label) constraint.
	engineID := uuid.New()
	bundle, err := BuildBundle(BundleInputs{
		EngineID:      engineID,
		OrgID:         orgID,
		Label:         body.Label,
		PortalURL:     h.PortalURL,
		EngineKeyPEM:  keyPEM,
		EngineCertPEM: certPEM,
		CACertPEM:     ca.CACertPEM,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build bundle: "+err.Error())
		return
	}

	// Persist the engine row. If this fails after a successful bundle
	// build, the operator gets no bundle and no DB trace — log the
	// label + fingerprint so ops can correlate.
	created, err := h.Store.CreateEngine(r.Context(), Engine{
		ID:              engineID,
		OrgID:           orgID,
		Label:           body.Label,
		CertFingerprint: fingerprint,
		Status:          StatusEnrolled,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeErr(w, http.StatusConflict, "engine label already exists in this org")
			return
		}
		log.Printf("engine create persist failed: org=%s label=%q fingerprint=%s err=%v",
			orgID, body.Label, fingerprint, err)
		writeErr(w, http.StatusInternalServerError, "create engine: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="engine-%s.tar.gz"`, sanitizeFilename(created.Label)),
	)
	w.Header().Set("X-Triton-Engine-Id", created.ID.String())
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(bundle)
}

// ListEngines returns all engines in the caller's org.
func (h *AdminHandlers) ListEngines(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.orgID(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid org claim")
		return
	}
	engines, err := h.Store.ListEngines(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list engines: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engines)
}

// GetEngine returns a single engine scoped to the caller's org.
func (h *AdminHandlers) GetEngine(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.orgID(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid org claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid engine id")
		return
	}
	eng, err := h.Store.GetEngine(r.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, ErrEngineNotFound) {
			writeErr(w, http.StatusNotFound, "engine not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get engine: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, eng)
}

// GetEngineEncryptionPubkey returns the engine's static X25519 public
// key (base64-encoded) so operator browsers can seal secrets against
// it. 404 if the engine has not yet submitted a pubkey.
func (h *AdminHandlers) GetEngineEncryptionPubkey(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.orgID(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid org claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid engine id")
		return
	}
	if _, err := h.Store.GetEngine(r.Context(), orgID, id); err != nil {
		writeErr(w, http.StatusNotFound, "engine not found")
		return
	}
	pk, err := h.Store.GetEncryptionPubkey(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get encryption pubkey: "+err.Error())
		return
	}
	if len(pk) == 0 {
		writeErr(w, http.StatusNotFound, "encryption pubkey not yet registered")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"pubkey": base64.StdEncoding.EncodeToString(pk),
	})
}

// RevokeEngine flips an engine to revoked status. Owner-only.
func (h *AdminHandlers) RevokeEngine(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.orgID(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid org claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid engine id")
		return
	}
	if err := h.Store.Revoke(r.Context(), orgID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke engine: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sanitizeFilename strips characters that would break a
// Content-Disposition filename. We aren't doing RFC 5987 escaping;
// just keep it boring for the happy path.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "engine"
	}
	return b.String()
}
