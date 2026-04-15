package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/hostmatch"
)

// InventoryLister is the narrow slice of inventory.Store that the
// credentials handlers need. Declaring it here (rather than importing
// inventory.Store wholesale) keeps this package's dependency surface
// minimal and makes handler tests trivial to fake.
type InventoryLister interface {
	ListHostSummaries(ctx context.Context, orgID uuid.UUID) ([]hostmatch.HostSummary, error)
}

// AuditRecorder mirrors the inventory package's recorder contract.
// Handlers tolerate a nil recorder for tests and embedded deployments.
type AuditRecorder interface {
	Record(ctx context.Context, event, subject string, fields map[string]any)
}

// AdminHandlers implements the /api/v1/manage/credentials/* API. It
// coordinates Store (profiles + tests) with EngineStore (engine
// ownership + pubkey lookup) and InventoryStore (matcher resolution).
type AdminHandlers struct {
	Store          Store
	EngineStore    engine.Store
	InventoryStore InventoryLister
	Audit          AuditRecorder
}

// NewAdminHandlers wires an AdminHandlers.
func NewAdminHandlers(s Store, es engine.Store, is InventoryLister, a AuditRecorder) *AdminHandlers {
	return &AdminHandlers{Store: s, EngineStore: es, InventoryStore: is, Audit: a}
}

func (h *AdminHandlers) audit(ctx context.Context, event, subject string, fields map[string]any) {
	if h.Audit == nil {
		return
	}
	h.Audit.Record(ctx, event, subject, fields)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *AdminHandlers) claims(r *http.Request) (orgID, userID uuid.UUID, ok bool) {
	c := server.ClaimsFromContext(r.Context())
	if c == nil {
		return uuid.Nil, uuid.Nil, false
	}
	var err error
	orgID, err = uuid.Parse(c.Org)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = uuid.Parse(c.Sub)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, userID, true
}

// isUniqueViolation reports whether err is PostgreSQL 23505. Handlers
// use it to distinguish duplicate-name from other INSERT errors.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// --- handlers ---

type createProfilePayload struct {
	Name            string    `json:"name"`
	AuthType        AuthType  `json:"auth_type"`
	EngineID        uuid.UUID `json:"engine_id"`
	Matcher         Matcher   `json:"matcher"`
	EncryptedSecret string    `json:"encrypted_secret"`
}

// CreateProfile inserts a new credentials profile and enqueues the
// initial push delivery. The engine must have registered its X25519
// pubkey first (409 otherwise) — otherwise the operator browser had
// nothing to seal against and the delivery would be garbage.
func (h *AdminHandlers) CreateProfile(w http.ResponseWriter, r *http.Request) {
	var body createProfilePayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" || body.AuthType == "" || body.EngineID == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "name, auth_type, engine_id required")
		return
	}
	switch body.AuthType {
	case AuthSSHPassword, AuthSSHKey, AuthWinRMPassword, AuthBootstrapAdmin:
	default:
		writeErr(w, http.StatusBadRequest, "invalid auth_type")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(body.EncryptedSecret)
	// SealedBoxOverhead = 32 (ephemeral X25519 pubkey) + 12
	// (ChaCha20-Poly1305 nonce) + 16 (Poly1305 tag) = 60. Any valid
	// sealed-box ciphertext must be at least this long. The guard
	// rejects anything shorter, since it cannot possibly be valid
	// (and we expect at least one plaintext byte on top).
	if err != nil || len(ct) < 60 {
		writeErr(w, http.StatusBadRequest, "invalid encrypted_secret")
		return
	}

	orgID, userID, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}

	// The engine must belong to the caller's org AND must have
	// registered its encryption pubkey. We check both before calling
	// CreateProfileWithDelivery so we never insert a profile paired
	// with an unreachable engine.
	if _, err := h.EngineStore.GetEngine(r.Context(), orgID, body.EngineID); err != nil {
		writeErr(w, http.StatusNotFound, "engine not found in org")
		return
	}
	pk, err := h.EngineStore.GetEncryptionPubkey(r.Context(), body.EngineID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load engine pubkey: "+err.Error())
		return
	}
	if len(pk) == 0 {
		writeErr(w, http.StatusConflict, "engine encryption key not yet registered; wait for engine to come online")
		return
	}

	profile := Profile{
		ID:        uuid.Must(uuid.NewV7()),
		OrgID:     orgID,
		EngineID:  body.EngineID,
		Name:      body.Name,
		AuthType:  body.AuthType,
		Matcher:   body.Matcher,
		SecretRef: uuid.Must(uuid.NewV7()),
		CreatedBy: userID,
	}
	profile, err = h.Store.CreateProfileWithDelivery(r.Context(), profile, ct)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "profile name already exists in org")
			return
		}
		writeErr(w, http.StatusInternalServerError, "create profile: "+err.Error())
		return
	}
	h.audit(r.Context(), "credentials.profile.create", profile.ID.String(),
		map[string]any{
			"name":      profile.Name,
			"auth_type": string(profile.AuthType),
			"engine_id": profile.EngineID.String(),
		})
	writeJSON(w, http.StatusCreated, profile)
}

// ListProfiles returns all profiles in the caller's org.
func (h *AdminHandlers) ListProfiles(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	profiles, err := h.Store.ListProfiles(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list profiles: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

// GetProfile returns a single profile by id.
func (h *AdminHandlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	p, err := h.Store.GetProfile(r.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			writeErr(w, http.StatusNotFound, "profile not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get profile: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// DeleteProfile removes the profile and queues a delete-kind delivery.
// Engineer+ only (gated at the route layer).
func (h *AdminHandlers) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	if err := h.Store.DeleteProfileWithDelivery(r.Context(), orgID, id); err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			writeErr(w, http.StatusNotFound, "profile not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete profile: "+err.Error())
		return
	}
	h.audit(r.Context(), "credentials.profile.delete", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

type startTestPayload struct {
	MaxHosts int `json:"max_hosts"`
}

// StartTest resolves the profile's matcher against current inventory,
// trims to MaxHosts, and enqueues a test job for the engine to claim.
func (h *AdminHandlers) StartTest(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	profileID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile id")
		return
	}

	var body startTestPayload
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.MaxHosts <= 0 {
		body.MaxHosts = 3
	}
	if body.MaxHosts > 50 {
		body.MaxHosts = 50
	}

	profile, err := h.Store.GetProfile(r.Context(), orgID, profileID)
	if err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			writeErr(w, http.StatusNotFound, "profile not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "load profile: "+err.Error())
		return
	}

	hosts, err := h.InventoryStore.ListHostSummaries(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list hosts: "+err.Error())
		return
	}
	matched := ResolveMatcher(profile.Matcher, hosts)
	if len(matched) == 0 {
		writeErr(w, http.StatusBadRequest, "matcher resolved to zero hosts")
		return
	}
	if len(matched) > body.MaxHosts {
		matched = matched[:body.MaxHosts]
	}

	tj := TestJob{
		ID:        uuid.Must(uuid.NewV7()),
		OrgID:     orgID,
		EngineID:  profile.EngineID,
		ProfileID: profileID,
		HostIDs:   matched,
	}
	tj, err = h.Store.CreateTestJob(r.Context(), tj)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create test job: "+err.Error())
		return
	}
	h.audit(r.Context(), "credentials.profile.test", profileID.String(),
		map[string]any{"host_count": len(matched), "test_id": tj.ID.String()})
	writeJSON(w, http.StatusCreated, tj)
}

// GetTestJob returns a test job with its per-host results.
func (h *AdminHandlers) GetTestJob(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid test id")
		return
	}
	job, err := h.Store.GetTestJob(r.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, ErrTestJobNotFound) {
			writeErr(w, http.StatusNotFound, "test job not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get test job: "+err.Error())
		return
	}
	results, err := h.Store.ListTestResults(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list results: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":     job,
		"results": results,
	})
}
