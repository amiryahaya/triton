package agents

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// AgentCapGuard is the narrow licence-guard surface the agents Enrol
// handler consults before signing + persisting a new agent bundle.
// Matches the HostCapGuard shape: one-method, LimitCap-only — agents
// use a hard cap, no soft buffer.
//
// A nil Guard on AdminHandlers means "no licence configured" — cap
// check skipped. LimitCap returning -1 for agents/total means the
// same thing.
type AgentCapGuard interface {
	LimitCap(metric, window string) int64
}

// AdminHandlers serves the /api/v1/admin/{enrol/agent,agents} endpoints.
// Constructed against a ca.Store (which owns CA load + signing), an
// agents.Store (which owns manage_agents CRUD), a ManageGatewayURL
// string that's baked into each issued bundle, a PhoneHomeInterval
// cadence for the bundle's config.yaml, and an optional Guard that
// enforces the Batch H licence seat cap.
//
// PhoneHomeInterval defaults to 60 s when the constructor receives
// zero. ManageGatewayURL must be non-empty or Enrol will 500.
type AdminHandlers struct {
	CAStore           ca.Store
	AgentStore        Store
	ManageGatewayURL  string
	PhoneHomeInterval time.Duration
	Guard             AgentCapGuard
}

// NewAdminHandlers wires the admin handlers with sensible defaults.
// PhoneHomeInterval defaults to 60s when zero — matches the Batch F
// spec. ManageGatewayURL must be non-empty or Enrol will 500. A nil
// Guard disables licence-cap enforcement (used in tests that don't
// exercise Batch H).
func NewAdminHandlers(caStore ca.Store, agentStore Store, gatewayURL string, phoneHome time.Duration, guard AgentCapGuard) *AdminHandlers {
	if phoneHome <= 0 {
		phoneHome = 60 * time.Second
	}
	return &AdminHandlers{
		CAStore:           caStore,
		AgentStore:        agentStore,
		ManageGatewayURL:  gatewayURL,
		PhoneHomeInterval: phoneHome,
		Guard:             guard,
	}
}

// enrolRequest is the body shape of POST /api/v1/admin/enrol/agent.
type enrolRequest struct {
	Name   string     `json:"name"`
	ZoneID *uuid.UUID `json:"zone_id,omitempty"`
}

// Enrol is the admin-triggered agent onboarding flow. It:
//  1. Loads the Manage CA (bootstrapped at server start).
//  2. Mints a fresh agent UUID + leaf cert + key.
//  3. Inserts a manage_agents row with status='pending'.
//  4. Builds + returns the bundle tar.gz.
//
// Licence-cap enforcement (Batch H): the handler consults Guard before
// signing the bundle so a rejected enrol never mints a cert that then
// sits unused. Guard is nil in tests and in production deployments
// without a licence.
func (h *AdminHandlers) Enrol(w http.ResponseWriter, r *http.Request) {
	if h.ManageGatewayURL == "" {
		internalErr(w, r, errors.New("ManageGatewayURL is empty"), "enrol agent")
		return
	}

	var body enrolRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	// Licence agent cap. Check BEFORE minting a cert so a rejected
	// enrol never leaves a dangling signed key around. Reading from
	// AgentStore.Count races with concurrent Enrols but a single-row
	// overshoot is tolerable — the usage pusher surfaces the overshoot
	// on the next tick.
	if h.Guard != nil {
		if cap := h.Guard.LimitCap("agents", "total"); cap >= 0 {
			c, err := h.AgentStore.Count(r.Context())
			if err != nil {
				internalErr(w, r, err, "count agents for cap")
				return
			}
			if c+1 > cap {
				writeErr(w, http.StatusForbidden, "licence agent cap exceeded")
				return
			}
		}
	}

	caBundle, err := h.CAStore.Load(r.Context())
	if errors.Is(err, ca.ErrNotFound) {
		// The Server bootstraps the CA on Run(); if we hit this path
		// in a live process it means bootstrap failed. Surface a
		// generic 503 so the admin UI can retry.
		writeErr(w, http.StatusServiceUnavailable, "manage CA not bootstrapped; retry shortly")
		return
	}
	if err != nil {
		internalErr(w, r, err, "load CA for enrol")
		return
	}

	agentID := uuid.Must(uuid.NewV7())
	leafPEM, keyPEM, err := caBundle.SignAgentCert(agentID)
	if err != nil {
		internalErr(w, r, err, "sign agent cert")
		return
	}

	// Parse the leaf to extract serial + NotAfter for the agent row.
	serial, expiresAt, err := parseLeafMetadata(leafPEM)
	if err != nil {
		internalErr(w, r, err, "parse signed leaf")
		return
	}

	agent := Agent{
		ID:            agentID,
		Name:          body.Name,
		ZoneID:        body.ZoneID,
		CertSerial:    serial,
		CertExpiresAt: expiresAt,
		Status:        StatusPending,
	}
	if _, err := h.AgentStore.Create(r.Context(), agent); err != nil {
		internalErr(w, r, err, "create agent row")
		return
	}

	bundle, err := ca.BuildBundle(ca.BundleInputs{
		AgentID:           agentID,
		ManageGatewayURL:  h.ManageGatewayURL,
		AgentKeyPEM:       keyPEM,
		AgentCertPEM:      leafPEM,
		ManageCACertPEM:   caBundle.CACertPEM,
		PhoneHomeInterval: h.PhoneHomeInterval,
	})
	if err != nil {
		internalErr(w, r, err, "build agent bundle")
		return
	}

	w.Header().Set("Content-Type", "application/x-gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="agent-%s.tar.gz"`, agentID.String()))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(bundle); err != nil {
		// Response already flushed headers — nothing to do but log.
		log.Printf("manageserver/agents: enrol: write bundle: %v", err)
	}
}

// List returns every agent.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.AgentStore.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list agents")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Get returns a single agent by id.
func (h *AdminHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	a, err := h.AgentStore.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get agent")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// Revoke flips status→revoked and writes the revocation row.
// The revocation is atomic in the sense that both writes need to
// succeed for the revoke to be effective. If the CA Revoke succeeds
// but the agent Revoke fails, the cert still can't be used — the
// revocation list is authoritative.
func (h *AdminHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid agent id")
		return
	}

	a, err := h.AgentStore.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get agent for revoke")
		return
	}

	// Write the revocation row first — if this succeeds but the agent
	// row update fails, the cert is still refused by gateway mTLS, so
	// we fail closed.
	if err := h.CAStore.Revoke(r.Context(), a.CertSerial, a.ID, "admin revoke"); err != nil {
		internalErr(w, r, err, "revoke cert")
		return
	}
	if err := h.AgentStore.Revoke(r.Context(), a.ID); err != nil {
		// CA revocation already in place; log and surface a 500 so
		// the admin knows the agent row is stale.
		internalErr(w, r, err, "mark agent revoked (cert already revoked)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseLeafMetadata extracts the serial (as base-16 string) + NotAfter
// from a leaf cert PEM. Serial formatting matches what
// x509.Certificate.SerialNumber.Text(16) produces, which is what the
// mtlsCNAuth middleware compares against on the gateway.
func parseLeafMetadata(leafPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(bytes.TrimSpace(leafPEM))
	if block == nil {
		return "", time.Time{}, errors.New("invalid leaf PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse leaf: %w", err)
	}
	return c.SerialNumber.Text(16), c.NotAfter, nil
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr writes a JSON error body {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// internalErr logs the underlying error + writes a generic 500 to the
// client, matching the pattern used elsewhere in manageserver. Caller
// supplies a short fixed verb-phrase for the log line. Request method
// + path are included so grep-ing server logs for "update agent row"
// lands you on the HTTP request without correlation tooling.
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/agents: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
