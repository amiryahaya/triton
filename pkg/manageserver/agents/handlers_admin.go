package agents

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
	"github.com/amiryahaya/triton/pkg/managestore"
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
// cadence for the bundle's config.yaml, and an optional GuardProvider
// that enforces the Batch H licence seat cap.
//
// GuardProvider is consulted per-request so the Server can rotate the
// licence guard under a mutex during /setup/license activation without
// racing the admin handlers. A nil provider (or a provider returning
// nil) disables licence-cap enforcement.
//
// PhoneHomeInterval defaults to 60 s when the constructor receives
// zero. ManageGatewayURL must be non-empty or Enrol will 500.
type AdminHandlers struct {
	CAStore           ca.Store
	AgentStore        Store
	SetupStore        managestore.Store // for licence proxy activation; nil means proxy disabled
	ManageGatewayURL  string
	PhoneHomeInterval time.Duration
	GuardProvider     func() AgentCapGuard
}

// NewAdminHandlers wires the admin handlers with sensible defaults.
// PhoneHomeInterval defaults to 60s when zero — matches the Batch F
// spec. ManageGatewayURL must be non-empty or Enrol will 500. A nil
// GuardProvider (or a provider returning nil) disables licence-cap
// enforcement (used in tests that don't exercise Batch H).
func NewAdminHandlers(caStore ca.Store, agentStore Store, setupStore managestore.Store, gatewayURL string, phoneHome time.Duration, provider func() AgentCapGuard) *AdminHandlers {
	if phoneHome <= 0 {
		phoneHome = 60 * time.Second
	}
	return &AdminHandlers{
		CAStore:           caStore,
		AgentStore:        agentStore,
		SetupStore:        setupStore,
		ManageGatewayURL:  gatewayURL,
		PhoneHomeInterval: phoneHome,
		GuardProvider:     provider,
	}
}

// guard returns the AgentCapGuard for this request, or nil when no
// provider is wired or the provider yields nil. Centralises the
// nil-check so Enrol reads as `if g := h.guard(); g != nil`.
func (h *AdminHandlers) guard() AgentCapGuard {
	if h.GuardProvider == nil {
		return nil
	}
	return h.GuardProvider()
}

// enrolRequest is the body shape of POST /api/v1/admin/enrol/agent.
type enrolRequest struct {
	Name string `json:"name"`
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
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

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
	if g := h.guard(); g != nil {
		if limit := g.LimitCap("agents", "total"); limit >= 0 {
			c, err := h.AgentStore.Count(r.Context())
			if err != nil {
				internalErr(w, r, err, "count agents for cap")
				return
			}
			if c+1 > limit {
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
		CertSerial:    serial,
		CertExpiresAt: expiresAt,
		Status:        StatusPending,
	}
	if _, err := h.AgentStore.Create(r.Context(), agent); err != nil {
		internalErr(w, r, err, "create agent row")
		return
	}

	// Proxy-activate a licence seat on behalf of this agent.
	seatActivated := false
	var enrolLicClient *license.ServerClient
	var enrolLicKey string

	if h.SetupStore != nil {
		st, stErr := h.SetupStore.GetSetup(r.Context())
		if stErr != nil {
			log.Printf("manageserver/agents: enrol: load setup state: %v (skipping licence activation)", stErr)
		} else if st.LicenseActivated {
			enrolLicClient = license.NewServerClient(st.LicenseServerURL)
			enrolLicKey = st.LicenseKey
			if _, actErr := enrolLicClient.ActivateForTenant(
				enrolLicKey,
				agentID.String(),
				license.ActivationTypeAgent,
				agent.Name,
			); actErr != nil {
				if errors.Is(actErr, license.ErrNoSeats) {
					// Seats exhausted — roll back the agent row and reject enrolment.
					if delErr := h.AgentStore.Delete(r.Context(), agentID); delErr != nil {
						log.Printf("manageserver/agents: enrol: rollback agent row after seats-full: %v", delErr)
					}
					writeErr(w, http.StatusPaymentRequired, "no licence seats available for new agent")
					return
				}
				// Transient error (network, timeout) — log and allow enrolment.
				log.Printf("manageserver/agents: enrol: licence activation transient error (continuing): %v", actErr)
			} else {
				seatActivated = true
			}
		}
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
		// Roll back: delete the agent row so the DB stays consistent.
		if delErr := h.AgentStore.Delete(r.Context(), agentID); delErr != nil {
			log.Printf("manageserver/agents: enrol: rollback agent row after bundle error: %v", delErr)
		}
		// Best-effort deactivate the licence seat we just consumed.
		if seatActivated && enrolLicClient != nil {
			if deactErr := enrolLicClient.DeactivateForTenant(enrolLicKey, agentID.String()); deactErr != nil {
				log.Printf("manageserver/agents: enrol: rollback seat after bundle error: %v", deactErr)
			}
		}
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

	// Best-effort licence seat release.
	if h.SetupStore != nil {
		state, stErr := h.SetupStore.GetSetup(r.Context())
		if stErr == nil && state.LicenseActivated {
			licClient := license.NewServerClient(state.LicenseServerURL)
			if deactErr := licClient.DeactivateForTenant(state.LicenseKey, a.ID.String()); deactErr != nil {
				log.Printf("manageserver/agents: revoke: licence deactivation (best-effort): %v", deactErr)
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// DispatchCommand handles POST /admin/agents/{id}/commands. It queues a
// pending scan command for the identified agent. An existing pending
// command is overwritten (last-writer wins). The agent picks the command
// up on its next GET /agents/commands poll.
//
// Body: {"scan_profile":"<profile>","job_id":"<optional>"}
// Returns 202 Accepted on success, 400 on bad JSON or missing profile,
// 404 when the agent does not exist.
func (h *AdminHandlers) DispatchCommand(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	var cmd AgentCommand
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&cmd); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch cmd.ScanProfile {
	case "quick", "standard", "comprehensive":
	default:
		writeErr(w, http.StatusBadRequest, "scan_profile must be quick, standard, or comprehensive")
		return
	}
	if err := h.AgentStore.SetCommand(r.Context(), id, &cmd); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "agent not found")
			return
		}
		internalErr(w, r, err, "dispatch command")
		return
	}
	w.WriteHeader(http.StatusAccepted)
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
