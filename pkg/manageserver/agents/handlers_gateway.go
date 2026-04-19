package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/model"
)

// maxGatewayBody caps the size of a single agent upload. Scan payloads
// are typically <1MB but can spike for comprehensive-profile hosts with
// many findings; 50MB is the same ceiling the plan uses for
// /agents/scans and leaves plenty of headroom without letting a single
// malicious agent OOM the server.
const maxGatewayBody = 50 << 20

// ResultEnqueuer is the narrow slice of scanresults.Store the gateway
// needs. Declared inline so the agents package doesn't pull the whole
// scanresults.Store interface into its public surface.
type ResultEnqueuer interface {
	Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string, sourceID uuid.UUID, scan *model.ScanResult) error
}

// GatewayHandlers serves the :8443 mTLS endpoints an agent dials. All
// handlers assume MTLSCNAuth has already run and stashed the CN in the
// request context — they pull the agent UUID from the CN rather than
// trusting any body-supplied identity.
type GatewayHandlers struct {
	CAStore      ca.Store
	AgentStore   Store
	ResultsStore ResultEnqueuer
}

// NewGatewayHandlers wires the gateway handlers. All three stores are
// required; nil panics at the first call site rather than at HTTP time.
func NewGatewayHandlers(caStore ca.Store, agentStore Store, resultsStore ResultEnqueuer) *GatewayHandlers {
	return &GatewayHandlers{
		CAStore:      caStore,
		AgentStore:   agentStore,
		ResultsStore: resultsStore,
	}
}

// MountGatewayRoutes wires the four agent gateway endpoints onto r.
// Callers must mount this under a subtree that's already wrapped by
// MTLSCNAuth — the handlers call CNFromContext on every request.
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
	r.Post("/agents/phone-home", h.PhoneHome)
	r.Post("/agents/scans", h.IngestScan)
	r.Post("/agents/findings", h.IngestFindings)
	r.Post("/agents/rotate-cert", h.RotateCert)
}

// agentIDFromCN strips the "agent:" prefix and parses the remainder as
// a UUID. Returns uuid.Nil + error if the CN is missing or malformed.
// The caller fails the request with 401 — a mangled CN means mTLS
// auth let something unexpected through.
func agentIDFromCN(ctx context.Context) (uuid.UUID, error) {
	cn := CNFromContext(ctx)
	if cn == "" {
		return uuid.Nil, errors.New("no CN in context")
	}
	if !strings.HasPrefix(cn, "agent:") {
		return uuid.Nil, fmt.Errorf("CN missing agent: prefix: %q", cn)
	}
	id, err := uuid.Parse(strings.TrimPrefix(cn, "agent:"))
	if err != nil {
		return uuid.Nil, fmt.Errorf("CN UUID parse: %w", err)
	}
	return id, nil
}

// PhoneHome is the agent's heartbeat. On each call we flip the agent
// row to status='active' + stamp last_seen_at=NOW. Idempotent: safe
// to call every 60s forever.
func (h *GatewayHandlers) PhoneHome(w http.ResponseWriter, r *http.Request) {
	agentID, err := agentIDFromCN(r.Context())
	if err != nil {
		http.Error(w, "bad cn", http.StatusUnauthorized)
		return
	}
	if err := h.AgentStore.MarkActive(r.Context(), agentID); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "unknown or revoked agent", http.StatusUnauthorized)
			return
		}
		log.Printf("manageserver/agents: phone-home: mark active: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// IngestScan accepts a completed ScanResult from an agent and enqueues
// it onto the outbox for drain → Report. scan_job_id is uuid.Nil
// because agent scans don't originate from a Manage-side scan_job row;
// the queue column is nullable (migration v7) and the Enqueue helper
// maps uuid.Nil to SQL NULL. Response is 202 Accepted — the drain
// handles delivery asynchronously.
func (h *GatewayHandlers) IngestScan(w http.ResponseWriter, r *http.Request) {
	agentID, err := agentIDFromCN(r.Context())
	if err != nil {
		http.Error(w, "bad cn", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxGatewayBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var scan model.ScanResult
	if err := json.Unmarshal(body, &scan); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if err := h.ResultsStore.Enqueue(r.Context(), uuid.Nil, "agent", agentID, &scan); err != nil {
		log.Printf("manageserver/agents: ingest scan: enqueue: %v", err)
		http.Error(w, "enqueue failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// IngestFindings is reserved for the finding-streaming path (agents
// pushing findings independently of scans). Stubbed for Batch F —
// accepts + acks to avoid breaking agents that try the endpoint.
func (h *GatewayHandlers) IngestFindings(w http.ResponseWriter, r *http.Request) {
	if _, err := agentIDFromCN(r.Context()); err != nil {
		http.Error(w, "bad cn", http.StatusUnauthorized)
		return
	}
	// Drain the body up to maxGatewayBody to avoid leaving a TCP half-
	// close that upsets HTTP/1.1 keep-alive.
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxGatewayBody))
	w.WriteHeader(http.StatusAccepted)
}

// RotateCert mints a new leaf for the calling agent and returns the
// fresh cert + key PEM in a JSON body. The agent writes both to disk
// and switches to the new pair for its next call.
//
// TRADEOFF — rotation does NOT revoke the old cert. Both the old and
// new certs remain cryptographically valid until their natural
// 1-year expiry. The mtlsCNAuth middleware only checks (a) CN prefix
// and (b) the revocation list — it does NOT check that the
// presenting serial matches manage_agents.cert_serial. So
// post-rotation, the old cert continues to pass mTLS.
//
// This extends to admin-initiated revocation: DELETE
// /admin/agents/{id} revokes ONLY the CURRENT cert_serial on the
// manage_agents row. Any previously-issued serials (pre-rotation)
// are NOT added to the revocation list and the cert chain keeps
// validating until expiry.
//
// PARTIAL MITIGATION — PhoneHome's MarkActive UPDATE is guarded by
// `status != 'revoked'`, so an agent whose status has been flipped
// to revoked (which admin Revoke does) cannot phone-home even with a
// still-valid OLD cert. This masks the tradeoff on the phone-home
// path specifically, but endpoints that don't read agent-status
// (IngestScan, IngestFindings, RotateCert itself) still accept the
// old cert unless the operator manually revokes the old serial.
//
// To invalidate ALL previously-issued certs for an agent across the
// whole endpoint surface, an operator must either (a) manually
// revoke each old serial, or (b) enrol a new agent under a fresh
// UUID and revoke the original. This is a deliberate tradeoff
// against operational simplicity — the alternative would require a
// per-agent serial history and cascading revocation.
// TestGateway_RotateCert_OldCertStillAccepted pins every observable
// facet above; re-read before changing. See design spec §7.3.
func (h *GatewayHandlers) RotateCert(w http.ResponseWriter, r *http.Request) {
	agentID, err := agentIDFromCN(r.Context())
	if err != nil {
		http.Error(w, "bad cn", http.StatusUnauthorized)
		return
	}

	caBundle, err := h.CAStore.Load(r.Context())
	if err != nil {
		log.Printf("manageserver/agents: rotate-cert: load CA: %v", err)
		http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
		return
	}
	leafPEM, keyPEM, err := caBundle.SignAgentCert(agentID)
	if err != nil {
		log.Printf("manageserver/agents: rotate-cert: sign: %v", err)
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	serial, expiresAt, err := parseLeafMetadata(leafPEM)
	if err != nil {
		log.Printf("manageserver/agents: rotate-cert: parse leaf: %v", err)
		http.Error(w, "parse leaf failed", http.StatusInternalServerError)
		return
	}
	if err := h.AgentStore.UpdateCert(r.Context(), agentID, serial, expiresAt); err != nil {
		log.Printf("manageserver/agents: rotate-cert: update agent row: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"client_cert_pem": string(leafPEM),
		"client_key_pem":  string(keyPEM),
		"expires_at":      expiresAt.UTC().Format(time.RFC3339),
	})
}
