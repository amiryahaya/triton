package agentgw

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// AgentStore manages the in-memory registry of connected agents on the
// engine side. Registration callbacks to the portal happen asynchronously
// via the push worker — this store is the fast-path for heartbeat/scan.
type AgentStore interface {
	AgentLookup
	RegisterAgent(hostID, fingerprint, version string)
	RecordHeartbeat(fingerprint string)
}

// InMemoryAgentStore tracks agents locally on the engine.
type InMemoryAgentStore struct {
	mu     sync.RWMutex
	agents map[string]*AgentIdentity // keyed by cert_fingerprint
}

// NewInMemoryAgentStore creates a new empty agent store.
func NewInMemoryAgentStore() *InMemoryAgentStore {
	return &InMemoryAgentStore{agents: make(map[string]*AgentIdentity)}
}

// LookupAgentByFingerprint returns the agent identity for a given
// certificate fingerprint, or false if unknown.
func (s *InMemoryAgentStore) LookupAgentByFingerprint(fp string) (*AgentIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[fp]
	return a, ok
}

// RegisterAgent stores an agent's identity keyed by certificate fingerprint.
func (s *InMemoryAgentStore) RegisterAgent(hostID, fp, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[fp] = &AgentIdentity{HostID: hostID, CertFingerprint: fp}
}

// RecordHeartbeat records that an agent has checked in. For MVP this is
// a local no-op — the portal tracks last_heartbeat via periodic relay.
func (s *InMemoryAgentStore) RecordHeartbeat(_ string) {}

// ScanDispatcher dispatches on-demand scans to agents and collects results.
type ScanDispatcher interface {
	// GetPendingScan returns a scan command for this host, or nil if idle.
	GetPendingScan(hostID string) *ScanCommand
	// SubmitFindings relays agent findings to the portal.
	SubmitFindings(ctx context.Context, hostID string, scanResult []byte) error
}

// PortalRelay relays agent lifecycle events to the portal. The engine
// acts as a proxy — agents talk to the engine, the engine relays to
// the portal. Nil means no relay (used in tests).
type PortalRelay interface {
	RelayHeartbeat(ctx context.Context, hostID, certFingerprint string) error
}

// ScanCommand describes a scan the agent should execute.
type ScanCommand struct {
	ScanProfile string   `json:"scan_profile"`
	Paths       []string `json:"paths,omitempty"`
}

// Handlers groups the HTTP handler methods for the agent gateway.
type Handlers struct {
	AgentStore     AgentStore
	ScanDispatcher ScanDispatcher
	PortalRelay    PortalRelay
}

// Mount registers agent gateway routes on the router.
func (h *Handlers) Mount(r chi.Router) {
	r.Post("/agent/register", h.Register)
	r.Post("/agent/heartbeat", h.Heartbeat)
	r.Get("/agent/scan", h.PollScan)
	r.Post("/agent/submit", h.Submit)
}

// Register handles POST /agent/register. The agent provides its host_id
// and version; the cert fingerprint comes from the mTLS middleware.
func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	agent := AgentFromContext(r.Context())
	if agent == nil {
		http.Error(w, "no agent identity", http.StatusUnauthorized)
		return
	}
	var body struct {
		HostID  string `json:"host_id"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.HostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}
	h.AgentStore.RegisterAgent(body.HostID, agent.CertFingerprint, body.Version)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

// Heartbeat handles POST /agent/heartbeat. Only registered agents
// (those with a HostID) are accepted. The heartbeat is recorded locally
// and relayed to the portal asynchronously (fire-and-forget) so the
// portal can update last_heartbeat and flip installing→healthy.
func (h *Handlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
	agent := AgentFromContext(r.Context())
	if agent == nil || agent.HostID == "" {
		http.Error(w, "unregistered agent", http.StatusUnauthorized)
		return
	}
	h.AgentStore.RecordHeartbeat(agent.CertFingerprint)

	// Relay heartbeat to portal (fire-and-forget for speed).
	if h.PortalRelay != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := h.PortalRelay.RelayHeartbeat(ctx, agent.HostID, agent.CertFingerprint); err != nil {
				log.Printf("relay heartbeat for %s: %v", agent.HostID, err)
			}
		}()
	}

	w.WriteHeader(http.StatusNoContent)
}

// PollScan handles GET /agent/scan. Returns 204 if no scan is pending,
// or 200 with a ScanCommand JSON body.
func (h *Handlers) PollScan(w http.ResponseWriter, r *http.Request) {
	agent := AgentFromContext(r.Context())
	if agent == nil || agent.HostID == "" {
		http.Error(w, "unregistered agent", http.StatusUnauthorized)
		return
	}
	if h.ScanDispatcher == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cmd := h.ScanDispatcher.GetPendingScan(agent.HostID)
	if cmd == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cmd)
}

// Submit handles POST /agent/submit. The agent posts scan findings as
// a JSON blob (up to 32 MB).
func (h *Handlers) Submit(w http.ResponseWriter, r *http.Request) {
	agent := AgentFromContext(r.Context())
	if agent == nil || agent.HostID == "" {
		http.Error(w, "unregistered agent", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
	if err != nil {
		http.Error(w, "body too large or read error", http.StatusRequestEntityTooLarge)
		return
	}
	if h.ScanDispatcher != nil {
		if err := h.ScanDispatcher.SubmitFindings(r.Context(), agent.HostID, body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
