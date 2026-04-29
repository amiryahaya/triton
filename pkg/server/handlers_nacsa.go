package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/nacsa/summary
//
// Returns tenant-level NACSA Arahan 9 readiness stats, top blockers,
// and migration phase summary. Accepts optional manage_server_id and
// hostname query parameters to scope the query to a specific segment.
func (s *Server) handleNacsaSummary(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	scope := store.NacsaScopeFilter{
		ManageServerID: r.URL.Query().Get("manage_server_id"),
		Hostname:       r.URL.Query().Get("hostname"),
	}
	summary, err := s.store.GetNacsaSummary(r.Context(), orgID, scope)
	if err != nil {
		log.Printf("nacsa summary: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// GET /api/v1/nacsa/servers
//
// Returns manage servers for the authenticated tenant with per-server
// readiness % and host count. Sorted by readiness_pct DESC.
func (s *Server) handleNacsaServers(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	rows, err := s.store.ListNacsaServers(r.Context(), orgID)
	if err != nil {
		log.Printf("nacsa servers: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/servers/{serverID}/hosts
//
// Returns hosts under a specific manage server with per-host readiness %
// and last scan timestamp.
func (s *Server) handleNacsaHosts(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	serverID := chi.URLParam(r, "serverID")
	rows, err := s.store.ListNacsaHosts(r.Context(), orgID, serverID)
	if err != nil {
		log.Printf("nacsa hosts: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/hosts/{hostname}/cbom
//
// Returns the crypto asset inventory (CBOM) for a specific hostname,
// grouped by (algorithm, key_size, pqc_status, module). Accepts an
// optional comma-separated status query parameter to filter by PQC
// status (e.g. ?status=UNSAFE,DEPRECATED). Empty = all statuses.
func (s *Server) handleNacsaCBOM(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	hostname := chi.URLParam(r, "hostname")
	statusParam := r.URL.Query().Get("status")
	var statuses []string
	if statusParam != "" {
		statuses = strings.Split(statusParam, ",")
	}
	rows, err := s.store.ListNacsaCBOM(r.Context(), orgID, hostname, statuses)
	if err != nil {
		log.Printf("nacsa cbom: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/hosts/{hostname}/risk
//
// Returns the risk register for a specific hostname. Accepts an optional
// sort query parameter: "score" (default), "impact", or "hostname".
func (s *Server) handleNacsaRisk(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	hostname := chi.URLParam(r, "hostname")
	sortBy := r.URL.Query().Get("sort")
	rows, err := s.store.ListNacsaRisk(r.Context(), orgID, hostname, sortBy)
	if err != nil {
		log.Printf("nacsa risk: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/migration
//
// Returns the full NACSA Arahan 9 migration plan with phases, activities,
// progress %, and budget data for the authenticated tenant.
func (s *Server) handleNacsaMigration(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	resp, err := s.store.GetNacsaMigration(r.Context(), orgID)
	if err != nil {
		log.Printf("nacsa migration: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
