package licenseserver

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// GET /api/v1/admin/audit
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	filter := licensestore.AuditFilter{
		EventType: r.URL.Query().Get("event"),
		LicenseID: r.URL.Query().Get("license"),
		OrgID:     r.URL.Query().Get("org"),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = n
			if filter.Limit > 10000 {
				filter.Limit = 10000
			}
		}
	}
	if v := r.URL.Query().Get("after"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.After = &t
		}
	}
	if v := r.URL.Query().Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Before = &t
		}
	}

	entries, err := s.store.ListAudit(r.Context(), filter)
	if err != nil {
		log.Printf("list audit error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// GET /api/v1/admin/stats
func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.DashboardStats(r.Context())
	if err != nil {
		log.Printf("dashboard stats error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// audit writes an audit log entry in the background.
func (s *Server) audit(r *http.Request, event, licenseID, orgID, machineID string, extra map[string]any) {
	details, _ := json.Marshal(extra)
	if details == nil {
		details = json.RawMessage("{}")
	}
	entry := &licensestore.AuditEntry{
		Timestamp: time.Now().UTC(),
		EventType: event,
		LicenseID: licenseID,
		OrgID:     orgID,
		MachineID: machineID,
		Actor:     "api",
		Details:   details,
		IPAddress: r.RemoteAddr,
	}
	// Use context.WithoutCancel to prevent audit write from failing if the
	// HTTP request context is cancelled (e.g., client disconnect or timeout).
	auditCtx := context.WithoutCancel(r.Context())
	if err := s.store.WriteAudit(auditCtx, entry); err != nil {
		log.Printf("audit write error: %v", err)
	}
}

// isNotFound checks if an error is a not-found error.
func isNotFound(err error) bool {
	var nf *licensestore.ErrNotFound
	return errors.As(err, &nf)
}
