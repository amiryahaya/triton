package licenseserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/auth"
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
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > 10000 {
			n = 10000
		}
		filter.Limit = n
	}
	if v := r.URL.Query().Get("after"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "after must be RFC3339 format")
			return
		}
		filter.After = &t
	}
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be RFC3339 format")
			return
		}
		filter.Before = &t
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

// auditActor determines the identity of the request sender.
func auditActor(r *http.Request) string {
	if claims := auth.ClaimsFromContext(r.Context()); claims != nil {
		if claims.Email != "" {
			return fmt.Sprintf("%s (%s)", claims.Sub, claims.Email)
		}
		return claims.Sub
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
		return "admin"
	}
	return "client"
}

// audit writes an audit log entry in the background.
func (s *Server) audit(r *http.Request, event, licenseID, orgID, machineID string, extra map[string]any) {
	details, err := json.Marshal(extra)
	if err != nil {
		log.Printf("audit marshal error: %v", err)
		details = json.RawMessage("{}")
	}
	if details == nil {
		details = json.RawMessage("{}")
	}
	entry := &licensestore.AuditEntry{
		Timestamp: time.Now().UTC(),
		EventType: event,
		LicenseID: licenseID,
		OrgID:     orgID,
		MachineID: machineID,
		Actor:     auditActor(r),
		Details:   details,
		IPAddress: clientIP(r),
	}
	// Use context.WithoutCancel to prevent audit write from failing if the
	// HTTP request context is cancelled (e.g., client disconnect or timeout).
	auditCtx := context.WithoutCancel(r.Context())
	if err := s.store.WriteAudit(auditCtx, entry); err != nil {
		log.Printf("audit write error: %v", err)
	}
}

// clientIP extracts the client IP address without port from the request.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isNotFound checks if an error is a not-found error.
func isNotFound(err error) bool {
	var nf *licensestore.ErrNotFound
	return errors.As(err, &nf)
}
