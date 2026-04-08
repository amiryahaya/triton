package server

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/audit — Phase 5 Sprint 3 B2.
//
// Returns recent audit events for the caller's org, newest first.
// Org-scoped by the tenant context set by UnifiedAuth, so one org
// never sees another org's events. Requires org_admin role
// (enforced at the router level).
//
// Query parameters:
//
//	?event_type=user.create  — filter by event type
//	?actor_id=<uuid>         — filter to events triggered by a specific user
//	?since=2026-04-08T00:00:00Z  — RFC3339 lower bound
//	?until=2026-04-09T00:00:00Z  — RFC3339 exclusive upper bound
//	?limit=N                 — cap result count (default 100, max 10000)
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	// /api/v1/audit is behind JWTAuth (not UnifiedAuth), so the
	// tenant is read from the authenticated user's OrgID rather
	// than the TenantContext the data routes use. Mirrors the
	// pattern in handleListUsers.
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	orgID := requester.OrgID
	// D5 fix: an empty OrgID must NOT collapse the filter down to
	// "return every event across all tenants". store.ListAudit
	// treats an empty OrgID as "no filter", so we reject here with
	// a 403 to prevent cross-tenant leakage if a user row ever
	// ends up with an empty org_id column (e.g., a misconfigured
	// bootstrap admin). The happy path — every real org_user or
	// org_admin has a non-empty OrgID populated by the provisioning
	// or create-user flow — passes through unaffected.
	if orgID == "" {
		writeError(w, http.StatusForbidden, "audit access requires an organization-scoped user")
		return
	}
	q := r.URL.Query()
	filter := store.AuditFilter{
		OrgID:     orgID,
		EventType: q.Get("event_type"),
		ActorID:   q.Get("actor_id"),
	}
	if since := q.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'since' timestamp: use RFC3339")
			return
		}
		filter.Since = &t
	}
	if until := q.Get("until"); until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'until' timestamp: use RFC3339")
			return
		}
		filter.Until = &t
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		filter.Limit = n
	}

	events, err := s.store.ListAudit(r.Context(), filter)
	if err != nil {
		log.Printf("list audit: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}
