package server

import (
	"context"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// Audit event type constants — short tags grep'able from log lines
// and the audit_events.event_type column. Add new values sparingly;
// a proliferation of types makes dashboards harder.
const (
	auditUserCreate       = "user.create"
	auditUserUpdate       = "user.update"
	auditUserDelete       = "user.delete"
	auditUserResendInvite = "user.resend_invite"
	auditScanDelete       = "scan.delete"
	auditOrgProvision     = "org.provision"
	auditAuthChangePW     = "auth.change_password" // successful change, not failed
)

// writeAudit is a fire-and-forget helper that logs on write failure
// but never surfaces the error to the caller. Audit failures must
// NOT cause a request to fail — that would be a DoS surface (an
// attacker who can break the audit DB could lock out all real
// actions). Use context.WithoutCancel so a cancelled request
// doesn't abort the audit write mid-flight.
//
// The tenant (orgID) is read from the authenticated user's OrgID
// when one is present, falling back to TenantFromContext for
// routes protected by UnifiedAuth (scan submission, scan delete).
// This dual-read lets audit work on every protected route regardless
// of which auth middleware guards it.
func (s *Server) writeAudit(r *http.Request, eventType, targetID string, details map[string]any) {
	actorID := ""
	orgID := ""
	if u := UserFromContext(r.Context()); u != nil {
		actorID = u.ID
		orgID = u.OrgID
	}
	if orgID == "" {
		orgID = TenantFromContext(r.Context())
	}

	entry := &store.AuditEvent{
		EventType: eventType,
		OrgID:     orgID,
		ActorID:   actorID,
		TargetID:  targetID,
		Details:   details,
		IPAddress: r.RemoteAddr,
	}
	// context.WithoutCancel keeps the DB write alive even if the
	// request context is canceled mid-handler (e.g., client
	// disconnected). Matches the license server's audit pattern.
	go func() {
		if err := s.store.WriteAudit(context.WithoutCancel(r.Context()), entry); err != nil {
			log.Printf("audit: WriteAudit(%s) failed: %v", eventType, err)
		}
	}()
}
