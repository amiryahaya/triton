package server

import (
	"errors"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// TenantLicenceGate enforces licence status for tenant-scoped routes.
// Must run after auth middleware so the org ID is available in context.
//
// Missing row → pass through (backward compat).
// active → pass through.
// grace  → pass through + X-Licence-Grace: true header.
// expired → 403 {"error": "licence expired"}.
func (s *Server) TenantLicenceGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := TenantFromContext(r.Context())
		if orgID == "" {
			next.ServeHTTP(w, r)
			return
		}

		tl, err := s.store.GetTenantLicence(r.Context(), orgID)
		if err != nil {
			var nf *store.ErrNotFound
			if errors.As(err, &nf) {
				// No licence row: backward-compat pass-through.
				next.ServeHTTP(w, r)
				return
			}
			// DB error: fail open to avoid blocking legitimate users.
			log.Printf("licence gate: GetTenantLicence %s: %v (failing open)", orgID, err)
			next.ServeHTTP(w, r)
			return
		}

		switch tl.Status {
		case "expired":
			writeError(w, http.StatusForbidden, "licence expired")
		case "grace":
			w.Header().Set("X-Licence-Grace", "true")
			next.ServeHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}
