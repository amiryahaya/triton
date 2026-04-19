package server

import (
	"net/http"
)

// handleEnrolManage is the Report-side admin endpoint Manage calls during
// its /setup/license flow to obtain an mTLS client bundle. Real behaviour
// lives in pkg/server/manage_enrol/handlers_admin.go; this method is a
// thin delegator that returns 501 when the handler isn't configured.
//
// Authentication: mounted behind ServiceKeyAuth under /api/v1/admin, same
// gate used by /api/v1/admin/orgs so both admin service-to-service flows
// share a single shared-secret.
//
// Configuration: wired in server.New when cfg.ManageEnrolConfig is
// populated (requires a Master key, an engine CA store for a specific
// OrgID, a ReportPublicURL, and a LicenseValidator). Deployments that do
// not run Manage leave ManageEnrolConfig nil and the route stays 501.
func (s *Server) handleEnrolManage(w http.ResponseWriter, r *http.Request) {
	if s.manageEnrolHandlers == nil {
		writeError(w, http.StatusNotImplemented, "manage enrol not configured on this server")
		return
	}
	s.manageEnrolHandlers.Enrol(w, r)
}
