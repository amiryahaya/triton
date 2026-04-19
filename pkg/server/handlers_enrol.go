package server

import (
	"net/http"
)

// handleEnrolManage is a stub placeholder for the Manage Server mTLS
// enrolment endpoint. The real implementation lands in PR B2
// (triton#feat/manage-server-b2) when the Manage Server's scanner
// orchestrator needs to push scan results to the Report Server over
// a mutually-authenticated channel.
//
// In B1 we only stand up the Manage Server's HTTP shell (setup, auth,
// licence wiring) — no scans flow between Manage → Report yet — so
// this handler deliberately returns 501 Not Implemented.
//
// Authentication: mounted behind ServiceKeyAuth under /api/v1/admin,
// same gate used by /api/v1/admin/orgs so both admin service-to-service
// flows share a single shared-secret.
func (s *Server) handleEnrolManage(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "manage mTLS enrolment lands in PR B2 (triton#feat/manage-server-b2)")
}
