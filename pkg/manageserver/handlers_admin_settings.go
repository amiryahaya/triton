package manageserver

import (
	"net/http"

	"github.com/amiryahaya/triton/internal/version"
)

// SettingsSummary is the JSON body of GET /api/v1/admin/settings.
//
// Read-only runtime configuration — no POST/PUT counterpart. The admin
// UI renders this purely for operator visibility; editing these values
// still requires a restart with updated environment variables.
//
// Struct tags pin the wire format; reordering or renaming fields is a
// breaking change for the Manage admin UI.
type SettingsSummary struct {
	Parallelism     int    `json:"parallelism"`
	GatewayListen   string `json:"gateway_listen"`
	GatewayHostname string `json:"gateway_hostname"`
	ReportServerURL string `json:"report_server_url"`
	ManageListen    string `json:"manage_listen"`
	InstanceID      string `json:"instance_id"`
	Version         string `json:"version"`
}

// handleSettings returns the live runtime configuration for operator
// visibility. Sources: s.cfg fields + manage_setup.instance_id +
// internal/version.Version.
//
// GET /api/v1/admin/settings
//
// Unlike /admin/licence this handler has no guard-nil branch — the
// values returned are static deployment metadata that exist regardless
// of licence activation state. A 500 here is always a DB/setup-read
// failure, not a policy decision.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	setup, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read setup state")
		return
	}

	writeJSON(w, http.StatusOK, SettingsSummary{
		Parallelism:     s.cfg.Parallelism,
		GatewayListen:   s.cfg.GatewayListen,
		GatewayHostname: s.cfg.GatewayHostname,
		ReportServerURL: s.cfg.ReportServer,
		ManageListen:    s.cfg.Listen,
		InstanceID:      setup.InstanceID,
		Version:         version.Version,
	})
}
