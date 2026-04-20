package manageserver

import (
	"net/http"
	"time"
)

// LicenceSummary is the JSON body of GET /api/v1/admin/licence.
//
// Struct tags pin the wire format; reordering or renaming fields is a
// breaking change for the Manage admin UI. When the handler returns
// 503 (licence inactive) the body is the standard {"error": ...}
// envelope instead — callers check the status code first.
type LicenceSummary struct {
	Tier                string          `json:"tier"`
	Features            map[string]bool `json:"features"`
	Limits              LicenceLimits   `json:"limits"`
	LicenseServerURL    string          `json:"license_server_url"`
	InstanceID          string          `json:"instance_id"`
	LastPushedAt        *time.Time      `json:"last_pushed_at"`
	LastPushError       string          `json:"last_push_error"`
	ConsecutiveFailures int             `json:"consecutive_failures"`
}

// LicenceLimits bundles the four tracked cap/usage pairs.
type LicenceLimits struct {
	Seats  LimitPair      `json:"seats"`
	Hosts  LimitPair      `json:"hosts"`
	Agents LimitPair      `json:"agents"`
	Scans  ScansLimitPair `json:"scans"`
}

// LimitPair is the (cap, used) shape for a single metric/window.
// Cap is -1 when no cap is configured (see Guard.LimitCap contract).
type LimitPair struct {
	Cap  int64 `json:"cap"`
	Used int64 `json:"used"`
}

// ScansLimitPair extends LimitPair with the soft-buffer ceiling the
// monthly scan cap uses — the admin UI renders this alongside the hard
// cap so operators can see the incremental-drift watermark.
type ScansLimitPair struct {
	LimitPair
	SoftBufferCeiling int64 `json:"soft_buffer_ceiling"`
}

// handleLicenceSummary serves GET /api/v1/admin/licence. Returns 503
// when the guard is nil (licence never activated, parse failure at
// boot, or stopLicence was called) so the UI can surface a "licence
// inactive — re-activate to continue" banner.
//
// We intentionally return 503 rather than an empty 200 payload: a 200
// with tier:"" would confuse cache / retry layers and hide a real
// activation failure. 503 is the same code the licence-middleware on
// the Report Server uses for the same condition.
//
// Setup state is read via s.store.GetSetup (authoritative for
// license_server_url + instance_id) rather than cached on the Guard;
// the Guard holds the parsed token and tier but not the deployment
// metadata. scanresults.LoadLicenseState surfaces the drain-side heartbeat
// columns (last_pushed_at, last_push_error, consecutive_failures).
//
// A transient LoadLicenseState error is tolerated — the response still
// carries tier + limits so the admin UI has enough to render. We
// deliberately don't 500 on that path because a stale heartbeat doesn't
// invalidate the authoritative tier/cap info.
func (s *Server) handleLicenceSummary(w http.ResponseWriter, r *http.Request) {
	guard := s.guardSnapshot()
	if guard == nil {
		writeError(w, http.StatusServiceUnavailable, "licence inactive")
		return
	}

	setup, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read setup state")
		return
	}

	// LoadLicenseState error is non-fatal — we still want to return
	// tier + limits even if the heartbeat columns are unreadable.
	state, _ := s.resultsStore.LoadLicenseState(r.Context())

	resp := LicenceSummary{
		Tier:                string(guard.Tier()),
		Features:            map[string]bool{"manage": guard.HasFeature("manage")},
		LicenseServerURL:    setup.LicenseServerURL,
		InstanceID:          setup.InstanceID,
		LastPushedAt:        state.LastPushedAt,
		LastPushError:       state.LastPushError,
		ConsecutiveFailures: state.ConsecutiveFailures,
	}
	resp.Limits.Seats = LimitPair{
		Cap:  guard.LimitCap("seats", "total"),
		Used: guard.CurrentUsage("seats", "total"),
	}
	resp.Limits.Hosts = LimitPair{
		Cap:  guard.LimitCap("hosts", "total"),
		Used: guard.CurrentUsage("hosts", "total"),
	}
	resp.Limits.Agents = LimitPair{
		Cap:  guard.LimitCap("agents", "total"),
		Used: guard.CurrentUsage("agents", "total"),
	}
	resp.Limits.Scans = ScansLimitPair{
		LimitPair: LimitPair{
			Cap:  guard.LimitCap("scans", "monthly"),
			Used: guard.CurrentUsage("scans", "monthly"),
		},
		SoftBufferCeiling: guard.SoftBufferCeiling("scans", "monthly"),
	}

	writeJSON(w, http.StatusOK, resp)
}
