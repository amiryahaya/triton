package licenseserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// POST /api/v1/admin/licenses
func (s *Server) handleCreateLicense(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		OrgID     string `json:"orgID"`
		Tier      string `json:"tier"`
		Seats     int    `json:"seats"`
		Days      int    `json:"days"`
		ExpiresAt string `json:"expiresAt"` // RFC3339, alternative to days
		Notes     string `json:"notes"`
		// v2 fields (optional — legacy licences omit these).
		Features      licensestore.Features `json:"features"`
		Limits        licensestore.Limits   `json:"limits"`
		SoftBufferPct int                   `json:"soft_buffer_pct"`
		ProductScope  string                `json:"product_scope"`
		// Portal-pushed schedule (migration 6).
		Schedule              string `json:"schedule"`
		ScheduleJitterSeconds int    `json:"scheduleJitterSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrgID == "" {
		writeError(w, http.StatusBadRequest, "orgID is required")
		return
	}
	if req.Tier == "" {
		writeError(w, http.StatusBadRequest, "tier is required")
		return
	}
	validTiers := map[string]bool{"free": true, "pro": true, "enterprise": true}
	if !validTiers[req.Tier] {
		writeError(w, http.StatusBadRequest, "tier must be free, pro, or enterprise")
		return
	}
	if req.Seats < 1 {
		writeError(w, http.StatusBadRequest, "seats must be >= 1")
		return
	}
	if tooLong(req.Notes, maxNotesLen) {
		writeError(w, http.StatusBadRequest, "notes exceeds maximum length")
		return
	}
	if req.Schedule != "" {
		if _, err := cron.ParseStandard(req.Schedule); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid schedule cron expression: %v", err))
			return
		}
	}
	if req.ScheduleJitterSeconds < 0 {
		writeError(w, http.StatusBadRequest, "scheduleJitterSeconds must be >= 0")
		return
	}

	// Verify org exists
	if _, err := s.store.GetOrg(r.Context(), req.OrgID); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "organization not found")
			return
		}
		log.Printf("get org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if req.ExpiresAt != "" && req.Days != 0 {
		writeError(w, http.StatusBadRequest, "specify either expiresAt or days, not both")
		return
	}

	now := time.Now().UTC()
	var expiresAt time.Time
	switch {
	case req.ExpiresAt != "":
		var err error
		expiresAt, err = time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expiresAt format, expected RFC3339")
			return
		}
		if !expiresAt.After(now) {
			writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
			return
		}
	case req.Days > 0:
		expiresAt = now.Add(time.Duration(req.Days) * 24 * time.Hour)
	case req.Days < 0:
		writeError(w, http.StatusBadRequest, "days must be positive")
		return
	default:
		expiresAt = now.Add(365 * 24 * time.Hour) // default 1 year
	}

	lic := &licensestore.LicenseRecord{
		ID:             uuid.Must(uuid.NewV7()).String(),
		OrgID:          req.OrgID,
		Tier:           req.Tier,
		Seats:          req.Seats,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		Notes:          req.Notes,
		CreatedAt:      now,
		Features:       req.Features,
		Limits:         req.Limits,
		SoftBufferPct:  req.SoftBufferPct,
		ProductScope:   req.ProductScope,
		Schedule:       req.Schedule,
		ScheduleJitter: req.ScheduleJitterSeconds,
	}

	if err := s.store.CreateLicense(r.Context(), lic); err != nil {
		log.Printf("create license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	auditExtra := map[string]any{
		"tier": req.Tier, "seats": req.Seats,
	}
	if req.Schedule != "" {
		auditExtra["schedule"] = req.Schedule
		auditExtra["scheduleJitterSeconds"] = req.ScheduleJitterSeconds
	}
	s.audit(r, "license_create", lic.ID, req.OrgID, "", auditExtra)
	writeJSON(w, http.StatusCreated, lic)
}

// GET /api/v1/admin/licenses
func (s *Server) handleListLicenses(w http.ResponseWriter, r *http.Request) {
	filter := licensestore.LicenseFilter{
		OrgID:  r.URL.Query().Get("org"),
		Tier:   r.URL.Query().Get("tier"),
		Status: r.URL.Query().Get("status"),
	}
	lics, err := s.store.ListLicenses(r.Context(), filter)
	if err != nil {
		log.Printf("list licenses error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if lics == nil {
		lics = []licensestore.LicenseRecord{} // never return null
	}
	writeJSON(w, http.StatusOK, lics)
}

// GET /api/v1/admin/licenses/{id}
func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Include activations
	acts, err := s.store.ListActivations(r.Context(), licensestore.ActivationFilter{LicenseID: id})
	if err != nil {
		log.Printf("list activations error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := struct {
		*licensestore.LicenseRecord
		Activations []licensestore.Activation `json:"activations"`
	}{
		LicenseRecord: lic,
		Activations:   acts,
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/admin/licenses/{id}/revoke
func (s *Server) handleRevokeLicense(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Reason string `json:"reason"`
	}
	// Body is optional
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := s.store.RevokeLicense(r.Context(), id, "admin"); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("revoke license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "license_revoke", id, "", "", map[string]any{"reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// PATCH /api/v1/admin/licenses/{id}
//
// Currently supports schedule + scheduleJitterSeconds. Extend the
// anonymous struct below to add more mutable fields later. Pointer
// types distinguish "don't touch" (nil) from "clear" (non-nil empty
// string / zero).
func (s *Server) handleUpdateLicense(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "license id required")
		return
	}

	var req struct {
		Schedule              *string `json:"schedule"`
		ScheduleJitterSeconds *int    `json:"scheduleJitterSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Schedule != nil && *req.Schedule != "" {
		if _, err := cron.ParseStandard(*req.Schedule); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid schedule cron expression: %v", err))
			return
		}
	}
	if req.ScheduleJitterSeconds != nil && *req.ScheduleJitterSeconds < 0 {
		writeError(w, http.StatusBadRequest, "scheduleJitterSeconds must be >= 0")
		return
	}

	upd := licensestore.LicenseUpdate{
		Schedule:       req.Schedule,
		ScheduleJitter: req.ScheduleJitterSeconds,
	}
	if err := s.store.UpdateLicense(r.Context(), id, upd); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("update license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	auditExtra := map[string]any{}
	if req.Schedule != nil {
		auditExtra["schedule"] = *req.Schedule
	}
	if req.ScheduleJitterSeconds != nil {
		auditExtra["scheduleJitterSeconds"] = *req.ScheduleJitterSeconds
	}
	s.audit(r, "license_schedule_updated", id, "", "", auditExtra)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// agentYAMLRequest is the optional POST body for the agent.yaml
// download endpoint. Every field is optional; an empty body
// produces a machine-unbound token with the license server's
// configured report_server URL and a "quick" profile default.
type agentYAMLRequest struct {
	// ReportServer overrides the license server's configured
	// ReportServerURL. Operators can leave it empty to use the
	// server default, or set it explicitly to "" to force
	// local-report mode even when the server is wired to a
	// report URL.
	ReportServer *string `json:"report_server,omitempty"`

	// Profile sets the default scan profile in the generated
	// agent.yaml. Valid values: "quick" | "standard" |
	// "comprehensive". When empty, defaults to "quick" so a
	// license-less drop-and-run still works.
	Profile string `json:"profile,omitempty"`

	// BindToMachine, when non-empty, makes the minted token
	// machine-bound via the MachineID claim. The expected value
	// is the target host's fingerprint string
	// (SHA-3-256(hostname|GOOS|GOARCH) — compute via
	// `triton license fingerprint` on the target machine). Leave
	// empty for the fool-proof "any machine" default.
	BindToMachine string `json:"bind_to_machine,omitempty"`
}

// POST /api/v1/admin/licenses/{id}/agent-yaml
//
// Generates a ready-to-ship agent.yaml file for a stored license.
// The license server mints a fresh Ed25519-signed token from the
// license's claims (same signing path as the activation flow) and
// bakes it into a YAML template with a prominent security header
// comment. The resulting file is streamed as an attachment so the
// superadmin can download it and hand it to the customer.
//
// Security note: the default path produces a MACHINE-UNBOUND
// token — any agent that drops the file in its exe directory can
// use it. That's the fool-proof deployment trade-off. If a
// customer wants per-machine scoping, the admin should either
// (a) use the activation flow (triton license activate
// --license-id <uuid>) on each target host, or (b) supply
// bind_to_machine in this request body with the target host's
// fingerprint.
//
// Tokens minted by this endpoint are NOT tracked in the
// activations table because there's no Activation record until
// the agent starts using it. Revocation is at the license level:
// revoking the license invalidates every token it ever minted.
func (s *Server) handleDownloadAgentYAML(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Fetch the license. Reuses the same store call
	// handleGetLicense uses so any consistency logic (e.g.,
	// revoked-license filtering) stays in one place.
	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("agent-yaml: get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "cannot generate agent.yaml for a revoked license")
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "cannot generate agent.yaml for an expired license")
		return
	}

	// Parse the optional request body. An empty body is valid
	// (the endpoint supports GET-like usage with POST semantics
	// so the admin UI can send `{}` from fetch without a
	// content-type mismatch).
	var req agentYAMLRequest
	if r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}

	// Validate the profile if one was supplied. Empty string
	// means "use the default 'quick'" and is fine.
	profile := strings.TrimSpace(req.Profile)
	if profile == "" {
		profile = "comprehensive"
	}
	if profile != "quick" && profile != "standard" && profile != "comprehensive" {
		writeError(w, http.StatusBadRequest,
			"invalid profile: must be quick, standard, or comprehensive")
		return
	}

	// Determine the report_server to embed. Explicit body field
	// wins (including "" which forces local-only mode). Otherwise
	// prefer the PUBLIC URL over the internal provisioning URL
	// because a customer-facing agent.yaml needs a hostname the
	// agent can actually resolve from outside the server network.
	// Falls back to the internal URL only when no public URL is
	// configured, which is a misconfiguration but still better
	// than silently writing an empty report_server when the
	// operator intended one.
	var reportServer string
	switch {
	case req.ReportServer != nil:
		reportServer = *req.ReportServer
	case s.config.ReportServerPublicURL != "":
		reportServer = s.config.ReportServerPublicURL
	default:
		reportServer = s.config.ReportServerURL
	}

	// Mint the token. Same signing path as signToken() but with
	// the machine ID driven by the request body rather than the
	// per-activation fingerprint.
	tok, err := s.signToken(lic, req.BindToMachine)
	if err != nil {
		log.Printf("agent-yaml: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build the yaml body. A hand-written template (not
	// encoding/yaml) because we want the header comment to
	// survive round-tripping and yaml.Marshal strips comments.
	body := buildAgentYAML(agentYAMLParams{
		License:       lic,
		Token:         tok,
		ReportServer:  reportServer,
		Profile:       profile,
		BindToMachine: req.BindToMachine,
	})

	s.audit(r, "license_download_agent_yaml", id, "", "", map[string]any{
		"profile":         profile,
		"report_server":   reportServer,
		"machine_bound":   req.BindToMachine != "",
		"tier":            lic.Tier,
		"license_expires": lic.ExpiresAt.Format(time.RFC3339),
	})

	// Stream as a download. application/x-yaml is the de-facto
	// Content-Type; text/yaml is an alternative some browsers
	// recognize. Either triggers the Save As dialog when paired
	// with Content-Disposition: attachment.
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="agent.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// agentYAMLParams is the set of substitutions buildAgentYAML
// needs. Extracted as a struct so the formatter stays readable
// as more fields are added.
type agentYAMLParams struct {
	License       *licensestore.LicenseRecord
	Token         string
	ReportServer  string
	Profile       string
	BindToMachine string
}

// buildAgentYAML returns a fully-populated agent.yaml file body
// as a string. The template is kept inline (rather than embedded
// via //go:embed) so the handler and the file-format comment
// live in one place and drift between them is impossible.
//
// The header comment carries:
//   - a clear "generated by the license server" marker
//   - the license ID and org so an operator can trace the file
//     back to its source in the admin UI
//   - the expiry date so an operator isn't surprised when the
//     token stops working
//   - a security warning about treating the file as a secret
func buildAgentYAML(p agentYAMLParams) string {
	machineBindNote := "(not machine-bound — runs on any host)"
	if p.BindToMachine != "" {
		machineBindNote = fmt.Sprintf("(machine-bound to fingerprint %s)", p.BindToMachine)
	}

	reportServerLine := fmt.Sprintf("report_server: %q", p.ReportServer)
	if p.ReportServer == "" {
		reportServerLine = `report_server: ""`
	}

	return fmt.Sprintf(`# =============================================================================
#  Triton Agent — generated by the License Server
# =============================================================================
#
#  This file was generated by the Triton License Server admin API for
#  license %s. Drop it next to the triton (or triton.exe) binary and
#  run the binary — the agent will pick up these settings automatically.
#
#  License details:
#    License ID:   %s
#    Organization: %s
#    Tier:         %s
#    Seats:        %d
#    Expires:      %s
#    %s
#
#  SECURITY: the license_key below is ALSO the credential the agent
#  uses to authenticate to a report server. Anyone with this file
#  can submit scan data as the organization above and (when paired
#  with a report_server URL) read back that org's results. Keep it
#  on a trusted filesystem with owner-only read permissions:
#
#      chmod 600 agent.yaml          # macOS / Linux
#      icacls agent.yaml /inheritance:r /grant:r "%%USERNAME%%:R"   # Windows
#
#  Rotate by regenerating a new agent.yaml from the license server
#  admin UI and redistributing to the target host. The old token
#  remains valid until the license itself is revoked.
# =============================================================================

license_key: %q

%s

profile: %q

# Reports are written to this directory when report_server is empty.
# Relative paths are resolved against the directory containing the
# triton binary (NOT the shell cwd) so double-clicking the binary
# from a file manager produces reports in a predictable place.
output_dir: "reports"

# Local-report formats. Leave empty or comment out to generate every
# format your licence tier allows. Ignored when report_server is set.
# formats:
#   - json
#   - html
#   - xlsx
`,
		p.License.ID,
		p.License.ID,
		p.License.OrgName,
		p.License.Tier,
		p.License.Seats,
		p.License.ExpiresAt.Format("2006-01-02"),
		machineBindNote,
		p.Token,
		reportServerLine,
		p.Profile,
	)
}
