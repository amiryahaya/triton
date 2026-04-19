package manageserver

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// handleSetupStatus returns {admin_created, license_activated, setup_required}.
// GET /api/v1/setup/status — always available, regardless of setup mode.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"admin_created":     state.AdminCreated,
		"license_activated": state.LicenseActivated,
		"setup_required":    !state.AdminCreated || !state.LicenseActivated,
	})
}

// handleSetupAdmin creates the first admin user.
// POST /api/v1/setup/admin — body {email, name, password}.
// Only allowed when no admin exists yet (gated by SetupOnly middleware).
// Returns 409 if an admin is already created (defence-in-depth against
// a race between the middleware check and the handler body).
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	if state.AdminCreated {
		writeError(w, http.StatusConflict, "admin already created")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	user := &managestore.ManageUser{
		Email:        req.Email,
		Name:         req.Name,
		Role:         "admin",
		PasswordHash: hash,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var cf *managestore.ErrConflict
		if errors.As(err, &cf) {
			writeError(w, http.StatusConflict, cf.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "create user failed")
		return
	}
	if err := s.store.MarkAdminCreated(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "mark setup failed")
		return
	}
	s.RefreshSetupMode(r.Context())

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":      true,
		"user_id": user.ID,
	})
}

// handleSetupLicense activates a licence against the configured License Server
// and persists the signed token locally, transitioning Manage out of setup mode.
//
// POST /api/v1/setup/license — body {license_server_url, license_key}.
//
// Atomicity caveat: if Activate succeeds on the Licence Server but the local
// persist fails, the seat is consumed on LS while Manage still thinks it's
// un-activated. Admin retries; LS dedupes on machine fingerprint + licence key.
func (s *Server) handleSetupLicense(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	if !state.AdminCreated {
		writeError(w, http.StatusConflict, "create admin first")
		return
	}
	if state.LicenseActivated {
		writeError(w, http.StatusConflict, "license already activated")
		return
	}

	var req struct {
		LicenseServerURL string `json:"license_server_url"`
		LicenseKey       string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.LicenseServerURL == "" || req.LicenseKey == "" {
		writeError(w, http.StatusBadRequest, "license_server_url and license_key required")
		return
	}

	// Activate against the License Server. The client is v1-shaped: it accepts
	// just the licence ID and computes machine binding internally. The v2
	// response fields (features, limits, product_scope) are populated when
	// the server is v2-capable; Manage enforces product scope client-side.
	client := license.NewServerClient(req.LicenseServerURL)
	resp, err := client.Activate(req.LicenseKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "activation failed: "+err.Error())
		return
	}
	if !resp.Features.Manage {
		writeError(w, http.StatusForbidden, "license does not grant manage product")
		return
	}

	instanceID := uuid.Must(uuid.NewV7()).String()
	if err := s.store.SaveLicenseActivation(r.Context(),
		req.LicenseServerURL, req.LicenseKey, resp.Token, instanceID); err != nil {
		writeError(w, http.StatusInternalServerError, "save activation: "+err.Error())
		return
	}
	s.RefreshSetupMode(r.Context())

	// Kick the licence guard + usage pusher so feature gating comes online
	// without restarting. Failures here are logged but non-fatal: the next
	// server boot will retry via initLicence.
	if lerr := s.startLicence(r.Context()); lerr != nil {
		log.Printf("manageserver: startLicence after setup: %v", lerr)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"features": resp.Features,
		"limits":   resp.Limits,
	})
}

// validatePassword enforces the minimum password policy for Manage Server
// admin accounts — at least 12 characters and at least one digit. Intended
// to be tightened by B2's invite/temp-password flow.
func validatePassword(p string) error {
	if len(p) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	hasDigit := false
	for _, c := range p {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return errors.New("password must contain a digit")
	}
	return nil
}
