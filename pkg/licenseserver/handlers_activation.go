package licenseserver

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// POST /api/v1/license/activate
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		LicenseID string `json:"licenseID"`
		MachineID string `json:"machineID"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LicenseID == "" || req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "licenseID and machineID are required")
		return
	}
	if tooLong(req.Hostname, maxHostnameLen) {
		writeError(w, http.StatusBadRequest, "hostname exceeds maximum length")
		return
	}

	// Lookup license
	lic, err := s.store.GetLicense(r.Context(), req.LicenseID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("activate get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Pre-sign a token for this machine.
	// The store.Activate transaction is the authoritative check for revoked/expired/seats.
	token, err := s.signToken(lic, req.MachineID)
	if err != nil {
		log.Printf("activate sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	act := &licensestore.Activation{
		ID:          uuid.Must(uuid.NewV7()).String(),
		LicenseID:   req.LicenseID,
		MachineID:   req.MachineID,
		Hostname:    req.Hostname,
		OS:          req.OS,
		Arch:        req.Arch,
		Token:       token,
		ActivatedAt: now,
		LastSeenAt:  now,
		Active:      true,
	}

	if err := s.store.Activate(r.Context(), act); err != nil {
		var sf *licensestore.ErrSeatsFull
		if errors.As(err, &sf) {
			writeError(w, http.StatusConflict, "all seats are occupied")
			return
		}
		var revoked *licensestore.ErrLicenseRevoked
		if errors.As(err, &revoked) {
			writeError(w, http.StatusForbidden, "license has been revoked")
			return
		}
		var expired *licensestore.ErrLicenseExpired
		if errors.As(err, &expired) {
			writeError(w, http.StatusForbidden, "license has expired")
			return
		}
		log.Printf("activate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Fetch the stored activation to get the canonical token and ID
	stored, err := s.store.GetActivationByMachine(r.Context(), req.LicenseID, req.MachineID)
	if err != nil {
		log.Printf("fetch activation after activate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	token = stored.Token
	act.ID = stored.ID

	seatsUsed, seatErr := s.store.CountActiveSeats(r.Context(), req.LicenseID)
	if seatErr != nil {
		log.Printf("count active seats error: %v", seatErr)
	}

	s.audit(r, "activate", req.LicenseID, lic.OrgID, req.MachineID, map[string]any{
		"hostname": req.Hostname, "os": req.OS, "arch": req.Arch,
	})

	features := licensestore.ResolveFeatures(lic)
	limits := licensestore.ResolveLimits(lic)

	usage, uerr := s.store.UsageSummary(r.Context(), lic.ID)
	if uerr != nil {
		log.Printf("activate usage summary error: %v", uerr)
		usage = map[string]map[string]int64{}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		// existing fields
		"token":        token,
		"activationID": act.ID,
		"tier":         lic.Tier,
		"seats":        lic.Seats,
		"seatsUsed":    seatsUsed,
		"expiresAt":    lic.ExpiresAt.Format(time.RFC3339),
		// v2 fields (additive, back-compat)
		"features":        features,
		"limits":          limits,
		"soft_buffer_pct": lic.SoftBufferPct,
		"product_scope":   lic.ProductScope,
		"usage":           usage,
		"grace_seconds":   7 * 24 * 3600,
	})
}

// POST /api/v1/license/deactivate
func (s *Server) handleDeactivate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		LicenseID string `json:"licenseID"`
		MachineID string `json:"machineID"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LicenseID == "" || req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "licenseID and machineID are required")
		return
	}

	if err := s.store.Deactivate(r.Context(), req.LicenseID, req.MachineID); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "activation not found")
			return
		}
		log.Printf("deactivate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "deactivate", req.LicenseID, "", req.MachineID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
}

// POST /api/v1/license/validate
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		LicenseID string `json:"licenseID"`
		MachineID string `json:"machineID"`
		Token     string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LicenseID == "" || req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "licenseID and machineID are required")
		return
	}

	// Check license status
	lic, err := s.store.GetLicense(r.Context(), req.LicenseID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
		return
	}
	if lic.Revoked {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
		return
	}

	// Check activation
	act, err := s.store.GetActivationByMachine(r.Context(), req.LicenseID, req.MachineID)
	if err != nil || !act.Active {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
		return
	}

	// Verify submitted token matches the stored token
	if req.Token == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(act.Token)) != 1 {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "validation failed"})
		return
	}

	// Update last_seen
	_ = s.store.UpdateLastSeen(r.Context(), act.ID)

	// Look up the org name so the report server's validation cache (Phase 2.1)
	// can populate org context without a second round-trip. The license is
	// already known-valid above, so an org-fetch failure here is non-fatal —
	// fall back to an empty name and let the caller decide how to handle it.
	var orgName string
	if lic.OrgID != "" {
		if org, err := s.store.GetOrg(r.Context(), lic.OrgID); err == nil {
			orgName = org.Name
		} else {
			log.Printf("validate: org lookup failed for %s: %v", lic.OrgID, err)
		}
	}

	features := licensestore.ResolveFeatures(lic)
	limits := licensestore.ResolveLimits(lic)

	usage, uerr := s.store.UsageSummary(r.Context(), lic.ID)
	if uerr != nil {
		log.Printf("validate usage summary error: %v", uerr)
		usage = map[string]map[string]int64{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		// existing fields
		"valid":     true,
		"tier":      lic.Tier,
		"orgID":     lic.OrgID,
		"orgName":   orgName,
		"seats":     lic.Seats,
		"seatsUsed": lic.SeatsUsed,
		"expiresAt": lic.ExpiresAt.Format(time.RFC3339),
		// cacheTTL is the maximum age in seconds that a caller (typically
		// the report server's validation cache, Phase 2.1) may treat this
		// result as authoritative. Centralizing the trust window here lets
		// the license server tune revocation propagation latency without
		// changing client code. 300s = 5 minutes is the initial default;
		// it can become a config field if ops needs to dial it.
		"cacheTTL": validateCacheTTLSeconds,
		// v2 fields (additive, back-compat)
		"features":        features,
		"limits":          limits,
		"soft_buffer_pct": lic.SoftBufferPct,
		"product_scope":   lic.ProductScope,
		"usage":           usage,
	})
}

// validateCacheTTLSeconds is the maximum number of seconds that callers
// (the report server's validation cache) should treat a positive validate
// response as authoritative before re-validating. See handleValidate.
const validateCacheTTLSeconds = 300

// GET /api/v1/admin/activations
func (s *Server) handleListActivations(w http.ResponseWriter, r *http.Request) {
	filter := licensestore.ActivationFilter{
		LicenseID: r.URL.Query().Get("license"),
		MachineID: r.URL.Query().Get("machine"),
	}
	if v := r.URL.Query().Get("active"); v == "true" {
		active := true
		filter.Active = &active
	} else if v == "false" {
		active := false
		filter.Active = &active
	}

	acts, err := s.store.ListActivations(r.Context(), filter)
	if err != nil {
		log.Printf("list activations error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, acts)
}

// POST /api/v1/admin/activations/{id}/deactivate
func (s *Server) handleAdminDeactivate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	act, err := s.store.GetActivation(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "activation not found")
			return
		}
		log.Printf("admin deactivate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if err := s.store.Deactivate(r.Context(), act.LicenseID, act.MachineID); err != nil {
		log.Printf("admin deactivate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "admin_deactivate", act.LicenseID, "", act.MachineID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
}

// signToken creates an Ed25519-signed license token for a machine.
// It includes v2 claims (features, limits, soft_buffer_pct, product_scope)
// resolved via compat so legacy licences get synthesised values.
func (s *Server) signToken(lic *licensestore.LicenseRecord, machineID string) (string, error) {
	l := &license.License{
		ID:        lic.ID,
		Tier:      license.Tier(lic.Tier),
		OrgID:     lic.OrgID,
		Org:       lic.OrgName,
		Seats:     lic.Seats,
		IssuedAt:  lic.IssuedAt.Unix(),
		ExpiresAt: lic.ExpiresAt.Unix(),
		MachineID: machineID,
		// v2 claims — resolved via compat so legacy licences get synthesised values.
		Features:      licensestore.ResolveFeatures(lic),
		Limits:        licensestore.ResolveLimits(lic),
		SoftBufferPct: lic.SoftBufferPct,
		ProductScope:  lic.ProductScope,
	}
	return license.Encode(l, s.config.SigningKey)
}
