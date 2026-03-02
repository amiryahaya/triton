package licenseserver

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
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

	now := time.Now().UTC()
	var expiresAt time.Time
	if req.ExpiresAt != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expiresAt: "+err.Error())
			return
		}
		if !expiresAt.After(now) {
			writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
			return
		}
	} else if req.Days > 0 {
		expiresAt = now.Add(time.Duration(req.Days) * 24 * time.Hour)
	} else if req.Days < 0 {
		writeError(w, http.StatusBadRequest, "days must be positive")
		return
	} else {
		expiresAt = now.Add(365 * 24 * time.Hour) // default 1 year
	}

	lic := &licensestore.LicenseRecord{
		ID:        uuid.New().String(),
		OrgID:     req.OrgID,
		Tier:      req.Tier,
		Seats:     req.Seats,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Notes:     req.Notes,
		CreatedAt: now,
	}

	if err := s.store.CreateLicense(r.Context(), lic); err != nil {
		log.Printf("create license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "license_create", lic.ID, req.OrgID, "", map[string]any{
		"tier": req.Tier, "seats": req.Seats,
	})
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

	s.audit(r, "revoke", id, "", "", map[string]any{"reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
