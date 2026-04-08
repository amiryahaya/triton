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

// POST /api/v1/admin/orgs
//
// Creates an organization in the license server. If admin_email and
// admin_name are supplied AND a report server is configured, also
// provisions the org on the report server (creates the org row +
// first admin user with a generated temporary password).
//
// The temporary password is returned in the response exactly once —
// the license server admin (or Phase 1.8 Resend integration) must
// deliver it to the invited admin out of band. It is never persisted
// in the license server.
//
// If provisioning fails, the org is rolled back in the license server
// to keep the two servers consistent. Idempotency on the report server
// side means a retry with the same org ID + name is safe.
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Name       string `json:"name"`
		Contact    string `json:"contact"`
		Notes      string `json:"notes"`
		AdminEmail string `json:"admin_email,omitempty"`
		AdminName  string `json:"admin_name,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(req.Name, maxNameLen) || tooLong(req.Contact, maxContactLen) || tooLong(req.Notes, maxNotesLen) {
		writeError(w, http.StatusBadRequest, "field exceeds maximum length")
		return
	}

	// If the caller supplied admin invite fields, both must be present.
	wantProvision := req.AdminEmail != "" || req.AdminName != ""
	if wantProvision {
		if req.AdminEmail == "" || req.AdminName == "" {
			writeError(w, http.StatusBadRequest, "admin_email and admin_name must be supplied together")
			return
		}
		if s.reportClient == nil {
			writeError(w, http.StatusServiceUnavailable, "report server not configured; cannot provision admin")
			return
		}
	}

	now := time.Now().UTC()
	org := &licensestore.Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      req.Name,
		Contact:   req.Contact,
		Notes:     req.Notes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateOrg(r.Context(), org); err != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("create org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Provision the admin on the report server if requested.
	var tempPassword string
	if wantProvision {
		generated, err := GenerateTempPassword()
		if err != nil {
			log.Printf("create org: temp password generation failed: %v", err)
			// Roll back the org since provisioning is a hard dependency here.
			if delErr := s.store.DeleteOrg(r.Context(), org.ID); delErr != nil {
				log.Printf("create org: ROLLBACK FAILED — orphan org %s: %v", org.ID, delErr)
			}
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		tempPassword = generated

		_, err = s.reportClient.ProvisionOrg(r.Context(), ProvisionOrgRequest{
			ID:                org.ID,
			Name:              org.Name,
			AdminEmail:        req.AdminEmail,
			AdminName:         req.AdminName,
			AdminTempPassword: tempPassword,
		})
		if err != nil {
			log.Printf("create org: report server provisioning failed: %v", err)
			// Roll back the org so the two servers stay consistent.
			if delErr := s.store.DeleteOrg(r.Context(), org.ID); delErr != nil {
				log.Printf("create org: ROLLBACK FAILED — orphan org %s: %v", org.ID, delErr)
			}
			writeError(w, http.StatusBadGateway, "report server provisioning failed")
			return
		}

		// Best-effort email delivery via Mailer (Phase 1.8). Email failure
		// is NOT fatal — the temp password is already in the API response
		// below, so ops can fall back to manual delivery. We log the
		// failure so it's visible in monitoring.
		if s.config.Mailer != nil {
			emailErr := s.config.Mailer.SendInviteEmail(r.Context(), InviteEmailData{
				ToEmail:      req.AdminEmail,
				ToName:       req.AdminName,
				OrgName:      org.Name,
				TempPassword: tempPassword,
				LoginURL:     s.config.ReportServerInviteURL,
			})
			if emailErr != nil {
				log.Printf("create org: invite email delivery failed (non-fatal): %v", emailErr)
			}
		}
	}

	s.audit(r, "org_create", "", org.ID, "", nil)

	// If we provisioned an admin, return the temp password exactly once
	// so the license server admin can deliver it. Phase 1.8 will replace
	// this with Resend email delivery — the temp password will still be
	// returned in the response for automation scenarios.
	if wantProvision {
		writeJSON(w, http.StatusCreated, map[string]any{
			"org":                 org,
			"admin_email":         req.AdminEmail,
			"admin_temp_password": tempPassword,
		})
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

// GET /api/v1/admin/orgs
func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs(r.Context())
	if err != nil {
		log.Printf("list orgs error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if orgs == nil {
		orgs = []licensestore.Organization{} // never return null
	}
	writeJSON(w, http.StatusOK, orgs)
}

// GET /api/v1/admin/orgs/{id}
func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	org, err := s.store.GetOrg(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "organization not found")
			return
		}
		log.Printf("get org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, org)
}

// PUT /api/v1/admin/orgs/{id}
func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Name    string `json:"name"`
		Contact string `json:"contact"`
		Notes   string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(req.Name, maxNameLen) || tooLong(req.Contact, maxContactLen) || tooLong(req.Notes, maxNotesLen) {
		writeError(w, http.StatusBadRequest, "field exceeds maximum length")
		return
	}

	org := &licensestore.Organization{
		ID:        id,
		Name:      req.Name,
		Contact:   req.Contact,
		Notes:     req.Notes,
		UpdatedAt: time.Now().UTC(),
	}

	if err := s.store.UpdateOrg(r.Context(), org); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "organization not found")
			return
		}
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("update org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "org_update", "", id, "", nil)

	// Fetch the full record to return complete data (including CreatedAt)
	updated, err := s.store.GetOrg(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, org)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// DELETE /api/v1/admin/orgs/{id}
func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteOrg(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "organization not found")
			return
		}
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("delete org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "org_delete", "", id, "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
