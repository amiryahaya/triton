package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/store"
)

// tenantResponse extends Organization with licence status fields sourced
// from the tenant_licences table.
type tenantResponse struct {
	store.Organization
	LicenceStatus string     `json:"licenceStatus"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

// handleListPlatformTenants returns all orgs with their licence status.
// GET /api/v1/platform/tenants
func (s *Server) handleListPlatformTenants(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs(r.Context())
	if err != nil {
		log.Printf("list platform tenants: list orgs: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	licences, err := s.store.ListTenantLicences(r.Context())
	if err != nil {
		log.Printf("list platform tenants: list tenant licences: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build a lookup map: orgID → TenantLicence.
	licenceByOrg := make(map[string]store.TenantLicence, len(licences))
	for _, tl := range licences {
		licenceByOrg[tl.OrgID] = tl
	}

	result := make([]tenantResponse, 0, len(orgs))
	for _, org := range orgs {
		resp := tenantResponse{
			Organization:  org,
			LicenceStatus: "active", // backward-compat default for orgs without a licence row
		}
		if tl, ok := licenceByOrg[org.ID]; ok {
			resp.LicenceStatus = tl.Status
			exp := tl.ExpiresAt
			resp.ExpiresAt = &exp
		}
		result = append(result, resp)
	}
	writeJSON(w, http.StatusOK, result)
}

// handleGetPlatformTenant returns a single org with its licence status.
// GET /api/v1/platform/tenants/{id}
func (s *Server) handleGetPlatformTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	org, err := s.store.GetOrg(r.Context(), id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		log.Printf("get platform tenant %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := tenantResponse{
		Organization:  *org,
		LicenceStatus: "active", // backward-compat default
	}

	tl, err := s.store.GetTenantLicence(r.Context(), id)
	if err == nil && tl != nil {
		resp.LicenceStatus = tl.Status
		exp := tl.ExpiresAt
		resp.ExpiresAt = &exp
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleCreatePlatformTenant provisions a new tenant org and activates a
// licence seat from the Licence Portal.
// POST /api/v1/platform/tenants
// Body: {"licenceKey":"...","adminName":"...","adminEmail":"..."}
func (s *Server) handleCreatePlatformTenant(w http.ResponseWriter, r *http.Request) {
	if s.licencePortalClient == nil {
		writeError(w, http.StatusServiceUnavailable, "licence portal not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		LicenceKey  string `json:"licenceKey"`
		AdminName   string `json:"adminName"`
		AdminEmail  string `json:"adminEmail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.LicenceKey = strings.TrimSpace(req.LicenceKey)
	req.AdminName = strings.TrimSpace(req.AdminName)
	req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))

	if req.LicenceKey == "" || req.AdminName == "" || req.AdminEmail == "" {
		writeError(w, http.StatusBadRequest, "licenceKey, adminName and adminEmail are required")
		return
	}
	if err := validUserEmail(req.AdminEmail); err != nil {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	inst, err := s.store.GetOrCreateInstance(r.Context())
	if err != nil {
		log.Printf("create platform tenant: get instance: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	tenantID := uuid.Must(uuid.NewV7()).String()
	machineID := inst.ID + "/" + tenantID

	activation, err := s.licencePortalClient.ActivateForTenant(req.LicenceKey, machineID)
	if err != nil {
		status, msg := classifyActivationError(err)
		writeError(w, status, msg)
		return
	}

	// Validate product scope — only "report", "bundle", or empty (pre-v2) allowed.
	scope := activation.ProductScope
	if scope != "" && scope != "report" && scope != "bundle" {
		// Licence is for a different product; release the seat immediately.
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after scope mismatch: %v", deactErr)
		}
		writeError(w, http.StatusUnprocessableEntity, "licence not valid for Report Portal")
		return
	}

	// Parse expiry; fall back to +1 year when the server returns an empty string.
	var expiresAt time.Time
	if activation.ExpiresAt != "" {
		t, parseErr := time.Parse(time.RFC3339, activation.ExpiresAt)
		if parseErr == nil {
			expiresAt = t
		}
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(365 * 24 * time.Hour)
	}

	now := time.Now().UTC()

	org := &store.Organization{
		ID:        tenantID,
		Name:      req.AdminEmail, // default name; can be updated via org settings
		LicenceID: req.LicenceKey,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateOrg(r.Context(), org); err != nil {
		log.Printf("create platform tenant: create org: %v", err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after org create failure: %v", deactErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	tl := &store.TenantLicence{
		OrgID:       tenantID,
		LicenceID:   req.LicenceKey,
		Token:       activation.Token,
		ActivatedAt: now,
		ExpiresAt:   expiresAt,
		Status:      "active",
	}
	if err := s.store.UpsertTenantLicence(r.Context(), tl); err != nil {
		log.Printf("create platform tenant: upsert tenant licence: %v", err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after licence upsert failure: %v", deactErr)
		}
		if delErr := s.store.DeleteOrg(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete org after licence upsert failure: %v", delErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Create the first org_admin user.
	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("create platform tenant: gen temp password: %v", err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after password gen failure: %v", deactErr)
		}
		if delErr := s.store.DeleteTenantLicence(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete licence after password gen failure: %v", delErr)
		}
		if delErr := s.store.DeleteOrg(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete org after password gen failure: %v", delErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("create platform tenant: bcrypt: %v", err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after bcrypt failure: %v", deactErr)
		}
		if delErr := s.store.DeleteTenantLicence(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete licence after bcrypt failure: %v", delErr)
		}
		if delErr := s.store.DeleteOrg(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete org after bcrypt failure: %v", delErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	adminUser := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              tenantID,
		Email:              req.AdminEmail,
		Name:               req.AdminName,
		Role:               "org_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		InvitedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(r.Context(), adminUser); err != nil {
		log.Printf("create platform tenant: create admin user: %v", err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("create platform tenant: cleanup deactivate after user create failure: %v", deactErr)
		}
		if delErr := s.store.DeleteTenantLicence(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete licence after user create failure: %v", delErr)
		}
		if delErr := s.store.DeleteOrg(r.Context(), tenantID); delErr != nil {
			log.Printf("create platform tenant: cleanup delete org after user create failure: %v", delErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Non-fatal: send invite email if mailer is configured.
	if s.config.Mailer != nil {
		if mailErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      req.AdminEmail,
			ToName:       req.AdminName,
			OrgName:      org.Name,
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		}); mailErr != nil {
			log.Printf("create platform tenant: mailer: %v", mailErr)
		}
	}

	s.writeAudit(r, auditOrgProvision, tenantID, map[string]any{
		"adminEmail":      req.AdminEmail,
		"licenceKeyPrefix": req.LicenceKey[:min(8, len(req.LicenceKey))] + "…",
	})

	resp := tenantResponse{
		Organization:  *org,
		LicenceStatus: tl.Status,
		ExpiresAt:     &expiresAt,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleRenewTenantLicence replaces a tenant's licence with a new key.
// POST /api/v1/platform/tenants/{id}/renew
// Body: {"licenceKey":"..."}
func (s *Server) handleRenewTenantLicence(w http.ResponseWriter, r *http.Request) {
	if s.licencePortalClient == nil {
		writeError(w, http.StatusServiceUnavailable, "licence portal not configured")
		return
	}

	id := chi.URLParam(r, "id")

	if _, err := s.store.GetOrg(r.Context(), id); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		log.Printf("renew tenant licence %s: get org: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		LicenceKey string `json:"licenceKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.LicenceKey = strings.TrimSpace(req.LicenceKey)
	if req.LicenceKey == "" {
		writeError(w, http.StatusBadRequest, "licenceKey is required")
		return
	}

	inst, err := s.store.GetOrCreateInstance(r.Context())
	if err != nil {
		log.Printf("renew tenant licence %s: get instance: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	machineID := inst.ID + "/" + id

	activation, err := s.licencePortalClient.ActivateForTenant(req.LicenceKey, machineID)
	if err != nil {
		status, msg := classifyActivationError(err)
		writeError(w, status, msg)
		return
	}

	// Validate product scope — only "report", "bundle", or empty (pre-v2) allowed.
	if activation.ProductScope != "report" && activation.ProductScope != "bundle" && activation.ProductScope != "" {
		_ = s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID)
		writeError(w, http.StatusUnprocessableEntity, "licence not valid for Report Portal")
		return
	}

	// If there's an existing licence that differs, deactivate the old seat.
	existing, existErr := s.store.GetTenantLicence(r.Context(), id)
	if existErr == nil && existing != nil && existing.LicenceID != req.LicenceKey {
		oldMachineID := inst.ID + "/" + id
		if deactErr := s.licencePortalClient.DeactivateForTenant(existing.LicenceID, oldMachineID); deactErr != nil {
			log.Printf("renew tenant licence %s: deactivate old licence %s: %v", id, existing.LicenceID, deactErr)
		}
	}

	var expiresAt time.Time
	if activation.ExpiresAt != "" {
		t, parseErr := time.Parse(time.RFC3339, activation.ExpiresAt)
		if parseErr == nil {
			expiresAt = t
		}
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(365 * 24 * time.Hour)
	}

	now := time.Now().UTC()
	tl := &store.TenantLicence{
		OrgID:       id,
		LicenceID:   req.LicenceKey,
		Token:       activation.Token,
		ActivatedAt: now,
		ExpiresAt:   expiresAt,
		RenewedAt:   &now,
		Status:      "active",
	}
	if err := s.store.UpsertTenantLicence(r.Context(), tl); err != nil {
		log.Printf("renew tenant licence %s: upsert: %v", id, err)
		if deactErr := s.licencePortalClient.DeactivateForTenant(req.LicenceKey, machineID); deactErr != nil {
			log.Printf("renew tenant licence %s: cleanup deactivate after upsert failure: %v", id, deactErr)
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, auditLicenceRenew, id, map[string]any{
		"licenceKeyPrefix": req.LicenceKey[:min(8, len(req.LicenceKey))] + "…",
	})

	writeJSON(w, http.StatusOK, tl)
}

// handleDeletePlatformTenant removes a tenant org and releases its licence seat.
// DELETE /api/v1/platform/tenants/{id}
func (s *Server) handleDeletePlatformTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Best-effort licence deactivation — don't fail the delete if the portal is down.
	if s.licencePortalClient != nil {
		inst, instErr := s.store.GetOrCreateInstance(r.Context())
		if instErr == nil {
			tl, tlErr := s.store.GetTenantLicence(r.Context(), id)
			if tlErr == nil && tl != nil {
				machineID := inst.ID + "/" + id
				if deactErr := s.licencePortalClient.DeactivateForTenant(tl.LicenceID, machineID); deactErr != nil {
					log.Printf("delete platform tenant %s: deactivate licence: %v", id, deactErr)
				}
			}
		} else {
			log.Printf("delete platform tenant %s: get instance for deactivation: %v", id, instErr)
		}
	}

	if err := s.store.DeleteOrg(r.Context(), id); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		log.Printf("delete platform tenant %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, auditOrgDelete, id, nil)

	w.WriteHeader(http.StatusNoContent)
}

// classifyActivationError maps Licence Portal client errors to HTTP status
// codes and human-readable messages suitable for API responses.
func classifyActivationError(err error) (int, string) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "licence not found"):
		return http.StatusNotFound, "licence not found"
	case strings.Contains(msg, "no seats available"):
		return http.StatusUnprocessableEntity, "no seats available"
	case strings.Contains(msg, "activation denied"):
		if strings.Contains(msg, "revoked") {
			return http.StatusUnprocessableEntity, "licence revoked"
		}
		if strings.Contains(msg, "expired") {
			return http.StatusUnprocessableEntity, "licence expired"
		}
		return http.StatusUnprocessableEntity, msg
	default:
		return http.StatusServiceUnavailable, "licence server unavailable"
	}
}
