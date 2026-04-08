package licenseserver

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// CreateOrgResponse is the unified response shape for POST /api/v1/admin/orgs.
// The Admin field is always present in the struct (by design — a consistent
// shape is easier for OpenAPI/typed clients), but is nil in the JSON when
// the request did not request admin provisioning (via the omitempty tag on
// a pointer field — nil pointers are omitted).
//
// Previously this endpoint had two different response shapes depending on
// whether admin_email was supplied. Unified per Phase 1.7/1.8 architecture
// review Arch #8.
type CreateOrgResponse struct {
	Org   *licensestore.Organization `json:"org"`
	Admin *CreateOrgAdminBlock       `json:"admin,omitempty"`
}

// CreateOrgAdminBlock is the admin-invite block returned when the request
// asked for admin provisioning. TempPassword is plaintext and is returned
// exactly once — callers must capture it or email delivery must succeed.
// EmailDelivered is true when the Mailer reported success; false means
// the caller must deliver the temp password manually.
type CreateOrgAdminBlock struct {
	Email          string `json:"email"`
	TempPassword   string `json:"temp_password"`
	EmailDelivered bool   `json:"email_delivered"`
}

// POST /api/v1/admin/orgs
//
// Creates an organization in the license server. If admin_email and
// admin_name are supplied AND a report server is configured, also
// provisions the org on the report server and sends the invite email.
//
// The handler is a thin adapter: it parses and validates the request,
// delegates the work to ProvisionOrgWithAdmin (which encapsulates the
// cross-server call, rollback, and email logic), and writes the
// unified response. All business logic lives in provisioning.go.
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

	// If the caller supplied admin invite fields, validate them before
	// anything hits the store or the report server. Email normalization
	// + format check + name length. Without these, user-controlled
	// strings would flow into the email body (header injection risk)
	// and the user table.
	wantProvision := req.AdminEmail != "" || req.AdminName != ""
	if wantProvision {
		if req.AdminEmail == "" || req.AdminName == "" {
			writeError(w, http.StatusBadRequest, "admin_email and admin_name must be supplied together")
			return
		}
		req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))
		if err := validateEmail(req.AdminEmail); err != nil {
			writeError(w, http.StatusBadRequest, "invalid admin_email: "+err.Error())
			return
		}
		if tooLong(req.AdminName, maxNameLen) {
			writeError(w, http.StatusBadRequest, "admin_name exceeds maximum length")
			return
		}
	}

	result, status, err := s.ProvisionOrgWithAdmin(r.Context(), ProvisionOrgInput{
		Name:       req.Name,
		Contact:    req.Contact,
		Notes:      req.Notes,
		AdminEmail: req.AdminEmail,
		AdminName:  req.AdminName,
	})
	if status != 0 {
		// Map service-layer status into HTTP. The service already logged
		// the underlying error; we surface a user-facing message here.
		var conflict *licensestore.ErrConflict
		switch {
		case errors.As(err, &conflict):
			writeError(w, http.StatusConflict, conflict.Message)
		case status == 503:
			writeError(w, http.StatusServiceUnavailable, "report server not configured; cannot provision admin")
		case status == 502:
			writeError(w, http.StatusBadGateway, "report server provisioning failed")
		case status == 500:
			writeError(w, http.StatusInternalServerError, "internal server error")
		default:
			writeError(w, status, http.StatusText(status))
		}
		return
	}

	s.audit(r, "org_create", "", result.Org.ID, "", nil)

	// Build the unified response shape. Admin is nil (and omitted via
	// omitempty) when the request had no admin fields.
	resp := CreateOrgResponse{Org: result.Org}
	if result.Admin != nil {
		resp.Admin = &CreateOrgAdminBlock{
			Email:          result.Admin.Email,
			TempPassword:   result.Admin.TempPassword,
			EmailDelivered: result.Admin.EmailDelivered,
		}
	}
	writeJSON(w, http.StatusCreated, resp)
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
