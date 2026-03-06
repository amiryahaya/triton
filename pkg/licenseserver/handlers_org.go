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
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
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

	s.audit(r, "org_create", "", org.ID, "", nil)
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
