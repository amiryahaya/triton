package licenseserver

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
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// Superadmin handler constants.
const (
	// minPasswordLen aliases auth.MinPasswordLength so the license
	// server stays in lockstep with the report server's policy.
	// Canonical value lives in internal/auth/password.go — raise it
	// there to propagate to every auth endpoint.
	minPasswordLen = auth.MinPasswordLength
	maxEmailLen    = 255
)

type createSuperadminRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type updateSuperadminRequest struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"` // omit to keep current
}

// validateEmail performs minimal email validation.
func validateEmail(email string) error {
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("valid email is required")
	}
	if tooLong(email, maxEmailLen) {
		return errors.New("email exceeds maximum length")
	}
	return nil
}

// getSuperadminByID is a thin adapter over loadPlatformAdminByID that
// extracts the context from an *http.Request. Kept as a method on Server
// so the existing handler call sites don't need to be reshuffled.
func (s *Server) getSuperadminByID(r *http.Request, id string) (user *licensestore.User, errStatus int, errMsg string) {
	return s.loadPlatformAdminByID(r.Context(), id)
}

// POST /api/v1/admin/superadmins
func (s *Server) handleCreateSuperadmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req createSuperadminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(req.Name, maxNameLen) {
		writeError(w, http.StatusBadRequest, "name exceeds maximum length")
		return
	}
	if len(req.Password) < minPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &licensestore.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Email:     email,
		Name:      req.Name,
		Role:      "platform_admin", // forced — request body role ignored
		Password:  string(hashed),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("create superadmin error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "superadmin_create", "", "", "", map[string]any{
		"user_id": user.ID,
		"email":   user.Email,
	})
	writeJSON(w, http.StatusCreated, user)
}

// GET /api/v1/admin/superadmins
func (s *Server) handleListSuperadmins(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), licensestore.UserFilter{Role: "platform_admin"})
	if err != nil {
		log.Printf("list superadmins error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if users == nil {
		users = []licensestore.User{} // never return null
	}
	writeJSON(w, http.StatusOK, users)
}

// GET /api/v1/admin/superadmins/{id}
func (s *Server) handleGetSuperadmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, status, msg := s.getSuperadminByID(r, id)
	if status != 0 {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// PUT /api/v1/admin/superadmins/{id}
func (s *Server) handleUpdateSuperadmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req updateSuperadminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Reject no-op updates rather than silently touching the row and
	// writing a meaningless audit entry.
	if req.Name == "" && req.Password == "" {
		writeError(w, http.StatusBadRequest, "at least one of name or password must be provided")
		return
	}

	existing, status, msg := s.getSuperadminByID(r, id)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	// Build a UserUpdate. The struct has no Role/OrgID field by design —
	// the type system enforces the immutability invariant.
	update := licensestore.UserUpdate{
		ID:   id,
		Name: existing.Name, // default to current
	}

	if req.Name != "" {
		if tooLong(req.Name, maxNameLen) {
			writeError(w, http.StatusBadRequest, "name exceeds maximum length")
			return
		}
		update.Name = req.Name
	}
	if req.Password != "" {
		if len(req.Password) < minPasswordLen {
			writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("bcrypt error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		update.Password = string(hashed)
	}

	if err := s.store.UpdateUser(r.Context(), update); err != nil {
		log.Printf("update superadmin error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Re-fetch so the response reflects the persisted state.
	updated, _, _ := s.getSuperadminByID(r, id)

	s.audit(r, "superadmin_update", "", "", "", map[string]any{
		"user_id":          id,
		"name_changed":     req.Name != "",
		"password_changed": req.Password != "",
	})
	writeJSON(w, http.StatusOK, updated)
}

// DELETE /api/v1/admin/superadmins/{id}
func (s *Server) handleDeleteSuperadmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if _, status, msg := s.getSuperadminByID(r, id); status != 0 {
		writeError(w, status, msg)
		return
	}

	// Prevent lockout by refusing to delete the last platform_admin.
	// Without this guard, an operator who deletes all admins would have
	// no way to regain access short of directly editing the database.
	admins, err := s.store.ListUsers(r.Context(), licensestore.UserFilter{Role: "platform_admin"})
	if err != nil {
		log.Printf("delete superadmin: list check error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if len(admins) <= 1 {
		writeError(w, http.StatusConflict, "cannot delete the last superadmin")
		return
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		log.Printf("delete superadmin error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "superadmin_delete", "", "", "", map[string]any{
		"user_id": id,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
