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

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// Superadmin handler constants.
const (
	minPasswordLen = 12
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

// getSuperadminByID fetches a user and verifies they are a platform_admin.
// On success, returns the user with errStatus == 0. On failure, returns
// (nil, status, message) where status is the HTTP code to send. This is
// defensive — until the Task 1.1 follow-up migration tightens the CHECK
// constraint, the table could contain non-superadmin rows that this endpoint
// must not expose.
func (s *Server) getSuperadminByID(r *http.Request, id string) (user *licensestore.User, errStatus int, errMsg string) {
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		var nf *licensestore.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound, "superadmin not found"
		}
		log.Printf("get superadmin error: %v", err)
		return nil, http.StatusInternalServerError, "internal server error"
	}
	if user.Role != "platform_admin" {
		return nil, http.StatusNotFound, "superadmin not found"
	}
	return user, 0, ""
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

	existing, status, msg := s.getSuperadminByID(r, id)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	if req.Name != "" {
		if tooLong(req.Name, maxNameLen) {
			writeError(w, http.StatusBadRequest, "name exceeds maximum length")
			return
		}
		existing.Name = req.Name
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
		existing.Password = string(hashed)
	}
	// Role is never updated.

	if err := s.store.UpdateUser(r.Context(), existing); err != nil {
		log.Printf("update superadmin error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "superadmin_update", "", "", "", map[string]any{
		"user_id":          id,
		"name_changed":     req.Name != "",
		"password_changed": req.Password != "",
	})
	writeJSON(w, http.StatusOK, existing)
}

// DELETE /api/v1/admin/superadmins/{id}
func (s *Server) handleDeleteSuperadmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if _, status, msg := s.getSuperadminByID(r, id); status != 0 {
		writeError(w, status, msg)
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
	w.WriteHeader(http.StatusNoContent)
}
