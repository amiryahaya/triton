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

	"github.com/amiryahaya/triton/pkg/store"
)

const (
	maxUserNameLen  = 255
	maxUserEmailLen = 255
)

type createUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

type updateUserRequest struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"` // empty = unchanged
}

// validUserEmail performs minimal email validation, mirroring the license
// server's superadmin validation rules.
func validUserEmail(email string) error {
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("valid email is required")
	}
	if len(email) > maxUserEmailLen {
		return errors.New("email exceeds maximum length")
	}
	return nil
}

// loadOrgScopedUser fetches a user by ID and asserts they belong to the
// requesting admin's org. Used by GET/PUT/DELETE handlers to enforce
// tenant isolation. Returns (user, 0) on success, (nil, status) on failure.
//
// Tenant isolation: an org_admin in org A who tries to act on a user in
// org B gets the same 404 they'd get for a missing user — never leak
// the existence of out-of-scope users.
func (s *Server) loadOrgScopedUser(r *http.Request, id string) (target *store.User, errStatus int) {
	requester := UserFromContext(r.Context())
	if requester == nil {
		return nil, http.StatusUnauthorized
	}
	target, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadOrgScopedUser: get error: %v", err)
		return nil, http.StatusInternalServerError
	}
	if target.OrgID != requester.OrgID {
		return nil, http.StatusNotFound
	}
	return target, 0
}

// POST /api/v1/users
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validUserEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Name) > maxUserNameLen {
		writeError(w, http.StatusBadRequest, "name exceeds maximum length")
		return
	}
	if req.Role != "org_admin" && req.Role != "org_user" {
		writeError(w, http.StatusBadRequest, "role must be org_admin or org_user")
		return
	}
	if len(req.Password) < minUserPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("create user: bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &store.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     requester.OrgID, // forced — admin can only create within own org
		Email:     email,
		Name:      req.Name,
		Role:      req.Role,
		Password:  string(hashed),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *store.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, "user with this email already exists")
			return
		}
		log.Printf("create user: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// GET /api/v1/users
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: requester.OrgID})
	if err != nil {
		log.Printf("list users: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if users == nil {
		users = []store.User{} // never null
	}
	writeJSON(w, http.StatusOK, users)
}

// GET /api/v1/users/{id}
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, status := s.loadOrgScopedUser(r, id)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// PUT /api/v1/users/{id}
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" && req.Password == "" {
		writeError(w, http.StatusBadRequest, "at least one of name or password must be provided")
		return
	}

	existing, status := s.loadOrgScopedUser(r, id)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}

	update := store.UserUpdate{
		ID:   id,
		Name: existing.Name, // default to current
	}
	if req.Name != "" {
		if len(req.Name) > maxUserNameLen {
			writeError(w, http.StatusBadRequest, "name exceeds maximum length")
			return
		}
		update.Name = req.Name
	}
	if req.Password != "" {
		if len(req.Password) < minUserPasswordLen {
			writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("update user: bcrypt error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		update.Password = string(hashed)
	}

	if err := s.store.UpdateUser(r.Context(), update); err != nil {
		log.Printf("update user: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	updated, _ := s.loadOrgScopedUser(r, id)
	writeJSON(w, http.StatusOK, updated)
}

// DELETE /api/v1/users/{id}
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Block self-deletion. Without this, an admin can lock themselves
	// out and (worse) leave their org with no admin if they were the last.
	if id == requester.ID {
		writeError(w, http.StatusConflict, "cannot delete yourself")
		return
	}

	target, status := s.loadOrgScopedUser(r, id)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}

	// Block deletion of the last org_admin in this org. Mirrors the
	// license server's last-superadmin-lockout guard (H3 lesson).
	if target.Role == "org_admin" {
		users, err := s.store.ListUsers(r.Context(), store.UserFilter{
			OrgID: requester.OrgID,
			Role:  "org_admin",
		})
		if err == nil && len(users) <= 1 {
			writeError(w, http.StatusConflict, "cannot delete the last org_admin")
			return
		}
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		log.Printf("delete user: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
