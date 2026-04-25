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

// GET /api/v1/platform/admins
func (s *Server) handleListPlatformAdmins(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: store.PlatformOrgFilter})
	if err != nil {
		log.Printf("list platform admins: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if users == nil {
		users = []store.User{} // never null
	}
	writeJSON(w, http.StatusOK, users)
}

// POST /api/v1/platform/admins
// Body: {"name": "...", "email": "..."}
func (s *Server) handleInvitePlatformAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	name := strings.TrimSpace(req.Name)
	if email == "" || name == "" {
		writeError(w, http.StatusBadRequest, "name and email are required")
		return
	}
	if err := validUserEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("invite platform admin: gen temp password: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("invite platform admin: bcrypt: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              "", // platform_admin has no org
		Email:              email,
		Name:               name,
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		InvitedAt:          now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *store.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, "email already in use")
			return
		}
		log.Printf("invite platform admin: create user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, auditUserCreate, user.ID, map[string]any{
		"email": email,
		"role":  "platform_admin",
	})

	w.Header().Set("Cache-Control", "no-store")

	resp := map[string]string{"id": user.ID}
	if s.config.Mailer != nil {
		mailErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      email,
			ToName:       name,
			OrgName:      "Report Portal",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if mailErr != nil {
			log.Printf("invite platform admin: mailer: %v", mailErr)
			resp["tempPassword"] = tempPassword
		}
	} else {
		resp["tempPassword"] = tempPassword
	}
	writeJSON(w, http.StatusCreated, resp)
}

// DELETE /api/v1/platform/admins/{id}
func (s *Server) handleDeletePlatformAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	claims := ClaimsFromContext(r.Context())
	if claims != nil && claims.Sub == id {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	target, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "admin not found")
			return
		}
		log.Printf("delete platform admin get: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if target.Role != "platform_admin" {
		writeError(w, http.StatusNotFound, "admin not found")
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "admin not found")
			return
		}
		log.Printf("delete platform admin: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.sessionCache.DeleteByUserID(id)
	s.writeAudit(r, auditUserDelete, id, map[string]any{"role": "platform_admin"})
	w.WriteHeader(http.StatusNoContent)
}
