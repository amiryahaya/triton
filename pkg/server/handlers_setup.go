package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/store"
)

// handleSetupStatus reports whether the platform needs first-run setup.
// GET /api/v1/setup/status — public, no auth.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: store.PlatformOrgFilter})
	if err != nil {
		log.Printf("setup status: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": len(users) == 0})
}

// handleFirstSetup creates the first platform_admin. Returns 409 if already done.
// POST /api/v1/setup — public, blocked after first use.
// Body: {"name": "Alice", "email": "alice@example.com"}
func (s *Server) handleFirstSetup(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: store.PlatformOrgFilter})
	if err != nil {
		log.Printf("setup: list users: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if len(users) > 0 {
		writeError(w, http.StatusConflict, "setup already completed")
		return
	}

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

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("setup: gen temp password: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("setup: bcrypt: %v", err)
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
		log.Printf("setup: create user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if s.config.Mailer != nil {
		if mailErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      email,
			ToName:       name,
			OrgName:      "Report Portal",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		}); mailErr != nil {
			log.Printf("setup: mailer: %v", mailErr)
			// Non-fatal: admin receives the temp password in the response body.
		}
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":           user.ID,
		"tempPassword": tempPassword,
	})
}
