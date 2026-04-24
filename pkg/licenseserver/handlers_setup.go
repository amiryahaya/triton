package licenseserver

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
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// GET /api/v1/setup/status
// Public endpoint — reports whether the DB has any users yet. The
// frontend calls this on first SPA boot to decide whether to show the
// setup wizard vs. the login page.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		log.Printf("setup status: count users: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": n == 0})
}

type firstAdminRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// POST /api/v1/setup/first-admin
// Public endpoint gated by empty-DB check inside the handler. Creates
// the first platform_admin with a generated temp password, emails the
// invite via the configured Mailer (if any), and returns the temp
// password in the body as a fallback for operators without mail wiring.
func (s *Server) handleFirstAdminSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		log.Printf("setup: count users: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "setup already completed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req firstAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if tooLong(name, maxNameLen) {
		writeError(w, http.StatusBadRequest, "name exceeds maximum length")
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
	user := &licensestore.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		Email:              email,
		Name:               name,
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Message)
			return
		}
		log.Printf("setup: create user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	emailSent := false
	if s.config.Mailer != nil {
		mErr := s.config.Mailer.SendInviteEmail(r.Context(), InviteEmailData{
			ToEmail:      user.Email,
			ToName:       user.Name,
			OrgName:      "Triton License Server",
			TempPassword: tempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if mErr != nil {
			log.Printf("setup: mailer: %v (non-fatal; temp password returned in body)", mErr)
		} else {
			emailSent = true
		}
	}

	s.audit(r, "setup_first_admin", "", "", "", map[string]any{
		"user_id":    user.ID,
		"email":      user.Email,
		"email_sent": emailSent,
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":         user,
		"tempPassword": tempPassword,
		"emailSent":    emailSent,
	})
}
