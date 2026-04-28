package licenseserver

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
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
	Email string `json:"email"`
	Name  string `json:"name"`
}

type updateSuperadminRequest struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"` // omit to keep current
}

// validateEmail validates email format per RFC 5322.
func validateEmail(email string) error {
	if email == "" {
		return errors.New("valid email is required")
	}
	if tooLong(email, maxEmailLen) {
		return errors.New("email exceeds maximum length")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("valid email is required")
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
		log.Printf("create superadmin: gen temp password: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	user := &licensestore.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		Email:              email,
		Name:               name,
		Role:               "platform_admin", // forced — request body role ignored
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
		log.Printf("create superadmin error: %v", err)
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
			log.Printf("create superadmin: mailer error: %v (non-fatal)", mErr)
		} else {
			emailSent = true
		}
	}

	s.audit(r, "superadmin_create", "", "", "", map[string]any{
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

// POST /api/v1/admin/superadmins/{id}/resend-invite
func (s *Server) handleResendInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, status, msg := s.loadPlatformAdminByID(r.Context(), id)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	tempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Rotate password + flag must-change.
	update := licensestore.UserUpdate{
		ID:                 user.ID,
		Name:               user.Name,
		Password:           string(hashed),
		MustChangePassword: true,
	}
	if err := s.store.UpdateUser(r.Context(), update); err != nil {
		log.Printf("resend invite: update user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Revoke all existing sessions — stolen tokens stop immediately.
	if err := s.store.DeleteSessionsForUser(r.Context(), user.ID); err != nil {
		log.Printf("resend invite: delete sessions: %v (non-fatal)", err)
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
		if mErr == nil {
			emailSent = true
		} else {
			log.Printf("resend invite: mailer: %v", mErr)
		}
	}

	s.audit(r, "superadmin_resend_invite", "", "", "", map[string]any{
		"user_id":    user.ID,
		"email":      user.Email,
		"email_sent": emailSent,
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"tempPassword": tempPassword,
		"emailSent":    emailSent,
	})
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
		ID:                 id,
		Name:               existing.Name, // default to current
		MustChangePassword: existing.MustChangePassword,
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

	// Self-delete guard — prevents an operator from accidentally locking
	// themselves out via a typo or script error.
	if authed, ok := UserFromContext(r.Context()); ok && authed.ID == id {
		writeError(w, http.StatusConflict, "cannot delete your own account")
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

	// Revoke all sessions so a deleted user's tokens stop immediately.
	if err := s.store.DeleteSessionsForUser(r.Context(), id); err != nil {
		log.Printf("delete superadmin: revoke sessions: %v (non-fatal)", err)
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
