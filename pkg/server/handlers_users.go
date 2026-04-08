package server

import (
	"context"
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
// given org. Used by GET/PUT/DELETE handlers to enforce tenant isolation.
// Returns (user, 0) on success, (nil, status) on failure.
//
// Tenant isolation: caller passes the requesting admin's org_id. If the
// target user is in a different org, the helper returns the same 404 it
// returns for a missing user — never leak the existence of out-of-scope
// users to a caller who shouldn't see them.
//
// Takes context.Context (not *http.Request) so it can be called from
// non-HTTP code paths (background tasks, tests, future Phase 2
// background workers). Matches the license server's Arch-5.1 pattern.
func (s *Server) loadOrgScopedUser(ctx context.Context, id, requesterOrgID string) (target *store.User, errStatus int) {
	target, err := s.store.GetUser(ctx, id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadOrgScopedUser: get error: %v", err)
		return nil, http.StatusInternalServerError
	}
	if target.OrgID != requesterOrgID {
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
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := chi.URLParam(r, "id")
	user, status := s.loadOrgScopedUser(r.Context(), id, requester.OrgID)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// PUT /api/v1/users/{id}
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
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

	existing, status := s.loadOrgScopedUser(r.Context(), id, requester.OrgID)
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

	// Re-fetch so the response reflects persisted state. If the row
	// disappeared between UpdateUser and now (e.g., a concurrent delete),
	// surface the failure rather than returning a 200 with a null body.
	updated, refetchStatus := s.loadOrgScopedUser(r.Context(), id, requester.OrgID)
	if refetchStatus != 0 {
		writeError(w, refetchStatus, "user not found")
		return
	}
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

	target, status := s.loadOrgScopedUser(r.Context(), id, requester.OrgID)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}

	// Block deletion of the last org_admin in this org. Mirrors the
	// license server's last-superadmin-lockout guard (H3 lesson).
	// A ListUsers failure must NOT silently disable the guard — surface
	// it as 500 so a transient DB error can't enable a lockout.
	if target.Role == "org_admin" {
		admins, err := s.store.ListUsers(r.Context(), store.UserFilter{
			OrgID: requester.OrgID,
			Role:  "org_admin",
		})
		if err != nil {
			log.Printf("delete user: count admins error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if len(admins) <= 1 {
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

// POST /api/v1/users/{id}/resend-invite — Phase 5.2.
//
// Rotates a pending invite for a user whose must_change_password flag
// is still set. The store layer refuses to update users who have
// already completed the first-login flow (mcp=false) so this endpoint
// can't be abused to reset a working user's password. The response
// carries the new temp password ONCE — the admin is expected to
// surface it to the invitee out-of-band.
//
// Security note (Sprint 1 review S3): returning the temp password in
// the JSON body puts credential material into HTTP response logs,
// browser devtools history, and any reverse proxy that captures
// response bodies. We set Cache-Control: no-store to prevent the
// response from being cached, and operators are expected to disable
// response-body logging on the reverse proxy layer for this route.
//
// TODO(sprint-2): integrate the license server's Resend mailer so
// the report server can push the temp password via email directly
// and drop it from the response body entirely. Tracked in the
// multi-tenant plan under "Report-server mailer integration".
func (s *Server) handleResendInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	requester := UserFromContext(r.Context())
	if requester == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Load the target to enforce tenant isolation before rotating any
	// password material. A cross-org UUID guess must surface as 404.
	target, status := s.loadOrgScopedUser(r.Context(), id, requester.OrgID)
	if status != 0 {
		writeError(w, status, "user not found")
		return
	}
	if !target.MustChangePassword {
		// Already completed their first login — resending an invite
		// would silently reset a working password, which is exactly
		// what the store-layer guard prevents but we also surface a
		// clear 409 so the admin UI can show a helpful message.
		writeError(w, http.StatusConflict, "user has already completed their first login")
		return
	}

	// Generate a fresh temp password. 24 url-safe chars = ~144 bits.
	newTempPassword, err := auth.GenerateTempPassword(24)
	if err != nil {
		log.Printf("resend invite: generate temp password error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(newTempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("resend invite: bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if err := s.store.ResendInvite(r.Context(), id, string(hashed)); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("resend invite: store error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Phase 5 Sprint 2 S2.7 — prefer mailer-based delivery when the
	// server has been configured with a Mailer. Load the org name
	// for the email greeting; failure here is non-fatal (we still
	// want to deliver the invite), so the org name falls back to
	// the org ID if the lookup fails.
	orgName := target.OrgID
	if org, err := s.store.GetOrg(r.Context(), target.OrgID); err == nil && org != nil {
		orgName = org.Name
	}

	// Cache-Control: no-store regardless of whether the password
	// ends up in the body — belt-and-braces against any future bug
	// that accidentally reintroduces it into a cached response.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if s.config.Mailer != nil {
		// Mailer delivery path — push the temp password via email
		// and return a response that does NOT contain it. This is
		// the preferred production configuration. Mailer failure is
		// treated as fatal here because the admin explicitly asked
		// for a resend; falling back to the JSON-body path would
		// leak credential material that the operator configured
		// their deployment specifically to avoid.
		mailErr := s.config.Mailer.SendInviteEmail(r.Context(), mailer.InviteEmailData{
			ToEmail:      target.Email,
			ToName:       target.Name,
			OrgName:      orgName,
			TempPassword: newTempPassword,
			LoginURL:     s.config.InviteLoginURL,
		})
		if mailErr != nil {
			log.Printf("resend invite: mailer error: %v", mailErr)
			writeError(w, http.StatusBadGateway,
				"invite password rotated but email delivery failed; contact the invitee out-of-band or retry")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":         "invite resent",
			"emailDelivered": "true",
		})
		return
	}

	// Legacy fallback — mailer not configured, return the temp
	// password in the JSON body so the admin can surface it to the
	// invitee manually. The no-store header above plus the one-time
	// nature (next call rotates it again) is our only defense here.
	writeJSON(w, http.StatusOK, map[string]string{
		"status":       "invite resent",
		"tempPassword": newTempPassword,
	})
}
