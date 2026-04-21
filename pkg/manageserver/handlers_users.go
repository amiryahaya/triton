package manageserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/managestore"
)

// SeatCapGuard is the narrow licence-guard surface consulted by
// handleCreateUser before it writes a new user row. Kept deliberately
// small so tests can inject a one-method fake without constructing a
// real *license.Guard. Exported so manageserver_test tests can define
// a matching fake from the _test package.
//
// A nil guard means "no licence configured" (free-tier default via
// seatCapGuardLimit) — treated as unlimited here because users are
// the lowest-risk resource to leak-guard against; the operator still
// has to authenticate as an admin to hit this endpoint.
type SeatCapGuard interface {
	LimitCap(metric, window string) int64
}

// seatCapGuardLimit reads LimitCap from g, returning -1 (unlimited)
// when g is nil. Centralising the nil-check here keeps the handler
// body free of `if g != nil` noise and mirrors the pattern the other
// Batch H handlers use inside their packages.
func seatCapGuardLimit(g SeatCapGuard, metric, window string) int64 {
	if g == nil {
		return -1
	}
	return g.LimitCap(metric, window)
}

// resolveSeatCapGuard returns the guard the handler should consult for
// seat-cap enforcement. Tests swap in a fake via
// SetSeatCapGuardForTest; production runs fall through to the real
// *license.Guard wired by startLicence.
//
// Reading from a mu-held pointer means a concurrent /setup/license
// activation that rotates the licence can't leave the handler with a
// half-initialised view.
func (s *Server) resolveSeatCapGuard() SeatCapGuard {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.seatCapGuardOverride != nil {
		return s.seatCapGuardOverride
	}
	if s.licenceGuard == nil {
		return nil
	}
	return s.licenceGuard
}

// generateTempPassword returns a base64url-encoded 18-byte random
// string (24 chars, no padding). Meets the validatePassword policy of
// "≥ 12 chars + one digit" by construction — base64 always produces at
// least one digit in 24 chars of random data, but we append one just
// to be safe against the astronomically unlikely all-letter case.
func generateTempPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// base64url without padding — url-safe so admins can paste the
	// temp password into chat/email without escaping.
	pw := base64.RawURLEncoding.EncodeToString(buf)
	// Defence-in-depth: ensure at least one digit is present so
	// validatePassword can't reject the generated temp. Collision with
	// an existing digit is harmless.
	return pw + "0", nil
}

// createUserRequest is the body shape for POST /api/v1/admin/users.
// Role defaults to "network_engineer" when empty; explicit "admin"
// values are honoured so the admin can seed additional admins.
type createUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// validateCreateUser enforces the handler-layer invariants before the
// row reaches the store: email is required, role (if supplied) must be
// one of the known values. Matches the invariants the DB check
// constraint on manage_users.role would ultimately enforce; catching
// them early keeps 400s separate from 500s.
func validateCreateUser(req createUserRequest) error {
	if strings.TrimSpace(req.Email) == "" {
		return errors.New("email is required")
	}
	switch req.Role {
	case "", "admin", "network_engineer":
		// empty is allowed — defaults to network_engineer
	default:
		return errors.New("role must be 'admin' or 'network_engineer'")
	}
	return nil
}

// handleCreateUser is POST /api/v1/admin/users. Gated by RequireRole("admin")
// upstream. Enforces the `seats/total` licence cap before inserting the
// row: if LimitCap returns a non-negative value, we refuse when the
// current user count + 1 would exceed it.
//
// Password is auto-generated and returned in the 201 response body as
// `temp_password`. In production, SMTP delivery replaces the in-body
// return; here we keep it simple so the admin UI has something to
// display until the mail plumbing lands.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateCreateUser(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Licence seat cap. `seats/total` semantics: the cap is the total
	// number of live user rows. We read the current count and reject
	// when adding one would exceed it. Non-nil guard + non-negative
	// cap is the only path that gates; nil guard or -1 cap means
	// unlimited.
	if limit := seatCapGuardLimit(s.resolveSeatCapGuard(), "seats", "total"); limit >= 0 {
		cur, err := s.store.CountUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "count users failed")
			return
		}
		if cur+1 > limit {
			writeError(w, http.StatusForbidden, "licence seat cap exceeded")
			return
		}
	}

	tempPW, err := generateTempPassword()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate temp password failed")
		return
	}
	hash, err := HashPassword(tempPW)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}

	role := req.Role
	if role == "" {
		role = "network_engineer"
	}

	user := &managestore.ManageUser{
		Email:        strings.TrimSpace(req.Email),
		Name:         strings.TrimSpace(req.Name),
		Role:         role,
		PasswordHash: hash,
		MustChangePW: true,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var cf *managestore.ErrConflict
		if errors.As(err, &cf) {
			writeError(w, http.StatusConflict, cf.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "create user failed")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"role":           user.Role,
		"must_change_pw": true,
		"temp_password":  tempPW,
	})
}

// handleListUsers is GET /api/v1/admin/users/. Gated by
// RequireRole("admin") upstream. Returns a JSON array of users
// ordered newest-first; password_hash is never serialised thanks to
// the `json:"-"` tag on managestore.ManageUser.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list users failed")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// handleDeleteUser is DELETE /api/v1/admin/users/{id}. Gated by
// RequireRole("admin") upstream. Guard order:
//
//  1. Bad UUID → 400
//  2. Missing caller → 500 + log (router misconfiguration, not a client error)
//  3. Self-delete → 403
//  4. Target not found (via GetUserByID) → 404
//  5. DeleteUser (store-level atomic guard) → 409 on ErrLastAdmin, else 204
//
// The last-admin invariant is enforced atomically inside DeleteUser via a
// subquery guard, closing the TOCTOU race that a handler-level
// CountAdmins → DeleteUser sequence would leave open.
//
// Session rows for the deleted user are cleaned up automatically
// by the ON DELETE CASCADE on manage_sessions.user_id (migration v2).
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	caller := userFromContext(r)
	if caller == nil {
		// Defensive — jwtAuth should have populated this. Reaching this
		// branch indicates a router misconfiguration (handler wired
		// outside the auth middleware chain), not a client auth failure.
		log.Printf("manageserver: handleDeleteUser: no user in context; middleware may be misconfigured")
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if caller.ID == id {
		writeError(w, http.StatusForbidden, "cannot delete your own account")
		return
	}

	_, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		var nf *managestore.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, managestore.ErrLastAdmin) {
			writeError(w, http.StatusConflict, "cannot delete the last admin")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete user failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
