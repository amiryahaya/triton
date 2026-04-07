package licenseserver

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// loadPlatformAdminByID fetches a user by ID and asserts they are a
// platform_admin. On success, returns (user, 0, ""). On failure, returns
// (nil, httpStatus, message) suitable for direct use with writeError.
//
// Both "user not found" and "user found but role is not platform_admin"
// map to 404 with the same message — this prevents role enumeration via
// the admin API.
//
// This is the single source of truth for "find a superadmin by ID" used
// by the superadmin CRUD handlers AND by handleRefresh (after JWT verify).
// Consolidating it here means there's one place to fix the role-check
// logic if it ever needs to change.
func (s *Server) loadPlatformAdminByID(ctx context.Context, id string) (user *licensestore.User, errStatus int, errMsg string) {
	user, err := s.store.GetUser(ctx, id)
	if err != nil {
		var nf *licensestore.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound, "superadmin not found"
		}
		log.Printf("loadPlatformAdminByID error: %v", err)
		return nil, http.StatusInternalServerError, "internal server error"
	}
	if user.Role != "platform_admin" {
		return nil, http.StatusNotFound, "superadmin not found"
	}
	return user, 0, ""
}

// loadPlatformAdminByEmail is the email-keyed counterpart to
// loadPlatformAdminByID. Used by handleLogin to fetch the authenticating
// user with role enforcement applied at the lookup boundary.
//
// Like loadPlatformAdminByID, this returns 404-with-generic-message for
// both missing-user and wrong-role. Login callers should map that 404 to
// 401 themselves before responding to the client (because the login
// endpoint must not leak whether an email exists).
func (s *Server) loadPlatformAdminByEmail(ctx context.Context, email string) (user *licensestore.User, errStatus int, errMsg string) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		var nf *licensestore.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound, "superadmin not found"
		}
		log.Printf("loadPlatformAdminByEmail error: %v", err)
		return nil, http.StatusInternalServerError, "internal server error"
	}
	if user.Role != "platform_admin" {
		return nil, http.StatusNotFound, "superadmin not found"
	}
	return user, 0, ""
}
