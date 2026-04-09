package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// loadOrgUserByID fetches a user by ID and asserts they are an org_admin
// or org_user (i.e., a legitimate report-server user). Returns
// (user, 0) on success, (nil, status) on failure.
//
// "Not found" and "wrong role" both map to 404 to prevent role
// enumeration. Defensive against any future state where the users table
// contains rows with unexpected role values. Callers translate the
// status into their own user-facing error message (login surfaces 401,
// other handlers may surface 404).
func (s *Server) loadOrgUserByID(ctx context.Context, id string) (user *store.User, errStatus int) {
	user, err := s.store.GetUser(ctx, id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadOrgUserByID error: %v", err)
		return nil, http.StatusInternalServerError
	}
	if user.Role != "org_admin" && user.Role != "org_user" {
		return nil, http.StatusNotFound
	}
	return user, 0
}

// loadOrgUserByEmail is the email-keyed counterpart used by handleLogin.
func (s *Server) loadOrgUserByEmail(ctx context.Context, email string) (user *store.User, errStatus int) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadOrgUserByEmail error: %v", err)
		return nil, http.StatusInternalServerError
	}
	if user.Role != "org_admin" && user.Role != "org_user" {
		return nil, http.StatusNotFound
	}
	return user, 0
}
