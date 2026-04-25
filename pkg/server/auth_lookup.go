package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// loadUserByID fetches any user by ID, regardless of role. Used by auth
// handlers that must work for both org users and platform admins
// (handleLogin, handleChangePassword).
func (s *Server) loadUserByID(ctx context.Context, id string) (user *store.User, errStatus int) {
	user, err := s.store.GetUser(ctx, id)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadUserByID error: %v", err)
		return nil, http.StatusInternalServerError
	}
	return user, 0
}

// loadUserByEmail fetches any user by email, regardless of role.
func (s *Server) loadUserByEmail(ctx context.Context, email string) (user *store.User, errStatus int) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			return nil, http.StatusNotFound
		}
		log.Printf("loadUserByEmail error: %v", err)
		return nil, http.StatusInternalServerError
	}
	return user, 0
}
