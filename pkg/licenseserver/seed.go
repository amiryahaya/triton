package licenseserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// SeedInitialSuperadmin creates a platform_admin user if the users table is
// empty. Returns (true, nil) if a user was created, (false, nil) if the table
// already had at least one user, or (false, err) on validation/store errors.
//
// The same email/password validation rules as the admin CRUD endpoint apply
// (Task 1.4): valid-looking email, password ≥ 12 characters, bcrypt hashed.
//
// Intended to be called once at license server startup. Idempotent — safe to
// call on every boot.
func SeedInitialSuperadmin(ctx context.Context, store licensestore.Store, email, password string) (bool, error) {
	count, err := store.CountUsers(ctx)
	if err != nil {
		return false, fmt.Errorf("counting users: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	email = strings.ToLower(strings.TrimSpace(email))
	if err := validateEmail(email); err != nil {
		return false, err
	}
	if len(password) < minPasswordLen {
		return false, fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("hashing password: %w", err)
	}

	now := time.Now().UTC()
	user := &licensestore.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Email:     email,
		Name:      "Platform Admin",
		Role:      "platform_admin",
		Password:  string(hashed),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateUser(ctx, user); err != nil {
		return false, fmt.Errorf("creating initial superadmin: %w", err)
	}
	return true, nil
}
