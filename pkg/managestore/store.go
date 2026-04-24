package managestore

import (
	"context"
	"errors"
	"time"
)

// ManageUser is a Manage Portal user.
// Auth surface is completely separate from Report Server's users table.
type ManageUser struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"` // "admin" | "network_engineer"
	PasswordHash string    `json:"-"`
	MustChangePW bool      `json:"must_change_pw"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ManageSession represents an active JWT session.
type ManageSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// SetupState is the singleton row tracking Manage Server initialisation.
type SetupState struct {
	AdminCreated         bool
	LicenseActivated     bool
	LicenseServerURL     string
	LicenseKey           string
	SignedToken          string
	InstanceID           string
	PendingDeactivation  bool
	UpdatedAt            time.Time
}

// Store is the Manage Server's storage surface.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *ManageUser) error
	GetUserByEmail(ctx context.Context, email string) (*ManageUser, error)
	GetUserByID(ctx context.Context, id string) (*ManageUser, error)
	ListUsers(ctx context.Context) ([]ManageUser, error)
	UpdateUserPassword(ctx context.Context, id, newHash string) error
	CountUsers(ctx context.Context) (int64, error)
	// CountAdmins is a read-only helper (used by tests and diagnostics).
	// DeleteUser enforces the last-admin invariant atomically via a
	// subquery guard; callers use errors.Is(err, ErrLastAdmin) to
	// distinguish the guard rejection from other errors.
	CountAdmins(ctx context.Context) (int64, error)
	DeleteUser(ctx context.Context, id string) error

	// Sessions
	CreateSession(ctx context.Context, sess *ManageSession) error
	GetSessionByTokenHash(ctx context.Context, hash string) (*ManageSession, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	// Setup
	GetSetup(ctx context.Context) (*SetupState, error)
	MarkAdminCreated(ctx context.Context) error
	SaveLicenseActivation(ctx context.Context, serverURL, key, signedToken, instanceID string) error

	Close() error
}

// ErrNotFound signals a resource miss; handlers return 404.
type ErrNotFound struct{ Resource, ID string }

func (e *ErrNotFound) Error() string { return e.Resource + " not found: " + e.ID }

// ErrConflict signals a uniqueness violation or state-machine rejection.
type ErrConflict struct{ Message string }

func (e *ErrConflict) Error() string { return e.Message }

// ErrLastAdmin signals that DeleteUser blocked an admin deletion that
// would have dropped the admin count to zero. Distinct from ErrConflict
// because it represents a semantic invariant, not a uniqueness violation.
var ErrLastAdmin = errors.New("cannot delete the last admin")
