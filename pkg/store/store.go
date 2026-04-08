package store

import (
	"context"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// ScanStore is the persistence interface for scan results.
type ScanStore interface {
	// SaveScan persists a complete scan result.
	SaveScan(ctx context.Context, result *model.ScanResult) error

	// GetScan retrieves a scan result by ID.
	// If orgID is non-empty, the scan must belong to that org (tenant isolation).
	GetScan(ctx context.Context, id, orgID string) (*model.ScanResult, error)

	// ListScans returns scan summaries matching the given filter.
	ListScans(ctx context.Context, filter ScanFilter) ([]ScanSummary, error)

	// DeleteScan removes a scan result by ID.
	// If orgID is non-empty, the scan must belong to that org (tenant isolation).
	DeleteScan(ctx context.Context, id, orgID string) error
}

// HashStore is the file-hash caching interface for incremental scanning.
type HashStore interface {
	// GetFileHash retrieves the stored hash and scan time for a file path.
	GetFileHash(ctx context.Context, path string) (hash string, scannedAt time.Time, err error)

	// SetFileHash stores (or updates) the hash for a file path.
	SetFileHash(ctx context.Context, path string, hash string) error

	// PruneStaleHashes removes file hash entries older than the given time.
	PruneStaleHashes(ctx context.Context, before time.Time) error

	// FileHashStats returns summary statistics about the file hash cache.
	FileHashStats(ctx context.Context) (count int, oldest, newest time.Time, err error)
}

// OrgStore is the persistence interface for organizations on the report
// server. The report server's organizations table mirrors the license
// server's authoritative one — provisioning happens via Phase 1.5b's
// receiver endpoint, not directly here.
type OrgStore interface {
	CreateOrg(ctx context.Context, org *Organization) error
	GetOrg(ctx context.Context, id string) (*Organization, error)
	ListOrgs(ctx context.Context) ([]Organization, error)
	UpdateOrg(ctx context.Context, org *Organization) error
	DeleteOrg(ctx context.Context, id string) error
}

// UserStore is the persistence interface for org users on the report
// server. Roles are restricted to org_admin and org_user — platform
// admins live in the license server (split-identity model, 2026-04-07
// amendment). Every user belongs to exactly one org (org_id NOT NULL).
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, filter UserFilter) ([]User, error)
	UpdateUser(ctx context.Context, update UserUpdate) error
	DeleteUser(ctx context.Context, id string) error
	CountUsersByOrg(ctx context.Context, orgID string) (int, error)
	ResendInvite(ctx context.Context, userID, newPasswordHash string) error
}

// SessionStore is the persistence interface for user sessions on the
// report server. Mirrors the license server's session shape but lives
// in a different DB (split identity stores).
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// AuditStore is the persistence interface for report-server audit
// events. Writes are fire-and-forget from handlers; reads are
// exposed via a future admin endpoint for compliance review.
type AuditStore interface {
	WriteAudit(ctx context.Context, entry *AuditEvent) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEvent, error)
}

// Store composes all storage interfaces.
// Implementations must be safe for concurrent use.
type Store interface {
	ScanStore
	HashStore
	OrgStore
	UserStore
	SessionStore
	AuditStore

	// Close releases any resources held by the store.
	Close() error
}

// AuditEvent is a single record in the audit log. Fire-and-forget:
// failed writes log a warning but never block the triggering action,
// because audit failure should not cause a user-visible request
// failure.
type AuditEvent struct {
	ID        int64          `json:"id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	EventType string         `json:"eventType"`
	OrgID     string         `json:"orgID,omitempty"`
	ActorID   string         `json:"actorID,omitempty"`
	TargetID  string         `json:"targetID,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	IPAddress string         `json:"ipAddress,omitempty"`
}

// AuditFilter specifies criteria for ListAudit. Empty fields are
// wildcards; Limit defaults to 100, max 10000.
type AuditFilter struct {
	OrgID     string
	EventType string
	ActorID   string
	Since     *time.Time
	Until     *time.Time
	Limit     int
}

// ScanFilter specifies criteria for listing scans.
type ScanFilter struct {
	Hostname string
	After    *time.Time
	Before   *time.Time
	Profile  string
	Limit    int
	OrgID    string // Tenant isolation: if set, only return scans for this org.
}

// ScanSummary is a lightweight representation of a stored scan.
type ScanSummary struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	Timestamp     time.Time `json:"timestamp"`
	Profile       string    `json:"profile"`
	TotalFindings int       `json:"totalFindings"`
	Safe          int       `json:"safe"`
	Transitional  int       `json:"transitional"`
	Deprecated    int       `json:"deprecated"`
	Unsafe        int       `json:"unsafe"`
}

// ErrNotFound is returned when a requested resource does not exist.
type ErrNotFound struct {
	Resource string
	ID       string
}

func (e *ErrNotFound) Error() string {
	return e.Resource + " not found: " + e.ID
}

// ErrConflict is returned when a write fails due to a uniqueness constraint
// (e.g., duplicate user email).
type ErrConflict struct {
	Message string
}

func (e *ErrConflict) Error() string {
	return e.Message
}

// Organization is a report-server mirror of an organization defined in
// the license server. Only ID, Name, and timestamps are stored — contact
// info and license details remain in the license server.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// User is a report-server org user. Distinct from licensestore.User by
// design (split-identity model): org_id is required, role is restricted
// to org_admin or org_user, and there's a must_change_password flag for
// the invite-and-first-login flow.
//
// InvitedAt is the wall-clock anchor for the Phase 5.2 invite expiry
// gate: if must_change_password is still true when invited_at + the
// configured expiry window has elapsed, handleLogin returns 401
// "invalid credentials" (not a distinct status) to avoid a credential
// oracle — see Sprint 1 review D4. Users who have completed the
// change-password flow ignore the field entirely (mcp=false
// short-circuits the expiry check).
type User struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"orgID"`
	Email              string    `json:"email"`
	Name               string    `json:"name"`
	Role               string    `json:"role"`
	Password           string    `json:"-"` // bcrypt hash, never serialized
	MustChangePassword bool      `json:"mustChangePassword"`
	InvitedAt          time.Time `json:"invitedAt"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

// UserUpdate is a narrow DTO for updating a user. By design it has no
// Role or OrgID field — those are immutable via the CRUD path. To change
// a user's role or move them between orgs, delete and recreate.
//
// Password is optional (empty = unchanged). MustChangePassword is a
// pointer so callers can distinguish "leave alone" (nil) from "set to
// false" (clear the invite flag after first login).
type UserUpdate struct {
	ID                 string
	Name               string
	Password           string // empty = unchanged
	MustChangePassword *bool  // nil = unchanged
}

// UserFilter controls user listing.
type UserFilter struct {
	OrgID string
	Role  string
}

// Session is an active user session on the report server.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userID"`
	TokenHash string    `json:"-"` // SHA-256 of session token, never serialized
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}
