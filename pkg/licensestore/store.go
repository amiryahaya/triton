package licensestore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Store defines the persistence interface for the license server.
type Store interface {
	// Organizations
	CreateOrg(ctx context.Context, org *Organization) error
	GetOrg(ctx context.Context, id string) (*Organization, error)
	ListOrgs(ctx context.Context) ([]Organization, error)
	UpdateOrg(ctx context.Context, org *Organization) error
	DeleteOrg(ctx context.Context, id string) error
	SuspendOrg(ctx context.Context, id string, suspended bool) error

	// Licenses
	CreateLicense(ctx context.Context, lic *LicenseRecord) error
	GetLicense(ctx context.Context, id string) (*LicenseRecord, error)
	ListLicenses(ctx context.Context, filter LicenseFilter) ([]LicenseRecord, error)
	RevokeLicense(ctx context.Context, id, revokedBy string) error
	UpdateLicense(ctx context.Context, id string, upd LicenseUpdate) error

	// ListExpiringLicenses returns non-revoked licenses whose expires_at falls
	// between NOW() and NOW()+within. Includes notified_*d_at so callers can
	// filter without a second query.
	ListExpiringLicenses(ctx context.Context, within time.Duration) ([]LicenseWithOrg, error)

	// MarkLicenseNotified sets the notified_*d_at column for the given interval
	// ("30d", "7d", or "1d") to NOW(). Returns an error for unknown intervals.
	MarkLicenseNotified(ctx context.Context, licenseID, interval string) error

	// Activations
	Activate(ctx context.Context, act *Activation) error
	Deactivate(ctx context.Context, licenseID, machineID string) error
	GetActivation(ctx context.Context, id string) (*Activation, error)
	GetActivationByMachine(ctx context.Context, licenseID, machineID string) (*Activation, error)
	ListActivations(ctx context.Context, filter ActivationFilter) ([]Activation, error)
	CountActiveSeats(ctx context.Context, licenseID string) (int, error)
	UpdateLastSeen(ctx context.Context, id string) error
	// ReapStaleActivations marks active seats as inactive when their
	// last_seen_at exceeds the given threshold. Returns the count of
	// reaped activations. Standalone non-transactional variant for
	// admin tooling and tests. The production Activate path uses an
	// internal transactional reap (reapAndRecount) instead.
	ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error)

	// Audit
	WriteAudit(ctx context.Context, entry *AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)

	// Usage
	UpsertUsage(ctx context.Context, reports []UsageReport) error
	UsageSummary(ctx context.Context, licenseID string) (map[string]map[string]int64, error)

	// Stats
	DashboardStats(ctx context.Context) (*DashboardStats, error)

	// Users
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, filter UserFilter) ([]User, error)
	UpdateUser(ctx context.Context, update UserUpdate) error
	DeleteUser(ctx context.Context, id string) error
	CountUsers(ctx context.Context) (int, error)

	// CountPlatformAdmins returns the count of users with role =
	// 'platform_admin'. Used to block last-platform-admin deletion.
	CountPlatformAdmins(ctx context.Context) (int, error)

	// DeleteSessionsForUser revokes every session belonging to the given
	// user. Called on password change, resend-invite, and delete-user so
	// stolen tokens stop working immediately.
	DeleteSessionsForUser(ctx context.Context, userID string) error

	// Sessions
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Lifecycle
	TruncateAll(ctx context.Context) error
	Close() error
}

// Organization represents a customer organization.
type Organization struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ContactName  string `json:"contact_name"`
	ContactPhone string `json:"contact_phone"`
	ContactEmail string `json:"contact_email"`
	Notes        string `json:"notes"`
	Suspended    bool   `json:"suspended"`
	// ActiveActivations and HasSeatedLicenses are read-only computed fields
	// populated by ListOrgs — never written to the database directly.
	ActiveActivations int       `json:"activeActivations"`
	HasSeatedLicenses bool      `json:"hasSeatedLicenses"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// LicenseRecord represents a license in the server database.
type LicenseRecord struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"orgID"`
	Tier      string     `json:"tier"`
	Seats     int        `json:"seats"`
	IssuedAt  time.Time  `json:"issuedAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	RevokedBy *string    `json:"revokedBy,omitempty"`
	Notes     string     `json:"notes"`
	CreatedAt time.Time  `json:"createdAt"`

	// v2 fields (migration 5). No `omitempty` on Features or Limits —
	// both types have custom MarshalJSON that emits a non-null zero
	// value (empty Features object, empty []), and the frontend relies
	// on these fields being present on every Licence. With omitempty
	// the whole key disappears for legacy licences, bypassing the
	// custom marshaller and breaking the UI (l.limits.find → undefined).
	Features      Features `json:"features"`
	Limits        Limits   `json:"limits"`
	SoftBufferPct int      `json:"soft_buffer_pct"`
	ProductScope  string   `json:"product_scope"`

	// Portal-pushed schedule fields (migration 6).
	// Schedule is an optional cron expression pushed to the agent on
	// /validate. Empty string (DB NULL) means "no override; agent uses
	// its local agent.yaml schedule/interval." See
	// docs/plans/2026-04-19-portal-pushed-schedule-design.md.
	Schedule string `json:"schedule"`

	// ScheduleJitter is the optional jitter bound in seconds applied on
	// top of the cron fire time. 0 disables. Only meaningful when
	// Schedule is non-empty.
	ScheduleJitter int `json:"scheduleJitterSeconds"`

	// Populated by joins, not stored directly. No `omitempty` so the
	// zero values still serialise — the frontend relies on these fields
	// being present on every Licence (seatsUsed=0 is a valid state for
	// a newly issued licence with no activations yet).
	OrgName   string `json:"orgName"`
	SeatsUsed int    `json:"seatsUsed"`
	IsExpired bool   `json:"isExpired"`
}

// LicenseWithOrg is a read-only projection used by the expiry notification
// goroutine. It joins the license row with the owning organization's contact
// fields so the caller can send emails without a second query.
type LicenseWithOrg struct {
	LicenseID     string
	OrgID         string
	OrgName       string
	ContactName   string
	ContactPhone  string
	ContactEmail  string
	ExpiresAt     time.Time
	Notified30dAt *time.Time
	Notified7dAt  *time.Time
	Notified1dAt  *time.Time
}

// Activation represents a machine activation record.
type Activation struct {
	ID             string     `json:"id"`
	LicenseID      string     `json:"licenseID"`
	MachineID      string     `json:"machineID"`
	Hostname       string     `json:"hostname"`
	OS             string     `json:"os"`
	Arch           string     `json:"arch"`
	Token          string     `json:"token"`
	ActivatedAt    time.Time  `json:"activatedAt"`
	LastSeenAt     time.Time  `json:"lastSeenAt"`
	DeactivatedAt  *time.Time `json:"deactivatedAt,omitempty"`
	Active         bool       `json:"active"`
	ActivationType string     `json:"activationType"`
	DisplayName    string     `json:"displayName"`
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID        int64           `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	EventType string          `json:"eventType"`
	LicenseID string          `json:"licenseID,omitempty"`
	OrgID     string          `json:"orgID,omitempty"`
	MachineID string          `json:"machineID,omitempty"`
	Actor     string          `json:"actor"`
	Details   json.RawMessage `json:"details"`
	IPAddress string          `json:"ipAddress"`
}

// DashboardStats holds aggregate statistics for the admin dashboard.
type DashboardStats struct {
	TotalOrgs        int `json:"totalOrgs"`
	TotalLicenses    int `json:"totalLicenses"`
	ActiveLicenses   int `json:"activeLicenses"`
	RevokedLicenses  int `json:"revokedLicenses"`
	ExpiredLicenses  int `json:"expiredLicenses"`
	TotalActivations int `json:"totalActivations"`
	ActiveSeats      int `json:"activeSeats"`
}

// User represents a platform or organization user.
type User struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"orgID,omitempty"` // empty = platform admin
	Email              string    `json:"email"`
	Name               string    `json:"name"`
	Role               string    `json:"role"` // platform_admin, org_admin, org_user
	Password           string    `json:"-"`    // bcrypt hash, never serialized
	MustChangePassword bool      `json:"mustChangePassword"`
	InvitedAt          time.Time `json:"invitedAt"` // when temp-password invite was last issued
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
	OrgName            string    `json:"orgName,omitempty"` // populated by joins
}

// Session represents an active user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userID"`
	TokenHash string    `json:"-"` // SHA-256 of session token, never serialized
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// UserFilter controls user listing.
type UserFilter struct {
	OrgID string
	Role  string
}

// UserUpdate is a narrow type for updating a user. By design it has no Role
// or OrgID field — those are immutable via the CRUD path. The split-identity
// model says role changes are not a legitimate runtime operation; if a user's
// role needs to change, delete and recreate. The type system enforces this:
// callers cannot supply a Role even by accident, because the field doesn't
// exist on this struct.
//
// Password is optional: an empty string means "leave unchanged".
// MustChangePassword is always written — callers that do not intend to change
// it should read the current value first and pass it through unchanged.
// ResetInvitedAt, when true, sets invited_at = NOW() — used by resend-invite
// to restart the 7-day invite expiry window.
type UserUpdate struct {
	ID                 string
	Name               string
	Password           string // empty = unchanged
	MustChangePassword bool
	ResetInvitedAt     bool
}

// LicenseFilter filters license listings.
type LicenseFilter struct {
	OrgID  string
	Tier   string
	Status string // "active", "revoked", "expired"
}

// LicenseUpdate carries optional partial-update fields for UpdateLicense.
// A nil pointer means "leave this column untouched." A non-nil pointer
// writes its value — including empty string / zero, which means "clear
// the override." This three-state convention distinguishes "don't touch"
// from "set to zero" in a JSON PATCH body.
type LicenseUpdate struct {
	Schedule       *string
	ScheduleJitter *int
}

// ActivationFilter filters activation listings.
type ActivationFilter struct {
	LicenseID string
	MachineID string
	Active    *bool
}

// AuditFilter filters audit log listings.
type AuditFilter struct {
	EventType string
	LicenseID string
	OrgID     string
	After     *time.Time
	Before    *time.Time
	Limit     int
}

// ErrNotFound is returned when a resource is not found.
type ErrNotFound struct {
	Resource string
	ID       string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("%s not found: %s", e.Resource, e.ID)
}

// ErrSeatsFull is returned when all seats are occupied.
type ErrSeatsFull struct {
	LicenseID string
	Seats     int
	Used      int
}

func (e *ErrSeatsFull) Error() string {
	return "all seats are occupied"
}

// ErrConflict is returned for constraint violations (e.g. org has licenses).
type ErrConflict struct {
	Message string
}

func (e *ErrConflict) Error() string {
	return e.Message
}

// ErrLicenseRevoked is returned when an operation targets a revoked license.
type ErrLicenseRevoked struct {
	LicenseID string
}

func (e *ErrLicenseRevoked) Error() string {
	return fmt.Sprintf("license %s has been revoked", e.LicenseID)
}

// ErrLicenseExpired is returned when an operation targets an expired license.
type ErrLicenseExpired struct {
	LicenseID string
}

func (e *ErrLicenseExpired) Error() string {
	return fmt.Sprintf("license %s has expired", e.LicenseID)
}
