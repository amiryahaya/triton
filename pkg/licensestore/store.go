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

	// Licenses
	CreateLicense(ctx context.Context, lic *LicenseRecord) error
	GetLicense(ctx context.Context, id string) (*LicenseRecord, error)
	ListLicenses(ctx context.Context, filter LicenseFilter) ([]LicenseRecord, error)
	RevokeLicense(ctx context.Context, id, revokedBy string) error

	// Activations
	Activate(ctx context.Context, act *Activation) error
	Deactivate(ctx context.Context, licenseID, machineID string) error
	GetActivation(ctx context.Context, id string) (*Activation, error)
	GetActivationByMachine(ctx context.Context, licenseID, machineID string) (*Activation, error)
	ListActivations(ctx context.Context, filter ActivationFilter) ([]Activation, error)
	CountActiveSeats(ctx context.Context, licenseID string) (int, error)
	UpdateLastSeen(ctx context.Context, id string) error

	// Audit
	WriteAudit(ctx context.Context, entry *AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)

	// Stats
	DashboardStats(ctx context.Context) (*DashboardStats, error)

	// Lifecycle
	TruncateAll(ctx context.Context) error
	Close() error
}

// Organization represents a customer organization.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Contact   string    `json:"contact"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
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

	// Populated by joins, not stored directly.
	OrgName    string `json:"orgName,omitempty"`
	SeatsUsed  int    `json:"seatsUsed,omitempty"`
	IsExpired  bool   `json:"isExpired,omitempty"`
}

// Activation represents a machine activation record.
type Activation struct {
	ID            string     `json:"id"`
	LicenseID     string     `json:"licenseID"`
	MachineID     string     `json:"machineID"`
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Arch          string     `json:"arch"`
	Token         string     `json:"token"`
	ActivatedAt   time.Time  `json:"activatedAt"`
	LastSeenAt    time.Time  `json:"lastSeenAt"`
	DeactivatedAt *time.Time `json:"deactivatedAt,omitempty"`
	Active        bool       `json:"active"`
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

// LicenseFilter filters license listings.
type LicenseFilter struct {
	OrgID  string
	Tier   string
	Status string // "active", "revoked", "expired"
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
	return fmt.Sprintf("all seats occupied for license %s (%d/%d)", e.LicenseID, e.Used, e.Seats)
}

// ErrConflict is returned for constraint violations (e.g. org has licenses).
type ErrConflict struct {
	Message string
}

func (e *ErrConflict) Error() string {
	return e.Message
}
