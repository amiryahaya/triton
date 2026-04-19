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

	// ListScansOrderedByTime returns all scan summaries for the given
	// org, sorted by timestamp ASCENDING (oldest first). This is the
	// chronological ordering required by pkg/analytics.ComputeOrgTrend.
	// The existing ListScans returns newest-first, which is the right
	// default for dashboards but wrong for trend math.
	// Returns an empty slice (not nil) when the org has no scans.
	// Analytics Phase 2.
	ListScansOrderedByTime(ctx context.Context, orgID string) ([]ScanSummary, error)

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
	AgentStore

	// SaveScanWithFindings atomically stores a scan and inserts its
	// extracted crypto findings. Marks the scan as backfilled on success
	// so the background goroutine skips it.
	SaveScanWithFindings(ctx context.Context, scan *model.ScanResult, findings []Finding) error

	// ListInventory aggregates findings into (algorithm, key_size) rows
	// for the given org, filtered to the latest scan per hostname.
	// Sorted by worst PQC status first, then instances descending.
	// Returns an empty slice (not nil) when there are no findings.
	ListInventory(ctx context.Context, orgID string, fp FilterParams) ([]InventoryRow, error)

	// ListExpiringCertificates returns findings with not_after set,
	// filtered to the latest scan per hostname, expiring within the
	// given duration from now. Already-expired certs are ALWAYS
	// included regardless of the window. Callers wanting "all future
	// expiries" pass a large duration (e.g. 100 years).
	ListExpiringCertificates(ctx context.Context, orgID string, within time.Duration, fp FilterParams) ([]ExpiringCertRow, error)

	// ListTopPriorityFindings returns the top N findings by
	// migration_priority descending, filtered to the latest scan per
	// hostname. Findings with priority 0 are excluded. limit=0 is
	// treated as limit=20.
	ListTopPriorityFindings(ctx context.Context, orgID string, limit int, fp FilterParams) ([]PriorityRow, error)

	// ListFilterOptions returns the distinct hostnames, algorithms, and
	// PQC statuses available for filtering, derived from the latest scan
	// per hostname. PQC statuses are hardcoded.
	ListFilterOptions(ctx context.Context, orgID string) (FilterOptions, error)

	// --- Analytics Pipeline (Phase 4A) ---

	// RefreshHostSummary recomputes the host_summary row for a single
	// (org, hostname) pair from the findings table. Called by pipeline T2.
	RefreshHostSummary(ctx context.Context, orgID, hostname string) error

	// RefreshOrgSnapshot recomputes the org_snapshot row for an org
	// from all host_summary rows. Called by pipeline T3.
	RefreshOrgSnapshot(ctx context.Context, orgID string) error

	// ListHostSummaries returns all host_summary rows for the given org,
	// sorted by readiness_pct ASC (worst first). pqcStatusFilter filters
	// by PQC status: "UNSAFE" returns hosts with unsafe > 0, etc.
	// Empty string means no filter.
	ListHostSummaries(ctx context.Context, orgID string, pqcStatusFilter string) ([]HostSummary, error)

	// GetOrgSnapshot returns the pre-computed org snapshot, or nil if
	// the pipeline hasn't run yet for this org.
	GetOrgSnapshot(ctx context.Context, orgID string) (*OrgSnapshot, error)

	// ListStaleHosts returns distinct (org_id, hostname) pairs from the
	// findings table that have no host_summary row or whose host_summary
	// is older than the latest finding. Used by the cold-start rebuilder.
	ListStaleHosts(ctx context.Context) ([]PipelineJob, error)

	// --- Remediation (Phase 4B) ---

	// SetFindingStatus inserts a new status row for the given finding_key.
	SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error

	// GetFindingHistory returns all status changes for a finding_key,
	// sorted by changed_at DESC (newest first). Scoped to org for
	// tenant isolation (defense-in-depth alongside the org-embedded hash).
	GetFindingHistory(ctx context.Context, findingKey, orgID string) ([]FindingStatusEntry, error)

	// GetRemediationSummary returns counts by status for the given org.
	GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error)

	// ListRemediationFindings returns findings enriched with remediation status.
	ListRemediationFindings(ctx context.Context, orgID string, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error)

	// GetFindingByID returns a single finding by ID, scoped to org.
	GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error)

	// ListFindingStatusLog returns finding_status entries for the org,
	// ordered by changed_at DESC. Limited by the limit parameter.
	// Used by the Excel Remediation Log sheet. Phase 5.
	ListFindingStatusLog(ctx context.Context, orgID string, limit int) ([]FindingStatusEntry, error)

	// GetOnboardingMetrics returns milestone timestamps for the org's
	// onboarding journey, derived from audit events.
	GetOnboardingMetrics(ctx context.Context, orgID string) (*OnboardingMetrics, error)

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

// OnboardingMetrics records the first time each onboarding milestone
// was reached for a given org. MinutesToFirstScan is nil if the org
// hasn't completed a scan yet.
type OnboardingMetrics struct {
	Signup             *time.Time `json:"t_signup,omitempty"`
	Engine             *time.Time `json:"t_engine,omitempty"`
	Hosts              *time.Time `json:"t_hosts,omitempty"`
	Creds              *time.Time `json:"t_creds,omitempty"`
	Scan               *time.Time `json:"t_scan,omitempty"`
	Results            *time.Time `json:"t_results,omitempty"`
	MinutesToFirstScan *float64   `json:"minutes_to_first_scan"`
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

// TrendSummary describes an org-wide monthly-bucketed trend in
// readiness over time. Returned as part of ExecutiveSummary by the
// GET /api/v1/executive endpoint. Analytics Phase 2.
type TrendSummary struct {
	Direction     string            `json:"direction"`     // improving|declining|stable|insufficient-history
	DeltaPercent  float64           `json:"deltaPercent"`  // first→last readiness delta, rounded to 1 decimal
	MonthlyPoints []TrendMonthPoint `json:"monthlyPoints"` // chronologically sorted series; may be empty
}

// TrendMonthPoint is one calendar month's aggregate readiness across
// all hosts that scanned during the month. The latest scan per host
// per month is used to avoid scan-frequency bias (see
// docs/plans/2026-04-10-analytics-phase-2-design.md §5.1).
type TrendMonthPoint struct {
	Month         string  `json:"month"`         // "2026-04" (YYYY-MM format)
	Readiness     float64 `json:"readiness"`     // safe/(safe+trans+dep+unsafe) × 100, rounded to 1 decimal
	TotalFindings int     `json:"totalFindings"` // sum across all hosts in this bucket
}

// ProjectionSummary is the pace-based "when will we reach X% at
// current pace" estimate returned as part of ExecutiveSummary.
// TargetPercent and DeadlineYear come from the org's
// organizations.executive_target_percent and
// organizations.executive_deadline_year columns (defaults 80/2030).
// Analytics Phase 2.
type ProjectionSummary struct {
	Status          string  `json:"status"` // insufficient-history|already-complete|regressing|insufficient-movement|capped|on-track|behind-schedule
	TargetPercent   float64 `json:"targetPercent"`
	DeadlineYear    int     `json:"deadlineYear"`
	PacePerMonth    float64 `json:"pacePerMonth"`    // readiness-points per calendar month, rounded to 1 decimal
	ProjectedYear   int     `json:"projectedYear"`   // 0 when Status is non-computable
	ExplanationText string  `json:"explanationText"` // server-composed human-readable sentence
}

// MachineHealthTiers is the red/yellow/green tier rollup of the
// org's machines. Rules:
//
//	red    = has any UNSAFE finding
//	yellow = no unsafe, has any DEPRECATED finding
//	green  = only SAFE / TRANSITIONAL findings (including zero-finding machines)
//
// Returned as part of ExecutiveSummary by /api/v1/executive and
// consumed by the upgraded Machines stat card on the Overview.
// Analytics Phase 2.
type MachineHealthTiers struct {
	Red    int `json:"red"`
	Yellow int `json:"yellow"`
	Green  int `json:"green"`
	Total  int `json:"total"` // = red + yellow + green, precomputed for the UI
}

// ReadinessSummary is the "PQC Readiness: N%" headline number for
// the executive view. Analytics Phase 2.
type ReadinessSummary struct {
	Percent       float64 `json:"percent"` // rounded to 1 decimal
	TotalFindings int     `json:"totalFindings"`
	SafeFindings  int     `json:"safeFindings"`
}

// PolicyVerdictSummary is one built-in policy's aggregate verdict
// across all latest scans in the org. The executive summary includes
// one entry per built-in policy (NACSA-2030 and CNSA-2.0 in Phase 2).
// Analytics Phase 2.
type PolicyVerdictSummary struct {
	PolicyName      string `json:"policyName"`      // "nacsa-2030" | "cnsa-2.0"
	PolicyLabel     string `json:"policyLabel"`     // "NACSA-2030" | "CNSA-2.0"
	Verdict         string `json:"verdict"`         // "PASS" | "WARN" | "FAIL"
	ViolationCount  int    `json:"violationCount"`  // summed across all evaluated scans
	FindingsChecked int    `json:"findingsChecked"` // summed across all evaluated scans
}

// ExecutiveSummary is the response body for GET /api/v1/executive.
// Everything the upgraded Overview's executive block needs, in a
// single round-trip. Analytics Phase 2.
type ExecutiveSummary struct {
	Readiness      ReadinessSummary       `json:"readiness"`
	Trend          TrendSummary           `json:"trend"`
	Projection     ProjectionSummary      `json:"projection"`
	PolicyVerdicts []PolicyVerdictSummary `json:"policyVerdicts"`
	TopBlockers    []PriorityRow          `json:"topBlockers"` // reuses Phase 1 type
	MachineHealth  MachineHealthTiers     `json:"machineHealth"`
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
// the license server. Only ID, Name, timestamps, and executive-summary
// display preferences are stored — contact info and license details
// remain in the license server.
//
// ExecutiveTargetPercent and ExecutiveDeadlineYear are display
// preferences used by GET /api/v1/executive to compute the projected
// completion status. Defaults are 80.0 and 2030 respectively. Each
// org can override via direct SQL (Phase 2) or a future admin UI
// (Phase 2.5). See docs/plans/2026-04-10-analytics-phase-2-design.md §6.
type Organization struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	ExecutiveTargetPercent float64   `json:"executiveTargetPercent"`
	ExecutiveDeadlineYear  int       `json:"executiveDeadlineYear"`
	CreatedAt              time.Time `json:"createdAt"`
	UpdatedAt              time.Time `json:"updatedAt"`
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
