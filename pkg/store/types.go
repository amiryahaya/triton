package store

import "time"

// Finding is the denormalized per-finding row stored in the findings
// table. Populated from model.Finding.CryptoAsset during extraction;
// findings without a crypto asset are skipped.
//
// Field mapping from model.Finding:
//   - Hostname comes from model.ScanResult.Metadata.Hostname
//   - FilePath comes from model.Finding.Source.Path (empty for non-file sources)
//   - Module is the scanner module name ("certificate", "library", "deps", ...)
//     and is the primary drill-down discriminator. model.Finding.Category
//     (a coarse ModuleCategory enum) is intentionally NOT stored — Module
//     carries the granular information Phase 1 views care about.
type Finding struct {
	ID                string
	ScanID            string
	OrgID             string
	Hostname          string
	FindingIndex      int
	Module            string
	FilePath          string
	Algorithm         string
	KeySize           int
	PQCStatus         string
	MigrationPriority int
	NotAfter          *time.Time
	Subject           string
	Issuer            string
	Reachability      string
	CreatedAt         time.Time
	ImageRef          string
	ImageDigest       string
}

// InventoryRow is one row in the Crypto Inventory view — one per
// (algorithm, key_size) combination within an org.
type InventoryRow struct {
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"keySize,omitempty"`
	PQCStatus   string `json:"pqcStatus"`
	Instances   int    `json:"instances"`
	Machines    int    `json:"machines"`
	MaxPriority int    `json:"maxPriority"`
}

// ExpiringCertRow is one row in the Expiring Certificates view.
type ExpiringCertRow struct {
	FindingID     string    `json:"findingId"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer,omitempty"`
	Hostname      string    `json:"hostname"`
	Algorithm     string    `json:"algorithm"`
	KeySize       int       `json:"keySize,omitempty"`
	NotAfter      time.Time `json:"notAfter"`
	DaysRemaining int       `json:"daysRemaining"`
	Status        string    `json:"status"`
}

// FilterParams holds optional filter criteria for analytics queries.
// Zero values mean "no filter" (show all).
type FilterParams struct {
	Hostname  string // exact match on hostname
	Algorithm string // exact match on algorithm
	PQCStatus string // exact match on pqc_status (SAFE/TRANSITIONAL/DEPRECATED/UNSAFE)
}

// FilterOptions holds the distinct values available for filtering,
// returned by GET /api/v1/filters.
type FilterOptions struct {
	Hostnames   []string `json:"hostnames"`
	Algorithms  []string `json:"algorithms"`
	PQCStatuses []string `json:"pqcStatuses"`
}

// PriorityRow is one row in the Migration Priority view.
//
// Module is the scanner module name ("certificate", "library", ...);
// we don't store a separate "category" field — the coarse
// ModuleCategory enum from the model package wasn't useful for
// drill-down, and Module carries the granular information.
type PriorityRow struct {
	FindingID string `json:"findingId"`
	Priority  int    `json:"priority"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"keySize,omitempty"`
	PQCStatus string `json:"pqcStatus"`
	Module    string `json:"module"`
	Hostname  string `json:"hostname"`
	FilePath  string `json:"filePath,omitempty"`
}

// SparklinePoint is one month's readiness snapshot for sparkline charts.
// Analytics Phase 4A.
type SparklinePoint struct {
	Month     string  `json:"month"`     // "2026-04" (YYYY-MM)
	Readiness float64 `json:"readiness"` // 0-100
}

// HostSummary is a pre-computed per-(org, hostname) aggregate.
// Refreshed by pipeline T2 when new findings arrive for a hostname.
// Analytics Phase 4A.
type HostSummary struct {
	OrgID                string           `json:"orgId"`
	Hostname             string           `json:"hostname"`
	ScanID               string           `json:"scanId"`
	ScannedAt            time.Time        `json:"scannedAt"`
	TotalFindings        int              `json:"totalFindings"`
	SafeFindings         int              `json:"safeFindings"`
	TransitionalFindings int              `json:"transitionalFindings"`
	DeprecatedFindings   int              `json:"deprecatedFindings"`
	UnsafeFindings       int              `json:"unsafeFindings"`
	ReadinessPct         float64          `json:"readinessPct"`
	CertsExpiring30d     int              `json:"certsExpiring30d"`
	CertsExpiring90d     int              `json:"certsExpiring90d"`
	CertsExpired         int              `json:"certsExpired"`
	MaxPriority          int              `json:"maxPriority"`
	TrendDirection       string           `json:"trendDirection"`
	TrendDeltaPct        float64          `json:"trendDeltaPct"`
	Sparkline            []SparklinePoint `json:"sparkline"`
	RefreshedAt          time.Time        `json:"refreshedAt"`
}

// OrgSnapshot is a pre-computed org-wide rollup of all host summaries.
// Refreshed by pipeline T3 after any host summary changes.
// Analytics Phase 4A.
type OrgSnapshot struct {
	OrgID            string                 `json:"orgId"`
	ReadinessPct     float64                `json:"readinessPct"`
	TotalFindings    int                    `json:"totalFindings"`
	SafeFindings     int                    `json:"safeFindings"`
	MachinesTotal    int                    `json:"machinesTotal"`
	MachinesRed      int                    `json:"machinesRed"`
	MachinesYellow   int                    `json:"machinesYellow"`
	MachinesGreen    int                    `json:"machinesGreen"`
	TrendDirection   string                 `json:"trendDirection"`
	TrendDeltaPct    float64                `json:"trendDeltaPct"`
	MonthlyTrend     []SparklinePoint       `json:"monthlyTrend"`
	ProjectionStatus string                 `json:"projectionStatus"`
	ProjectedYear    int                    `json:"projectedYear,omitempty"`
	TargetPct        float64                `json:"targetPct"`
	DeadlineYear     int                    `json:"deadlineYear"`
	PolicyVerdicts   []PolicyVerdictSummary `json:"policyVerdicts"`
	TopBlockers      []PriorityRow          `json:"topBlockers"`
	CertsExpiring30d int                    `json:"certsExpiring30d"`
	CertsExpiring90d int                    `json:"certsExpiring90d"`
	CertsExpired     int                    `json:"certsExpired"`
	RefreshedAt      time.Time              `json:"refreshedAt"`
}

// PipelineJob identifies a unit of work for the analytics pipeline.
// Analytics Phase 4A.
type PipelineJob struct {
	OrgID    string
	Hostname string
	ScanID   string // may be empty for cold-start rebuild jobs
}

// PipelineStatus is the response for GET /api/v1/pipeline/status.
// Analytics Phase 4A.
type PipelineStatus struct {
	Status             string    `json:"status"` // "idle" | "processing"
	QueueDepth         int       `json:"queueDepth"`
	LastProcessedAt    time.Time `json:"lastProcessedAt"`
	JobsProcessedTotal int64     `json:"jobsProcessedTotal"`
	JobsFailedTotal    int64     `json:"jobsFailedTotal"`
}

// FindingStatusEntry is one row from the finding_status table.
// Analytics Phase 4B.
type FindingStatusEntry struct {
	ID         int64      `json:"id"`
	FindingKey string     `json:"findingKey"`
	OrgID      string     `json:"orgId"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason"`
	ChangedBy  string     `json:"changedBy"`
	ChangedAt  time.Time  `json:"changedAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// RemediationRow is one finding enriched with its current remediation
// status, returned by GET /api/v1/remediation. Analytics Phase 4B.
type RemediationRow struct {
	FindingID  string     `json:"findingId"`
	Hostname   string     `json:"hostname"`
	Algorithm  string     `json:"algorithm"`
	KeySize    int        `json:"keySize,omitempty"`
	PQCStatus  string     `json:"pqcStatus"`
	Module     string     `json:"module"`
	Priority   int        `json:"priority"`
	Status     string     `json:"status"`
	ChangedAt  *time.Time `json:"changedAt"`
	ChangedBy  string     `json:"changedBy"`
	FindingKey string     `json:"findingKey"`
}

// RemediationSummary is the response for GET /api/v1/remediation/summary.
// Analytics Phase 4B.
type RemediationSummary struct {
	Open       int `json:"open"`
	InProgress int `json:"inProgress"`
	Resolved   int `json:"resolved"`
	Accepted   int `json:"accepted"`
	Total      int `json:"total"`
}
