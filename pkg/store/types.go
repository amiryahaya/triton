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
