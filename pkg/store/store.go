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
	GetScan(ctx context.Context, id string) (*model.ScanResult, error)

	// ListScans returns scan summaries matching the given filter.
	ListScans(ctx context.Context, filter ScanFilter) ([]ScanSummary, error)

	// DeleteScan removes a scan result by ID.
	DeleteScan(ctx context.Context, id string) error
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

// Store composes all storage interfaces.
// Implementations must be safe for concurrent use.
type Store interface {
	ScanStore
	HashStore

	// Close releases any resources held by the store.
	Close() error
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
