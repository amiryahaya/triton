package analytics

import (
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// scanSummaryAt is a test helper that builds a store.ScanSummary
// with the given hostname, timestamp, and per-status counts. Used
// by trend and machine-health unit tests.
func scanSummaryAt(hostname string, ts time.Time, safe, trans, dep, unsafe int) store.ScanSummary {
	return store.ScanSummary{
		ID:            hostname + "-" + ts.Format(time.RFC3339),
		Hostname:      hostname,
		Timestamp:     ts,
		Profile:       "quick",
		TotalFindings: safe + trans + dep + unsafe,
		Safe:          safe,
		Transitional:  trans,
		Deprecated:    dep,
		Unsafe:        unsafe,
	}
}

// mustParseMonth parses a "2006-01-15" date string into a time.Time
// for test fixtures. Panics on invalid input — use only in tests.
func mustParseMonth(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}
