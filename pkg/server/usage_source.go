package server

import (
	"context"
	"time"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)


// UsageSource collects current counts for the licence-usage pusher.
// Metrics that the store cannot expose are simply omitted — the pusher
// reports what it knows, and the License Server enforces what it can.
type UsageSource struct {
	store store.Store
}

// NewUsageSource returns a UsageSource backed by the given store.
func NewUsageSource(s store.Store) *UsageSource {
	return &UsageSource{store: s}
}

// Collect returns a fresh snapshot of metered counts.
//
// The Store interface does not currently expose cross-org aggregate
// counters (scan totals, seat totals) without a new method — adding one
// is out of scope for PR A. The pusher sends a heartbeat with an empty
// metrics slice; the License Server records the ping and enforces its
// own seat-activation count. Future sprints can add CountScansSince etc.
// to the Store interface and uncomment the relevant lines here.
func (u *UsageSource) Collect() []license.UsageMetric {
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// No aggregate counters available without new Store methods.
	// Return a non-nil empty slice so callers can range over it safely.
	return []license.UsageMetric{}
}

// monthStart returns midnight UTC on the first day of the current month.
// Kept for future use when a CountScansSince method is added to the store.
func monthStart() time.Time {
	n := time.Now().UTC()
	return time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
}
