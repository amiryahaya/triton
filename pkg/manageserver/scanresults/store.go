package scanresults

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ErrNotFound is returned when a queue row, push-creds singleton, or
// license-state singleton is missing. Handlers map this to HTTP 404;
// internal callers (drain) use errors.Is to distinguish benign misses
// from real DB faults.
var ErrNotFound = errors.New("scanresults: not found")

// Store is the persistence boundary for the scan-results outbox and
// its satellite singletons (push creds, license state).
//
// The shape of Enqueue matches the `scanjobs.ResultEnqueuer` interface
// exactly so that the orchestrator can hand completed scans straight
// into the drain's outbox without knowing anything about postgres.
type Store interface {
	// Enqueue wraps the scan payload + submitted_by envelope into JSON
	// and inserts one row into manage_scan_results_queue. Matches the
	// scanjobs.ResultEnqueuer interface verbatim.
	Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string, sourceID uuid.UUID, scan *model.ScanResult) error

	// ClaimDue returns up to `limit` rows whose next_attempt_at <= NOW
	// and attempt_count < 10, ordered by enqueued_at. The drain's
	// worker loop walks these and Delete/Defer/DeadLetter each one.
	// No row-level lock: a single-threaded drain makes this cheap.
	ClaimDue(ctx context.Context, limit int) ([]QueueRow, error)

	// Delete removes a queue row after a successful push. Returns
	// ErrNotFound if the row vanished before we got there.
	Delete(ctx context.Context, id uuid.UUID) error

	// Defer bumps attempt_count + 1, sets next_attempt_at, and stashes
	// the last error string. Called after a retryable push failure.
	Defer(ctx context.Context, id uuid.UUID, nextAttempt time.Time, errMsg string) error

	// DeadLetter copies the row into manage_scan_results_dead_letter
	// and deletes it from the queue, atomically, stamping the reason.
	// Called on the 10th retry or any non-retryable upstream rejection
	// (4xx other than 401/403/429).
	DeadLetter(ctx context.Context, id uuid.UUID, reason string) error

	// QueueDepth returns the total row count in manage_scan_results_queue.
	// Used by the scan-jobs handler for backpressure (saturation ≥ 10k).
	QueueDepth(ctx context.Context) (int64, error)

	// OldestAge returns how long the oldest enqueued row has been
	// waiting. Empty queue returns 0. Used by /admin/push-status.
	OldestAge(ctx context.Context) (time.Duration, error)

	// LoadPushCreds reads the singleton manage_push_creds row.
	// Returns ErrNotFound before Batch G's enrol flow populates it.
	LoadPushCreds(ctx context.Context) (PushCreds, error)

	// SavePushCreds upserts the singleton manage_push_creds row. Used
	// by Batch G's auto-enrol flow after the signed-token hand-off.
	SavePushCreds(ctx context.Context, creds PushCreds) error

	// RecordPushSuccess stamps manage_license_state after a successful
	// push: last_pushed_at=NOW, last_pushed_metrics=metricsJSON (nil
	// OK), clears last_push_error + consecutive_failures.
	RecordPushSuccess(ctx context.Context, metricsJSON []byte) error

	// RecordPushFailure increments consecutive_failures on
	// manage_license_state and stores the error message.
	RecordPushFailure(ctx context.Context, errMsg string) error

	// LoadLicenseState reads manage_license_state + the current queue
	// depth + oldest-row age and returns a Status struct for the
	// /admin/push-status handler. Populates QueueDepth and
	// OldestRowAgeSeconds from the queue tables.
	LoadLicenseState(ctx context.Context) (Status, error)
}
