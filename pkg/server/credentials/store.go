package credentials

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors. Handlers map these to HTTP status codes.
var (
	// ErrProfileNotFound: GetProfile / DeleteProfileWithDelivery received
	// an (org, id) pair with no matching row.
	ErrProfileNotFound = errors.New("credentials: profile not found")

	// ErrDeliveryAlreadyAcked: AckDelivery called for a row that is
	// already in a terminal state (acked or failed). Idempotent retry
	// from a crashed engine is the expected caller.
	ErrDeliveryAlreadyAcked = errors.New("credentials: delivery already terminal")

	// ErrTestAlreadyTerminal: FinishTestJob called for a row that has
	// already been marked completed / failed / cancelled.
	ErrTestAlreadyTerminal = errors.New("credentials: test job already terminal")

	// ErrTestJobNotFound: GetTestJob received an (org, id) pair with no
	// matching row. Distinct from a generic DB failure so handlers can
	// return 404 vs 500.
	ErrTestJobNotFound = errors.New("credentials: test job not found")
)

// Store persists credentials profiles, the per-engine delivery queue,
// and the connectivity-test pipeline. Concrete implementation lives in
// postgres.go (next batch).
type Store interface {
	// CreateProfileWithDelivery inserts a profile + an initial push
	// delivery in a single transaction. Ciphertext is the sealed-box blob.
	CreateProfileWithDelivery(ctx context.Context, p Profile, ciphertext []byte) (Profile, error)

	// GetProfile returns the profile matching (org_id, id) or
	// ErrProfileNotFound.
	GetProfile(ctx context.Context, orgID, id uuid.UUID) (Profile, error)

	// ListProfiles returns all profiles in the org ordered by created_at
	// descending.
	ListProfiles(ctx context.Context, orgID uuid.UUID) ([]Profile, error)

	// DeleteProfileWithDelivery removes the profile and enqueues a
	// delete-kind delivery so the engine drops the SecretRef from its
	// keystore. Both mutations happen in one transaction.
	DeleteProfileWithDelivery(ctx context.Context, orgID, id uuid.UUID) error

	// ClaimNextDelivery atomically grabs the oldest queued delivery for
	// this engine and flips its status to 'claimed'. The bool return is
	// false when the queue is empty.
	ClaimNextDelivery(ctx context.Context, engineID uuid.UUID) (Delivery, bool, error)

	// AckDelivery marks a delivery acked (errMsg == "") or failed
	// (errMsg populated). Returns ErrDeliveryAlreadyAcked if the row is
	// already terminal.
	AckDelivery(ctx context.Context, id uuid.UUID, errMsg string) error

	// ReclaimStaleDeliveries flips claimed rows whose claimed_at is
	// older than cutoff back to 'queued' so another (or the same)
	// engine can retry them.
	ReclaimStaleDeliveries(ctx context.Context, cutoff time.Time) error

	// CreateTestJob inserts a new queued test job.
	CreateTestJob(ctx context.Context, t TestJob) (TestJob, error)

	// GetTestJob returns the job matching (org_id, id) or a not-found
	// error from the underlying store.
	GetTestJob(ctx context.Context, orgID, id uuid.UUID) (TestJob, error)

	// ListTestResults returns all per-host results for a test job.
	ListTestResults(ctx context.Context, testID uuid.UUID) ([]TestResult, error)

	// ClaimNextTest atomically grabs the oldest queued test job for
	// the caller. Bool is false when the queue is empty.
	ClaimNextTest(ctx context.Context, engineID uuid.UUID) (TestJob, bool, error)

	// InsertTestResults appends per-host outcomes for a running test.
	InsertTestResults(ctx context.Context, results []TestResult) error

	// FinishTestJob transitions a test job to its terminal state
	// (completed / failed / cancelled) and stamps completed_at. Returns
	// ErrTestAlreadyTerminal on a second call.
	FinishTestJob(ctx context.Context, id uuid.UUID, status, errMsg string) error

	// ReclaimStaleTests flips claimed/running rows whose claimed_at is
	// older than cutoff back to queued.
	ReclaimStaleTests(ctx context.Context, cutoff time.Time) error

	// GetEngineEncryptionPubkey returns the engine's static X25519
	// public key so the admin API can echo it to the browser for
	// sealed-box encryption. Nil slice + nil error means the engine
	// exists but has not yet published a pubkey.
	GetEngineEncryptionPubkey(ctx context.Context, engineID uuid.UUID) ([]byte, error)
}
