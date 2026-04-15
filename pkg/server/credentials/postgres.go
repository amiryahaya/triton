package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool owned
// by the caller (usually pkg/store.PostgresStore).
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pool. The caller owns the pool's lifetime.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// CreateProfileWithDelivery inserts the profile row and an initial
// push-kind delivery in a single transaction. If either INSERT fails
// the entire operation rolls back — we never leak a profile without a
// corresponding delivery or vice versa.
func (s *PostgresStore) CreateProfileWithDelivery(ctx context.Context, p Profile, ciphertext []byte) (Profile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Profile{}, fmt.Errorf("create profile: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed). // Rollback after a successful Commit is a documented pgx no-op.

	matcherJSON, err := json.Marshal(p.Matcher)
	if err != nil {
		return Profile{}, fmt.Errorf("marshal matcher: %w", err)
	}

	row := tx.QueryRow(ctx,
		`INSERT INTO credentials_profiles
		 (id, org_id, engine_id, name, auth_type, matcher, secret_ref, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING created_at`,
		p.ID, p.OrgID, p.EngineID, p.Name, string(p.AuthType), matcherJSON, p.SecretRef, p.CreatedBy,
	)
	if err := row.Scan(&p.CreatedAt); err != nil {
		return Profile{}, fmt.Errorf("insert profile: %w", err)
	}

	deliveryID := uuid.Must(uuid.NewV7())
	profileIDPtr := p.ID
	if _, err := tx.Exec(ctx,
		`INSERT INTO credential_deliveries
		 (id, org_id, engine_id, profile_id, secret_ref, auth_type, kind, ciphertext)
		 VALUES ($1, $2, $3, $4, $5, $6, 'push', $7)`,
		deliveryID, p.OrgID, p.EngineID, profileIDPtr, p.SecretRef, string(p.AuthType), ciphertext,
	); err != nil {
		return Profile{}, fmt.Errorf("insert delivery: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Profile{}, fmt.Errorf("commit: %w", err)
	}
	return p, nil
}

// profileSelectCols matches the column order expected by scanProfile.
const profileSelectCols = `id, org_id, engine_id, name, auth_type, matcher,
	secret_ref, COALESCE(created_by, '00000000-0000-0000-0000-000000000000'::uuid),
	created_at, last_tested_at`

func scanProfile(scanner pgx.Row) (Profile, error) {
	var p Profile
	var authTypeStr string
	var matcherJSON []byte
	if err := scanner.Scan(
		&p.ID, &p.OrgID, &p.EngineID, &p.Name, &authTypeStr, &matcherJSON,
		&p.SecretRef, &p.CreatedBy, &p.CreatedAt, &p.LastTestedAt,
	); err != nil {
		return Profile{}, err
	}
	p.AuthType = AuthType(authTypeStr)
	if len(matcherJSON) > 0 {
		if err := json.Unmarshal(matcherJSON, &p.Matcher); err != nil {
			return Profile{}, fmt.Errorf("unmarshal matcher: %w", err)
		}
	}
	return p, nil
}

func (s *PostgresStore) GetProfile(ctx context.Context, orgID, id uuid.UUID) (Profile, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+profileSelectCols+` FROM credentials_profiles WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	p, err := scanProfile(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Profile{}, ErrProfileNotFound
		}
		return Profile{}, fmt.Errorf("get profile: %w", err)
	}
	return p, nil
}

func (s *PostgresStore) ListProfiles(ctx context.Context, orgID uuid.UUID) ([]Profile, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+profileSelectCols+` FROM credentials_profiles WHERE org_id = $1 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	out := []Profile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProfileWithDelivery enqueues a delete-kind delivery then
// deletes the profile row, both in one tx. The delete-delivery row
// keeps engine_id + secret_ref + auth_type so the engine can drop the
// keystore entry; profile_id is captured for audit but the FK-less
// column survives the profile row disappearing.
func (s *PostgresStore) DeleteProfileWithDelivery(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("delete profile: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed). // Rollback after Commit is a documented pgx no-op.

	var engineID, secretRef uuid.UUID
	var authType string
	row := tx.QueryRow(ctx,
		`SELECT engine_id, secret_ref, auth_type FROM credentials_profiles
		 WHERE org_id = $1 AND id = $2 FOR UPDATE`,
		orgID, id,
	)
	if err := row.Scan(&engineID, &secretRef, &authType); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProfileNotFound
		}
		return fmt.Errorf("load profile for delete: %w", err)
	}

	deliveryID := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx,
		`INSERT INTO credential_deliveries
		 (id, org_id, engine_id, profile_id, secret_ref, auth_type, kind, ciphertext)
		 VALUES ($1, $2, $3, $4, $5, $6, 'delete', NULL)`,
		deliveryID, orgID, engineID, id, secretRef, authType,
	); err != nil {
		return fmt.Errorf("insert delete delivery: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM credentials_profiles WHERE org_id = $1 AND id = $2`,
		orgID, id,
	); err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}

	return tx.Commit(ctx)
}

// deliverySelectCols matches the column order expected by scanDelivery.
const deliverySelectCols = `id, org_id, engine_id, profile_id, secret_ref,
	auth_type, kind, ciphertext, status, COALESCE(error, ''),
	requested_at, claimed_at, acked_at`

func scanDelivery(scanner pgx.Row) (Delivery, error) {
	var d Delivery
	var authTypeStr, kindStr string
	if err := scanner.Scan(
		&d.ID, &d.OrgID, &d.EngineID, &d.ProfileID, &d.SecretRef,
		&authTypeStr, &kindStr, &d.Ciphertext, &d.Status, &d.Error,
		&d.RequestedAt, &d.ClaimedAt, &d.AckedAt,
	); err != nil {
		return Delivery{}, err
	}
	d.AuthType = AuthType(authTypeStr)
	d.Kind = DeliveryKind(kindStr)
	return d, nil
}

// ClaimNextDelivery pops the oldest queued delivery for engineID using
// SELECT ... FOR UPDATE SKIP LOCKED so concurrent engines (or restart
// races) never double-claim a row.
func (s *PostgresStore) ClaimNextDelivery(ctx context.Context, engineID uuid.UUID) (Delivery, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Delivery{}, false, fmt.Errorf("claim delivery: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed).

	row := tx.QueryRow(ctx,
		`SELECT `+deliverySelectCols+`
		 FROM credential_deliveries
		 WHERE engine_id = $1 AND status = 'queued'
		 ORDER BY requested_at ASC
		 FOR UPDATE SKIP LOCKED
		 LIMIT 1`,
		engineID,
	)
	d, err := scanDelivery(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Delivery{}, false, nil
		}
		return Delivery{}, false, fmt.Errorf("scan claim delivery: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE credential_deliveries SET status = 'claimed', claimed_at = NOW() WHERE id = $1`,
		d.ID,
	); err != nil {
		return Delivery{}, false, fmt.Errorf("update claim delivery: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Delivery{}, false, fmt.Errorf("commit claim delivery: %w", err)
	}
	d.Status = "claimed"
	now := time.Now().UTC()
	d.ClaimedAt = &now
	return d, true, nil
}

// AckDelivery flips a claimed delivery to its terminal state. Returns
// ErrDeliveryAlreadyAcked if the row is already terminal (retry from a
// crashed engine sees this and can move on).
func (s *PostgresStore) AckDelivery(ctx context.Context, id uuid.UUID, errMsg string) error {
	newStatus := "acked"
	if errMsg != "" {
		newStatus = "failed"
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE credential_deliveries
		 SET status = $1, error = NULLIF($2, ''), acked_at = NOW()
		 WHERE id = $3 AND status NOT IN ('acked', 'failed')`,
		newStatus, errMsg, id,
	)
	if err != nil {
		return fmt.Errorf("ack delivery: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrDeliveryAlreadyAcked
	}
	return nil
}

// ReclaimStaleDeliveries flips claimed rows older than cutoff back to
// queued. Idempotent — if no rows match, does nothing.
func (s *PostgresStore) ReclaimStaleDeliveries(ctx context.Context, cutoff time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE credential_deliveries
		 SET status = 'queued', claimed_at = NULL
		 WHERE status = 'claimed' AND claimed_at IS NOT NULL AND claimed_at < $1`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("reclaim stale deliveries: %w", err)
	}
	return nil
}

// --- test jobs ---

const testSelectCols = `id, org_id, engine_id, profile_id, host_ids, status,
	COALESCE(error, ''), requested_at, claimed_at, completed_at`

func scanTestJob(scanner pgx.Row) (TestJob, error) {
	var t TestJob
	if err := scanner.Scan(
		&t.ID, &t.OrgID, &t.EngineID, &t.ProfileID, &t.HostIDs,
		&t.Status, &t.Error, &t.RequestedAt, &t.ClaimedAt, &t.CompletedAt,
	); err != nil {
		return TestJob{}, err
	}
	return t, nil
}

func (s *PostgresStore) CreateTestJob(ctx context.Context, t TestJob) (TestJob, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO credential_tests
		 (id, org_id, engine_id, profile_id, host_ids)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING status, requested_at`,
		t.ID, t.OrgID, t.EngineID, t.ProfileID, t.HostIDs,
	)
	if err := row.Scan(&t.Status, &t.RequestedAt); err != nil {
		return TestJob{}, fmt.Errorf("create test job: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) GetTestJob(ctx context.Context, orgID, id uuid.UUID) (TestJob, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+testSelectCols+` FROM credential_tests WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	t, err := scanTestJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TestJob{}, ErrTestJobNotFound
		}
		return TestJob{}, fmt.Errorf("get test job: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) ListTestResults(ctx context.Context, testID uuid.UUID) ([]TestResult, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT test_id, host_id, success, COALESCE(latency_ms, 0), COALESCE(error, ''), probed_at
		 FROM credential_test_results WHERE test_id = $1 ORDER BY probed_at`,
		testID,
	)
	if err != nil {
		return nil, fmt.Errorf("list test results: %w", err)
	}
	defer rows.Close()

	out := []TestResult{}
	for rows.Next() {
		var r TestResult
		if err := rows.Scan(&r.TestID, &r.HostID, &r.Success, &r.LatencyMs, &r.Error, &r.ProbedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ClaimNextTest(ctx context.Context, engineID uuid.UUID) (TestJob, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TestJob{}, false, fmt.Errorf("claim test: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed).

	row := tx.QueryRow(ctx,
		`SELECT `+testSelectCols+`
		 FROM credential_tests
		 WHERE engine_id = $1 AND status = 'queued'
		 ORDER BY requested_at ASC
		 FOR UPDATE SKIP LOCKED
		 LIMIT 1`,
		engineID,
	)
	t, err := scanTestJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TestJob{}, false, nil
		}
		return TestJob{}, false, fmt.Errorf("scan claim test: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE credential_tests SET status = 'claimed', claimed_at = NOW() WHERE id = $1`,
		t.ID,
	); err != nil {
		return TestJob{}, false, fmt.Errorf("update claim test: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return TestJob{}, false, fmt.Errorf("commit claim test: %w", err)
	}
	t.Status = "claimed"
	now := time.Now().UTC()
	t.ClaimedAt = &now
	return t, true, nil
}

// InsertTestResults batch-inserts per-host outcomes. Idempotent at
// (test_id, host_id) — a retry after a crash overwrites the previous
// row's fields so eventually-consistent delivery is safe.
func (s *PostgresStore) InsertTestResults(ctx context.Context, results []TestResult) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("insert test results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed).

	for _, r := range results {
		probedAt := r.ProbedAt
		if probedAt.IsZero() {
			probedAt = time.Now().UTC()
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO credential_test_results
			 (test_id, host_id, success, latency_ms, error, probed_at)
			 VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6)
			 ON CONFLICT (test_id, host_id) DO UPDATE SET
			   success    = EXCLUDED.success,
			   latency_ms = EXCLUDED.latency_ms,
			   error      = EXCLUDED.error,
			   probed_at  = EXCLUDED.probed_at`,
			r.TestID, r.HostID, r.Success, r.LatencyMs, r.Error, probedAt,
		); err != nil {
			return fmt.Errorf("insert test result: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// FinishTestJob transitions the job to its terminal state. Returns
// ErrTestAlreadyTerminal if the row is already completed/failed/cancelled.
func (s *PostgresStore) FinishTestJob(ctx context.Context, id uuid.UUID, status, errMsg string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE credential_tests
		 SET status = $1, error = NULLIF($2, ''), completed_at = NOW()
		 WHERE id = $3 AND status NOT IN ('completed', 'failed', 'cancelled')`,
		status, errMsg, id,
	)
	if err != nil {
		return fmt.Errorf("finish test job: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrTestAlreadyTerminal
	}
	return nil
}

func (s *PostgresStore) ReclaimStaleTests(ctx context.Context, cutoff time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE credential_tests
		 SET status = 'queued', claimed_at = NULL
		 WHERE status IN ('claimed', 'running')
		   AND claimed_at IS NOT NULL AND claimed_at < $1`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("reclaim stale tests: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetEngineEncryptionPubkey(ctx context.Context, engineID uuid.UUID) ([]byte, error) {
	var pk []byte
	err := s.pool.QueryRow(ctx,
		`SELECT encryption_pubkey FROM engines WHERE id = $1`,
		engineID,
	).Scan(&pk)
	if errors.Is(err, pgx.ErrNoRows) {
		// Engine does not exist. Callers treat this the same as "no
		// pubkey yet" (nil slice) — the handler layer already verifies
		// engine existence before calling this, so reaching here means
		// a race with engine revocation and a 409 is appropriate.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get engine encryption pubkey: %w", err)
	}
	return pk, nil
}
