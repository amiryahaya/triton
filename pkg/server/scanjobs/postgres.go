package scanjobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/model"
)

// scanStoreAPI is the narrow surface scanjobs needs from the underlying
// scan store. Defined as an interface so tests can supply a fake and
// the package never imports pkg/store directly (would create a
// dependency cycle when scanjobs is later imported from pkg/store
// helpers).
type scanStoreAPI interface {
	SaveScanWithJobContext(ctx context.Context, scan *model.ScanResult, engineID, scanJobID uuid.UUID) error
}

// PostgresStore implements Store. The pool is owned by the caller;
// scanStore is the narrow scan-persistence dependency.
type PostgresStore struct {
	pool      *pgxpool.Pool
	scanStore scanStoreAPI
}

// NewPostgresStore wires the dependencies. scanStore may be nil during
// admin-only flows, but RecordScanResult will panic if invoked without
// it (the Phase-5 gateway always provides one).
func NewPostgresStore(pool *pgxpool.Pool, scanStore scanStoreAPI) *PostgresStore {
	return &PostgresStore{pool: pool, scanStore: scanStore}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// jobSelectCols matches the column order expected by scanJob below.
const jobSelectCols = `id, org_id, engine_id, group_id, host_ids,
	scan_profile, credential_profile_id, status, COALESCE(error, ''),
	COALESCE(requested_by, '00000000-0000-0000-0000-000000000000'::uuid),
	requested_at, claimed_at, completed_at,
	progress_total, progress_done, progress_failed`

func scanJob(scanner pgx.Row) (Job, error) {
	var j Job
	var profileStr, statusStr string
	if err := scanner.Scan(
		&j.ID, &j.OrgID, &j.EngineID, &j.GroupID, &j.HostIDs,
		&profileStr, &j.CredentialProfileID, &statusStr, &j.Error,
		&j.RequestedBy, &j.RequestedAt, &j.ClaimedAt, &j.CompletedAt,
		&j.ProgressTotal, &j.ProgressDone, &j.ProgressFailed,
	); err != nil {
		return Job{}, err
	}
	j.ScanProfile = ScanProfile(profileStr)
	j.Status = JobStatus(statusStr)
	return j, nil
}

// CreateJob persists a new queued scan job. The caller is expected to
// have already validated that engine_id, group_id, host_ids, and
// credential_profile_id all belong to the org (handler responsibility).
func (s *PostgresStore) CreateJob(ctx context.Context, j Job) (Job, error) {
	if j.ScanProfile == "" {
		j.ScanProfile = ProfileStandard
	}
	progressTotal := len(j.HostIDs)
	row := s.pool.QueryRow(ctx,
		`INSERT INTO scan_jobs
		 (id, org_id, engine_id, group_id, host_ids, scan_profile,
		  credential_profile_id, requested_by, progress_total)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING status, requested_at, progress_total`,
		j.ID, j.OrgID, j.EngineID, j.GroupID, j.HostIDs, string(j.ScanProfile),
		j.CredentialProfileID, j.RequestedBy, progressTotal,
	)
	var statusStr string
	if err := row.Scan(&statusStr, &j.RequestedAt, &j.ProgressTotal); err != nil {
		return Job{}, fmt.Errorf("create scan job: %w", err)
	}
	j.Status = JobStatus(statusStr)
	return j, nil
}

func (s *PostgresStore) GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+` FROM scan_jobs WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	j, err := scanJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, ErrJobNotFound
		}
		return Job{}, fmt.Errorf("get scan job: %w", err)
	}
	return j, nil
}

func (s *PostgresStore) ListJobs(ctx context.Context, orgID uuid.UUID, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobSelectCols+` FROM scan_jobs
		 WHERE org_id = $1 ORDER BY requested_at DESC LIMIT $2`,
		orgID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	defer rows.Close()

	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CancelJob flips a queued job to cancelled. Disambiguates between
// "row does not exist" (404) and "row exists but is past queued"
// (409) so the handler layer can return the right HTTP status without
// a second round-trip.
func (s *PostgresStore) CancelJob(ctx context.Context, orgID, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs SET status = 'cancelled', completed_at = NOW()
		 WHERE org_id = $1 AND id = $2 AND status = 'queued'`,
		orgID, id,
	)
	if err != nil {
		return fmt.Errorf("cancel scan job: %w", err)
	}
	if ct.RowsAffected() != 0 {
		return nil
	}
	// Disambiguate: does the row exist at all?
	var curStatus string
	err = s.pool.QueryRow(ctx,
		`SELECT status FROM scan_jobs WHERE org_id = $1 AND id = $2`,
		orgID, id,
	).Scan(&curStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJobNotFound
		}
		return fmt.Errorf("cancel scan job (status check): %w", err)
	}
	return ErrJobNotCancellable
}

// ClaimNext atomically grabs the oldest queued job for engineID and
// enriches the wire payload with resolved host addresses + credential
// metadata. All work happens inside a single transaction so concurrent
// engines (or restart races) never double-claim a row.
//
// Port resolution: ssh-* → 22, winrm-* → 5985, no credential → 22.
// Address comes from inventory_hosts.address (INET, the /32 or /128
// suffix is stripped before being returned to the engine).
func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (JobPayload, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return JobPayload{}, false, fmt.Errorf("claim scan job: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after a successful Commit is a documented pgx no-op (ErrTxClosed).

	var (
		jobID         uuid.UUID
		hostIDs       []uuid.UUID
		profileStr    string
		credProfileID *uuid.UUID
	)
	row := tx.QueryRow(ctx,
		`SELECT id, host_ids, scan_profile, credential_profile_id
		 FROM scan_jobs
		 WHERE engine_id = $1 AND status = 'queued'
		 ORDER BY requested_at ASC
		 FOR UPDATE SKIP LOCKED
		 LIMIT 1`,
		engineID,
	)
	if err := row.Scan(&jobID, &hostIDs, &profileStr, &credProfileID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return JobPayload{}, false, nil
		}
		return JobPayload{}, false, fmt.Errorf("scan claim scan job: %w", err)
	}

	// Enrich with host targets. address is INET — cast to text and
	// strip the /32 (IPv4) or /128 (IPv6) prefix so the engine gets a
	// plain dotted-quad / colon-hex address.
	hosts, err := loadHostTargets(ctx, tx, hostIDs)
	if err != nil {
		return JobPayload{}, false, err
	}

	payload := JobPayload{
		ID:          jobID,
		ScanProfile: ScanProfile(profileStr),
		Hosts:       hosts,
	}

	port := 22
	if credProfileID != nil {
		var secretRef uuid.UUID
		var authType string
		if err := tx.QueryRow(ctx,
			`SELECT secret_ref, auth_type FROM credentials_profiles WHERE id = $1`,
			*credProfileID,
		).Scan(&secretRef, &authType); err != nil {
			return JobPayload{}, false, fmt.Errorf("load credential profile: %w", err)
		}
		payload.CredentialSecretRef = &secretRef
		payload.CredentialAuthType = authType
		if strings.HasPrefix(authType, "winrm") {
			port = 5985
		}
	}
	for i := range payload.Hosts {
		payload.Hosts[i].Port = port
	}

	if _, err := tx.Exec(ctx,
		`UPDATE scan_jobs SET status = 'claimed', claimed_at = NOW() WHERE id = $1`,
		jobID,
	); err != nil {
		return JobPayload{}, false, fmt.Errorf("update claim scan job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return JobPayload{}, false, fmt.Errorf("commit claim scan job: %w", err)
	}
	return payload, true, nil
}

// loadHostTargets hydrates HostTarget rows from inventory_hosts. INET
// addresses are cast to text and stripped of any /32 or /128 prefix —
// host-scoped INET values always carry a single-host mask in
// PostgreSQL and the engine wants a bare address for SSH dial.
func loadHostTargets(ctx context.Context, tx pgx.Tx, hostIDs []uuid.UUID) ([]HostTarget, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx,
		`SELECT id, COALESCE(address::text, ''),
		        COALESCE(hostname, ''), COALESCE(os, '')
		 FROM inventory_hosts WHERE id = ANY($1)`,
		hostIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("query host targets: %w", err)
	}
	defer rows.Close()

	out := make([]HostTarget, 0, len(hostIDs))
	for rows.Next() {
		var h HostTarget
		var addr string
		if err := rows.Scan(&h.ID, &addr, &h.Hostname, &h.OS); err != nil {
			return nil, fmt.Errorf("scan host target: %w", err)
		}
		if i := strings.IndexByte(addr, '/'); i >= 0 {
			addr = addr[:i]
		}
		h.Address = addr
		out = append(out, h)
	}
	return out, rows.Err()
}

// UpdateProgress increments per-host counters and flips a still-claimed
// job to running on the first call. Atomic in a single UPDATE so
// concurrent progress events from a multi-host engine never race.
func (s *PostgresStore) UpdateProgress(ctx context.Context, jobID uuid.UUID, done, failed int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs
		 SET progress_done   = progress_done + $2,
		     progress_failed = progress_failed + $3,
		     status          = CASE WHEN status = 'claimed' THEN 'running' ELSE status END
		 WHERE id = $1`,
		jobID, done, failed,
	)
	if err != nil {
		return fmt.Errorf("update scan job progress: %w", err)
	}
	return nil
}

// FinishJob transitions a job to its terminal state. Returns
// ErrJobAlreadyTerminal if the row is already completed/failed/cancelled.
func (s *PostgresStore) FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs
		 SET status = $1, error = NULLIF($2, ''), completed_at = NOW()
		 WHERE id = $3 AND status NOT IN ('completed', 'failed', 'cancelled')`,
		string(status), errMsg, jobID,
	)
	if err != nil {
		return fmt.Errorf("finish scan job: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrJobAlreadyTerminal
	}
	return nil
}

// ReclaimStale returns claimed/running jobs whose claimed_at is older
// than cutoff to the queued state so another engine can pick them up.
// Idempotent.
func (s *PostgresStore) ReclaimStale(ctx context.Context, cutoff time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs
		 SET status = 'queued', claimed_at = NULL
		 WHERE status IN ('claimed', 'running')
		   AND claimed_at IS NOT NULL
		   AND claimed_at < $1`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("reclaim stale scan jobs: %w", err)
	}
	return nil
}

// RecordScanResult unmarshals the JSON-marshalled ScanResult and
// delegates to the underlying scan store, which writes the scan row +
// findings tagged with engine_id + scan_job_id atomically.
//
// hostID is currently unused in persistence (the scan blob already
// carries Metadata.Hostname) but is part of the interface so future
// tagging — e.g. inventory_hosts.last_scan_id — can land without a
// signature change.
func (s *PostgresStore) RecordScanResult(ctx context.Context, jobID, engineID, hostID uuid.UUID, scanPayload []byte) error {
	_ = hostID
	if s.scanStore == nil {
		return fmt.Errorf("record scan result: scan store not configured")
	}
	var scan model.ScanResult
	if err := json.Unmarshal(scanPayload, &scan); err != nil {
		return fmt.Errorf("unmarshal scan result: %w", err)
	}
	return s.scanStore.SaveScanWithJobContext(ctx, &scan, engineID, jobID)
}
