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
	"github.com/amiryahaya/triton/pkg/server/jobqueue"
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
// scanStore is the narrow scan-persistence dependency. Queue operations
// (claim, cancel, reclaim) are delegated to the embedded jobqueue.Queue;
// domain-specific enrichment remains here.
type PostgresStore struct {
	pool      *pgxpool.Pool
	scanStore scanStoreAPI
	queue     *jobqueue.Queue
}

// NewPostgresStore wires the dependencies. scanStore may be nil during
// admin-only flows, but RecordScanResult will panic if invoked without
// it (the Phase-5 gateway always provides one).
func NewPostgresStore(pool *pgxpool.Pool, scanStore scanStoreAPI) *PostgresStore {
	q := jobqueue.New(pool, jobqueue.Config{
		Table:             "scan_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"completed", "failed", "cancelled"},
	})
	return &PostgresStore{pool: pool, scanStore: scanStore, queue: q}
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
// (409) via the generic jobqueue.Queue implementation.
func (s *PostgresStore) CancelJob(ctx context.Context, orgID, id uuid.UUID) error {
	err := s.queue.Cancel(ctx, orgID, id)
	switch {
	case errors.Is(err, jobqueue.ErrNotFound):
		return ErrJobNotFound
	case errors.Is(err, jobqueue.ErrNotCancellable):
		return ErrJobNotCancellable
	default:
		return err
	}
}

// ClaimNext atomically grabs the oldest queued job for engineID via
// the generic jobqueue claim, then enriches the wire payload with
// resolved host addresses + credential metadata.
//
// Port resolution: ssh-* → 22, winrm-* → 5985, no credential → 22.
// Address comes from inventory_hosts.address (INET, the /32 or /128
// suffix is stripped before being returned to the engine).
func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (JobPayload, bool, error) {
	id, found, err := s.queue.ClaimNextID(ctx, engineID)
	if !found || err != nil {
		return JobPayload{}, false, err
	}
	return s.enrichClaimedJob(ctx, id)
}

// enrichClaimedJob loads the claimed row's fields and resolves host
// targets + credential metadata into a wire-ready JobPayload.
func (s *PostgresStore) enrichClaimedJob(ctx context.Context, jobID uuid.UUID) (JobPayload, bool, error) {
	var (
		hostIDs       []uuid.UUID
		profileStr    string
		credProfileID *uuid.UUID
	)
	err := s.pool.QueryRow(ctx,
		`SELECT host_ids, scan_profile, credential_profile_id
		 FROM scan_jobs WHERE id = $1`,
		jobID,
	).Scan(&hostIDs, &profileStr, &credProfileID)
	if err != nil {
		return JobPayload{}, false, fmt.Errorf("enrich claimed scan job: %w", err)
	}

	hosts, err := loadHostTargetsFromPool(ctx, s.pool, hostIDs)
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
		if err := s.pool.QueryRow(ctx,
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
	return payload, true, nil
}

// querier is the pgx query interface shared by *pgxpool.Pool and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadHostTargetsFromPool hydrates HostTarget rows using the connection
// pool (for use after the claim transaction has committed).
func loadHostTargetsFromPool(ctx context.Context, pool *pgxpool.Pool, hostIDs []uuid.UUID) ([]HostTarget, error) {
	return loadHostTargetsFrom(ctx, pool, hostIDs)
}

// loadHostTargets hydrates HostTarget rows from inventory_hosts using a
// transaction (retained for backward compatibility with any callers
// that need transactional reads).
func loadHostTargets(ctx context.Context, tx pgx.Tx, hostIDs []uuid.UUID) ([]HostTarget, error) {
	return loadHostTargetsFrom(ctx, tx, hostIDs)
}

// loadHostTargetsFrom is the shared implementation. INET addresses are
// cast to text and stripped of any /32 or /128 prefix — host-scoped
// INET values always carry a single-host mask in PostgreSQL and the
// engine wants a bare address for SSH dial.
func loadHostTargetsFrom(ctx context.Context, q querier, hostIDs []uuid.UUID) ([]HostTarget, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx,
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
// than cutoff to the queued state. Delegates to jobqueue.Queue.
func (s *PostgresStore) ReclaimStale(ctx context.Context, cutoff time.Time) error {
	return s.queue.ReclaimStale(ctx, cutoff)
}

// RecordScanResult unmarshals the JSON-marshalled ScanResult and
// delegates to the underlying scan store, which writes the scan row +
// findings tagged with engine_id + scan_job_id atomically.
//
// hostID is currently unused in persistence (the scan blob already
// carries Metadata.Hostname) but is part of the interface so future
// tagging — e.g. inventory_hosts.last_scan_id — can land without a
// signature change.
//
// NOTE (TOCTOU): The ownership+status check below runs outside the
// SaveScanWithJobContext transaction. A race is theoretically possible
// where the reaper reclaims the job between the check and the insert.
// Accepted for Phase 7: the consequence is a phantom scan row tagged to
// the wrong engine, which is detectable + correctable. A transactional
// wrap would require SaveScanWithJobContext to accept an external tx.
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
