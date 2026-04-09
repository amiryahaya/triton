package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amiryahaya/triton/pkg/model"
)

// BackfillFindings walks every scan row where findings_extracted_at is
// NULL, unpacks result_json, extracts crypto findings, inserts them,
// and sets the marker. Safe to call repeatedly. Safe to interrupt
// mid-run — next call resumes from the next unprocessed scan.
//
// Intended to be called once from cmd/server.go after migrations run,
// in a background goroutine so it doesn't block the HTTP listener. On
// per-scan failure the scan is MARKED anyway so we don't retry forever
// on a corrupt blob; operators investigate via logs.
//
// See docs/plans/2026-04-09-analytics-phase-1-design.md §5 and the
// plan's Appendix A.9.
func (s *PostgresStore) BackfillFindings(ctx context.Context) error {
	const batchSize = 100
	total := 0
	start := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			log.Printf("backfill: context cancelled after %d scans: %v", total, err)
			return nil
		}

		scans, err := s.selectUnbackfilledScans(ctx, batchSize)
		if err != nil {
			return fmt.Errorf("backfill: select unbackfilled: %w", err)
		}
		if len(scans) == 0 {
			log.Printf("backfill: done — processed %d scans in %s", total, time.Since(start))
			return nil
		}

		for _, scanID := range scans {
			if err := ctx.Err(); err != nil {
				log.Printf("backfill: context cancelled mid-batch after %d scans", total)
				return nil
			}
			if err := s.extractAndInsertOneScan(ctx, scanID); err != nil {
				log.Printf("backfill: scan %s failed: %v — marking as processed anyway", scanID, err)
				s.backfillScansFailed.Add(1)
			} else {
				s.backfillScansTotal.Add(1)
			}
			if err := s.markScanBackfilled(ctx, scanID); err != nil {
				return fmt.Errorf("backfill: mark scan %s: %w", scanID, err)
			}
			total++
		}
		log.Printf("backfill: progress — %d scans processed", total)
	}
}

// selectUnbackfilledScans returns up to `limit` scan IDs whose
// findings_extracted_at is NULL. Ordered by ID for determinism.
func (s *PostgresStore) selectUnbackfilledScans(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM scans
		WHERE findings_extracted_at IS NULL
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// extractAndInsertOneScan fetches a scan, decrypts + unmarshals the
// blob, runs ExtractFindings, and bulk-inserts the result inside a
// transaction.
func (s *PostgresStore) extractAndInsertOneScan(ctx context.Context, scanID string) error {
	var (
		blob     []byte
		orgID    string
		hostname string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT result_json, COALESCE(org_id::text, ''), hostname
		FROM scans WHERE id = $1
	`, scanID).Scan(&blob, &orgID, &hostname)
	if err != nil {
		return fmt.Errorf("fetch scan: %w", err)
	}

	// Decrypt if configured. No-op when encryptor is nil.
	if enc := s.loadEncryptor(); enc != nil {
		decrypted, decErr := enc.Decrypt(blob)
		if decErr != nil {
			return fmt.Errorf("decrypt scan: %w", decErr)
		}
		blob = decrypted
	}

	var scan model.ScanResult
	if err := json.Unmarshal(blob, &scan); err != nil {
		return fmt.Errorf("unmarshal scan: %w", err)
	}

	// Rehydrate row-level fields so ExtractFindings gets the right
	// values — the persisted blob may have empty OrgID/Hostname.
	scan.ID = scanID
	if scan.OrgID == "" {
		scan.OrgID = orgID
	}
	if scan.Metadata.Hostname == "" {
		scan.Metadata.Hostname = hostname
	}

	findings := ExtractFindings(&scan)
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertFindingsInTx(ctx, tx, findings); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// markScanBackfilled sets findings_extracted_at = NOW() for the given scan.
func (s *PostgresStore) markScanBackfilled(ctx context.Context, scanID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NOW() WHERE id = $1`, scanID)
	return err
}
