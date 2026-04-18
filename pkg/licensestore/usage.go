package licensestore

import (
	"context"
	"fmt"
	"time"
)

// UsageReport is one row in POST /v1/license/usage body + the DB row.
type UsageReport struct {
	LicenseID  string    `json:"-"` // set server-side from the licence key lookup
	InstanceID string    `json:"-"` // set server-side from the request body
	Metric     string    `json:"metric"`
	Window     string    `json:"window"`
	Value      int64     `json:"value"`
	ReportedAt time.Time `json:"reported_at,omitempty"`
}

// UpsertUsage writes a batch of usage reports, upserting on
// (license_id, instance_id, metric, window). Empty batch is a no-op.
func (s *PostgresStore) UpsertUsage(ctx context.Context, reports []UsageReport) error {
	if len(reports) == 0 {
		return nil
	}
	const q = `
INSERT INTO license_usage (license_id, instance_id, metric, "window", value, reported_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (license_id, instance_id, metric, "window")
DO UPDATE SET value = EXCLUDED.value, reported_at = NOW()`

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback is a no-op if the tx has already been committed — safe to ignore err.
	defer func() { _ = tx.Rollback(ctx) }()

	for _, r := range reports {
		if _, err := tx.Exec(ctx, q, r.LicenseID, r.InstanceID, r.Metric, r.Window, r.Value); err != nil {
			return fmt.Errorf("upsert %s/%s: %w", r.Metric, r.Window, err)
		}
	}
	return tx.Commit(ctx)
}

// UsageSummary aggregates the latest value per (metric, window) across all
// instances of a licence. Returned map[metric][window] = sum.
//
// This is the authoritative "how much has this licence used" number used by
// the LS to compute `remaining` and over-cap flags in /v1/license/usage.
func (s *PostgresStore) UsageSummary(ctx context.Context, licenseID string) (map[string]map[string]int64, error) {
	const q = `
SELECT metric, "window", COALESCE(SUM(value), 0)
FROM license_usage
WHERE license_id = $1
GROUP BY metric, "window"`

	rows, err := s.pool.Query(ctx, q, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]map[string]int64)
	for rows.Next() {
		var metric, window string
		var val int64
		if err := rows.Scan(&metric, &window, &val); err != nil {
			return nil, err
		}
		if out[metric] == nil {
			out[metric] = make(map[string]int64)
		}
		out[metric][window] = val
	}
	return out, rows.Err()
}

// UsageByInstance returns the per-instance rows for observability (Admin UI).
func (s *PostgresStore) UsageByInstance(ctx context.Context, licenseID string) ([]UsageReport, error) {
	const q = `
SELECT instance_id, metric, "window", value, reported_at
FROM license_usage
WHERE license_id = $1
ORDER BY instance_id, metric, "window"`

	rows, err := s.pool.Query(ctx, q, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UsageReport
	for rows.Next() {
		r := UsageReport{LicenseID: licenseID}
		if err := rows.Scan(&r.InstanceID, &r.Metric, &r.Window, &r.Value, &r.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
