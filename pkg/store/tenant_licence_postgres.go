package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) GetOrCreateInstance(ctx context.Context) (*ReportInstance, error) {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO report_instance (id) VALUES (gen_random_uuid()) ON CONFLICT DO NOTHING`)
	if err != nil {
		return nil, fmt.Errorf("ensuring report instance: %w", err)
	}
	var inst ReportInstance
	err = s.pool.QueryRow(ctx,
		`SELECT id, created_at FROM report_instance LIMIT 1`).
		Scan(&inst.ID, &inst.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("reading report instance: %w", err)
	}
	return &inst, nil
}

func (s *PostgresStore) GetTenantLicence(ctx context.Context, orgID string) (*TenantLicence, error) {
	var tl TenantLicence
	err := s.pool.QueryRow(ctx,
		`SELECT org_id, licence_id, token, activated_at, expires_at, renewed_at, status
		 FROM tenant_licences WHERE org_id = $1`, orgID).
		Scan(&tl.OrgID, &tl.LicenceID, &tl.Token, &tl.ActivatedAt,
			&tl.ExpiresAt, &tl.RenewedAt, &tl.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "tenant_licence", ID: orgID}
		}
		return nil, fmt.Errorf("getting tenant licence: %w", err)
	}
	return &tl, nil
}

func (s *PostgresStore) UpsertTenantLicence(ctx context.Context, tl *TenantLicence) error {
	if tl.ActivatedAt.IsZero() {
		tl.ActivatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenant_licences (org_id, licence_id, token, activated_at, expires_at, renewed_at, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (org_id) DO UPDATE SET
		     licence_id   = EXCLUDED.licence_id,
		     token        = EXCLUDED.token,
		     expires_at   = EXCLUDED.expires_at,
		     renewed_at   = EXCLUDED.renewed_at,
		     status       = EXCLUDED.status`,
		tl.OrgID, tl.LicenceID, tl.Token, tl.ActivatedAt,
		tl.ExpiresAt, tl.RenewedAt, tl.Status,
	)
	if err != nil {
		return fmt.Errorf("upserting tenant licence: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListTenantLicences(ctx context.Context) ([]TenantLicence, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT org_id, licence_id, token, activated_at, expires_at, renewed_at, status
		 FROM tenant_licences ORDER BY activated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing tenant licences: %w", err)
	}
	defer rows.Close()

	out := []TenantLicence{} // never return nil
	for rows.Next() {
		var tl TenantLicence
		if err := rows.Scan(&tl.OrgID, &tl.LicenceID, &tl.Token, &tl.ActivatedAt,
			&tl.ExpiresAt, &tl.RenewedAt, &tl.Status); err != nil {
			return nil, fmt.Errorf("scanning tenant licence: %w", err)
		}
		out = append(out, tl)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteTenantLicence(ctx context.Context, orgID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM tenant_licences WHERE org_id = $1`, orgID)
	if err != nil {
		return fmt.Errorf("deleting tenant licence: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "tenant_licence", ID: orgID}
	}
	return nil
}
