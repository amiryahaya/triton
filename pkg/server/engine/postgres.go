package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pool. The caller owns the pool's lifetime.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) UpsertCA(ctx context.Context, orgID uuid.UUID, ca *CA) error {
	if ca == nil {
		return errors.New("nil CA")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO engine_cas (org_id, ca_cert_pem, ca_key_encrypted, ca_key_nonce)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id) DO UPDATE SET
		   ca_cert_pem      = EXCLUDED.ca_cert_pem,
		   ca_key_encrypted = EXCLUDED.ca_key_encrypted,
		   ca_key_nonce     = EXCLUDED.ca_key_nonce`,
		orgID, string(ca.CACertPEM), ca.CAKeyEncrypted, ca.CAKeyNonce,
	)
	if err != nil {
		return fmt.Errorf("upsert engine CA: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetCA(ctx context.Context, orgID uuid.UUID) (*CA, error) {
	var ca CA
	var pemStr string
	row := s.pool.QueryRow(ctx,
		`SELECT ca_cert_pem, ca_key_encrypted, ca_key_nonce
		 FROM engine_cas WHERE org_id = $1`,
		orgID,
	)
	if err := row.Scan(&pemStr, &ca.CAKeyEncrypted, &ca.CAKeyNonce); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w for org %s", ErrCANotFound, orgID)
		}
		return nil, fmt.Errorf("get engine CA: %w", err)
	}
	ca.CACertPEM = []byte(pemStr)
	return &ca, nil
}

func (s *PostgresStore) CreateEngine(ctx context.Context, e Engine) (Engine, error) {
	var ipArg any
	if e.PublicIP != nil {
		ipArg = e.PublicIP.String()
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO engines (id, org_id, label, public_ip, cert_fingerprint, status)
		 VALUES ($1, $2, $3, $4, $5, COALESCE(NULLIF($6, ''), 'enrolled'))
		 RETURNING bundle_issued_at, status`,
		e.ID, e.OrgID, e.Label, ipArg, e.CertFingerprint, e.Status,
	)
	if err := row.Scan(&e.BundleIssuedAt, &e.Status); err != nil {
		return Engine{}, fmt.Errorf("create engine: %w", err)
	}
	return e, nil
}

// engineSelectCols matches the column order expected by scanEngine.
const engineSelectCols = `id, org_id, label, public_ip::text, cert_fingerprint,
		bundle_issued_at, first_seen_at, last_poll_at, status, revoked_at`

func scanEngine(scanner pgx.Row) (Engine, error) {
	var e Engine
	var ip *string
	if err := scanner.Scan(
		&e.ID, &e.OrgID, &e.Label, &ip, &e.CertFingerprint,
		&e.BundleIssuedAt, &e.FirstSeenAt, &e.LastPollAt, &e.Status, &e.RevokedAt,
	); err != nil {
		return Engine{}, err
	}
	if ip != nil {
		a := *ip
		if idx := strings.IndexByte(a, '/'); idx >= 0 {
			a = a[:idx]
		}
		e.PublicIP = net.ParseIP(a)
	}
	return e, nil
}

func (s *PostgresStore) GetEngine(ctx context.Context, orgID, id uuid.UUID) (Engine, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+engineSelectCols+` FROM engines WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	e, err := scanEngine(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Engine{}, fmt.Errorf("%w: %s in org %s", ErrEngineNotFound, id, orgID)
		}
		return Engine{}, fmt.Errorf("get engine: %w", err)
	}
	return e, nil
}

func (s *PostgresStore) GetEngineByFingerprint(ctx context.Context, fingerprint string) (Engine, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+engineSelectCols+` FROM engines WHERE cert_fingerprint = $1`,
		fingerprint,
	)
	e, err := scanEngine(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Engine{}, fmt.Errorf("%w: fingerprint %s", ErrEngineNotFound, fingerprint)
		}
		return Engine{}, fmt.Errorf("get engine by fingerprint: %w", err)
	}
	return e, nil
}

func (s *PostgresStore) ListEngines(ctx context.Context, orgID uuid.UUID) ([]Engine, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+engineSelectCols+` FROM engines WHERE org_id = $1 ORDER BY label`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list engines: %w", err)
	}
	defer rows.Close()

	out := []Engine{}
	for rows.Next() {
		e, err := scanEngine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RecordFirstSeen(ctx context.Context, id uuid.UUID, publicIP string) (bool, error) {
	var ipArg any
	if publicIP != "" {
		ipArg = publicIP
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE engines
		 SET first_seen_at = NOW(),
		     public_ip = COALESCE($2::inet, public_ip),
		     status = 'online'
		 WHERE id = $1 AND first_seen_at IS NULL`,
		id, ipArg,
	)
	if err != nil {
		return false, fmt.Errorf("record first-seen: %w", err)
	}
	return ct.RowsAffected() == 1, nil
}

func (s *PostgresStore) RecordPoll(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE engines SET last_poll_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("record poll: %w", err)
	}
	return nil
}

func (s *PostgresStore) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE engines SET status = $2 WHERE id = $1`,
		id, status,
	)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	return nil
}

func (s *PostgresStore) Revoke(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE engines SET status = 'revoked', revoked_at = NOW()
		 WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	if err != nil {
		return fmt.Errorf("revoke engine: %w", err)
	}
	return nil
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)
