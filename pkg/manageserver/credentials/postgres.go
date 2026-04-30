package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against manage_credentials.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a PostgresStore backed by the given connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

const credSelectCols = `id, tenant_id, name, auth_type, vault_path, created_at, updated_at,
    (SELECT COUNT(*) FROM manage_hosts h WHERE h.credentials_ref = manage_credentials.id) AS in_use_count`

func scanCred(row pgx.Row) (Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.AuthType, &c.VaultPath, &c.CreatedAt, &c.UpdatedAt, &c.InUseCount)
	return c, err
}

// List returns all credentials for the given tenant, ordered by name.
func (s *PostgresStore) List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+credSelectCols+` FROM manage_credentials WHERE tenant_id = $1 ORDER BY name`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Credential{}
	}
	return out, nil
}

// Get returns a single credential by ID, or ErrCredentialNotFound if absent.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Credential, error) {
	c, err := scanCred(s.pool.QueryRow(ctx,
		`SELECT `+credSelectCols+` FROM manage_credentials WHERE id = $1`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("get credential: %w", err)
	}
	return c, nil
}

// Create inserts a new credential record and returns the persisted row.
// Returns ErrConflict if a credential with the same name already exists for the tenant.
func (s *PostgresStore) Create(ctx context.Context, c Credential) (Credential, error) {
	// INSERT then SELECT to avoid table-alias issues in RETURNING with subquery.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_credentials (id, tenant_id, name, auth_type, vault_path)
         VALUES ($1, $2, $3, $4, $5)`,
		c.ID, c.TenantID, c.Name, string(c.AuthType), c.VaultPath,
	)
	if isUniqueViolation(err) {
		return Credential{}, ErrConflict
	}
	if err != nil {
		return Credential{}, fmt.Errorf("create credential: %w", err)
	}
	return s.Get(ctx, c.ID)
}

// Update bumps updated_at on the credential row. The Vault secret write happens
// in the handler; this method only tracks the timestamp in the DB.
func (s *PostgresStore) Update(ctx context.Context, id uuid.UUID, _ SecretPayload) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_credentials SET updated_at = NOW() WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

// Delete removes a credential by ID.
// Returns ErrCredentialNotFound if the row did not exist.
func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM manage_credentials WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

// CountHosts returns the number of manage_hosts rows that reference credID.
func (s *PostgresStore) CountHosts(ctx context.Context, credID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_hosts WHERE credentials_ref = $1`, credID,
	).Scan(&n)
	return n, err
}
