package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a shared pgx pool. Caller owns
// the pool's lifetime; this package never Close()s it.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pool. The caller must have already run
// managestore.Migrate to v5 or later so manage_agents exists.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction.
var _ Store = (*PostgresStore)(nil)

// isUniqueViolation reports whether err wraps a Postgres unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// agentSelectCols keeps the SELECT list consistent across single-row
// lookups. Status is TEXT-typed in the DB; Scan into a string then
// caller casts to AgentStatus. PendingCommand is JSONB.
const agentSelectCols = `id, name, cert_serial, cert_expires_at,
	status, last_seen_at, pending_command, created_at, updated_at`

// scanAgent reads the agent columns from a pgx.Row into an Agent.
// Extracted so List + Get + GetByCertSerial share column order.
func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	var status string
	var rawCmd []byte // for pending_command JSONB
	err := row.Scan(
		&a.ID, &a.Name, &a.CertSerial, &a.CertExpiresAt,
		&status, &a.LastSeenAt, &rawCmd, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return Agent{}, err
	}
	a.Status = AgentStatus(status)
	if rawCmd != nil {
		var cmd AgentCommand
		if err := json.Unmarshal(rawCmd, &cmd); err != nil {
			return Agent{}, fmt.Errorf("agents: unmarshal pending_command: %w", err)
		}
		a.PendingCommand = &cmd
	}
	return a, nil
}

// Create inserts a new agent. The DB generates created_at + updated_at;
// the caller supplies ID (so the same UUID can be used as the cert CN).
func (s *PostgresStore) Create(ctx context.Context, a Agent) (Agent, error) {
	if a.ID == uuid.Nil {
		return Agent{}, fmt.Errorf("agent ID must be set by caller")
	}
	if a.Status == "" {
		a.Status = StatusPending
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO manage_agents
		   (id, name, cert_serial, cert_expires_at, status)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING created_at, updated_at`,
		a.ID, a.Name, a.CertSerial, a.CertExpiresAt, string(a.Status),
	).Scan(&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Agent{}, fmt.Errorf("%w: cert_serial %q", ErrConflict, a.CertSerial)
		}
		return Agent{}, fmt.Errorf("create agent: %w", err)
	}
	return a, nil
}

// Get fetches an agent by id.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Agent, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+` FROM manage_agents WHERE id = $1`, id,
	)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return a, nil
}

// GetByCertSerial looks up an agent by its current cert serial.
func (s *PostgresStore) GetByCertSerial(ctx context.Context, serial string) (Agent, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+` FROM manage_agents WHERE cert_serial = $1`, serial,
	)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("get agent by cert serial: %w", err)
	}
	return a, nil
}

// List returns every agent ordered by name.
func (s *PostgresStore) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentSelectCols+` FROM manage_agents ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkActive flips status→active and stamps last_seen_at=NOW. Guarded
// against revoked agents — a revoked agent that somehow slips past
// gateway auth should not silently re-activate.
func (s *PostgresStore) MarkActive(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_agents
		    SET status = 'active',
		        last_seen_at = NOW(),
		        updated_at = NOW()
		  WHERE id = $1 AND status != 'revoked'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("mark agent active: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the agent doesn't exist, or it's revoked. Either way,
		// surface as ErrNotFound so the gateway handler can 404/401.
		return ErrNotFound
	}
	return nil
}

// UpdateCert replaces cert_serial + cert_expires_at.
func (s *PostgresStore) UpdateCert(ctx context.Context, id uuid.UUID, newSerial string, expiresAt time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_agents
		    SET cert_serial = $2,
		        cert_expires_at = $3,
		        updated_at = NOW()
		  WHERE id = $1`,
		id, newSerial, expiresAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: cert_serial %q", ErrConflict, newSerial)
		}
		return fmt.Errorf("update agent cert: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Revoke flips status→revoked. Caller writes the revocation row
// separately via ca.Store.Revoke.
func (s *PostgresStore) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_agents
		    SET status = 'revoked',
		        updated_at = NOW()
		  WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Count returns the total number of agent rows.
func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_agents`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count agents: %w", err)
	}
	return n, nil
}

// SetCommand stores a pending scan command on the agent row, overwriting
// any previous value. Pass nil to clear without popping.
func (s *PostgresStore) SetCommand(ctx context.Context, id uuid.UUID, cmd *AgentCommand) error {
	var raw []byte
	if cmd != nil {
		var err error
		raw, err = json.Marshal(cmd)
		if err != nil {
			return fmt.Errorf("agents: marshal command: %w", err)
		}
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_agents SET pending_command = $1, updated_at = NOW() WHERE id = $2`,
		raw, id,
	)
	if err != nil {
		return fmt.Errorf("agents: set command: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PopCommand atomically reads and clears the pending command for the agent.
// Returns (nil, nil) when no command is pending. Returns ErrNotFound when
// the agent row does not exist.
//
// The CTE captures the old pending_command value before the UPDATE sets it
// to NULL, because PostgreSQL's RETURNING reflects the new (post-update)
// values, which would always be NULL here.
func (s *PostgresStore) PopCommand(ctx context.Context, id uuid.UUID) (*AgentCommand, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`WITH prev AS (
			SELECT pending_command FROM manage_agents WHERE id = $1 FOR UPDATE
		)
		UPDATE manage_agents
		SET pending_command = NULL, updated_at = NOW()
		FROM prev
		WHERE manage_agents.id = $1
		RETURNING prev.pending_command`,
		id,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("agents: pop command: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	var cmd AgentCommand
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return nil, fmt.Errorf("agents: unmarshal command: %w", err)
	}
	return &cmd, nil
}
