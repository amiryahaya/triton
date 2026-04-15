package inventory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateGroup(ctx context.Context, g Group) (Group, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO inventory_groups (id, org_id, name, description, created_by)
		 VALUES ($1, $2, $3, NULLIF($4, ''), $5)
		 RETURNING created_at`,
		g.ID, g.OrgID, g.Name, g.Description, g.CreatedBy,
	)
	if err := row.Scan(&g.CreatedAt); err != nil {
		return Group{}, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

func (s *PostgresStore) GetGroup(ctx context.Context, orgID, id uuid.UUID) (Group, error) {
	var g Group
	var desc *string
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, description, created_at, COALESCE(created_by, '00000000-0000-0000-0000-000000000000'::uuid)
		 FROM inventory_groups WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	if err := row.Scan(&g.ID, &g.OrgID, &g.Name, &desc, &g.CreatedAt, &g.CreatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, fmt.Errorf("group %s not found in org %s", id, orgID)
		}
		return Group{}, err
	}
	if desc != nil {
		g.Description = *desc
	}
	return g, nil
}

func (s *PostgresStore) ListGroups(ctx context.Context, orgID uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, COALESCE(description, ''), created_at, COALESCE(created_by, '00000000-0000-0000-0000-000000000000'::uuid)
		 FROM inventory_groups WHERE org_id = $1 ORDER BY name`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.CreatedAt, &g.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateGroup(ctx context.Context, orgID, id uuid.UUID, name, description string) (Group, error) {
	ct, err := s.pool.Exec(ctx,
		`UPDATE inventory_groups SET name = $3, description = NULLIF($4, '') WHERE org_id = $1 AND id = $2`,
		orgID, id, name, description,
	)
	if err != nil {
		return Group{}, err
	}
	if ct.RowsAffected() == 0 {
		return Group{}, fmt.Errorf("group %s not found in org %s", id, orgID)
	}
	return s.GetGroup(ctx, orgID, id)
}

func (s *PostgresStore) DeleteGroup(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM inventory_groups WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	return err
}

func (s *PostgresStore) CreateHost(ctx context.Context, h Host) (Host, error) {
	var addrArg any
	if h.Address != nil {
		addrArg = h.Address.String()
	} else {
		addrArg = nil
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO inventory_hosts (id, org_id, group_id, hostname, address, os, mode)
		 VALUES ($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), $7)
		 RETURNING created_at`,
		h.ID, h.OrgID, h.GroupID, h.Hostname, addrArg, h.OS, h.Mode,
	)
	if err := row.Scan(&h.CreatedAt); err != nil {
		return Host{}, fmt.Errorf("create host: %w", err)
	}
	return h, nil
}

func (s *PostgresStore) GetHost(ctx context.Context, orgID, id uuid.UUID) (Host, error) {
	var h Host
	var hostname, os *string
	var addr *string
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, group_id, hostname, address::text, os, mode, created_at
		 FROM inventory_hosts WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	if err := row.Scan(&h.ID, &h.OrgID, &h.GroupID, &hostname, &addr, &os, &h.Mode, &h.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, fmt.Errorf("host %s not found in org %s", id, orgID)
		}
		return Host{}, err
	}
	if hostname != nil {
		h.Hostname = *hostname
	}
	if os != nil {
		h.OS = *os
	}
	if addr != nil {
		a := *addr
		if idx := strings.IndexByte(a, '/'); idx >= 0 {
			a = a[:idx]
		}
		h.Address = net.ParseIP(a)
	}
	tags, err := s.GetTags(ctx, h.ID)
	if err != nil {
		return Host{}, err
	}
	h.Tags = tags
	return h, nil
}

func (s *PostgresStore) ListHosts(ctx context.Context, orgID uuid.UUID, f HostFilters) ([]Host, error) {
	q := `SELECT id, org_id, group_id, COALESCE(hostname, ''), address::text, COALESCE(os, ''), mode, created_at
	      FROM inventory_hosts WHERE org_id = $1`
	args := []any{orgID}
	if f.GroupID != nil {
		q += fmt.Sprintf(" AND group_id = $%d", len(args)+1)
		args = append(args, *f.GroupID)
	}
	if f.OS != "" {
		q += fmt.Sprintf(" AND os = $%d", len(args)+1)
		args = append(args, f.OS)
	}
	if f.Mode != "" {
		q += fmt.Sprintf(" AND mode = $%d", len(args)+1)
		args = append(args, f.Mode)
	}
	q += " ORDER BY hostname"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		var h Host
		var addr *string
		if err := rows.Scan(&h.ID, &h.OrgID, &h.GroupID, &h.Hostname, &addr, &h.OS, &h.Mode, &h.CreatedAt); err != nil {
			return nil, err
		}
		if addr != nil {
			a := *addr
			if idx := strings.IndexByte(a, '/'); idx >= 0 {
				a = a[:idx]
			}
			h.Address = net.ParseIP(a)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateHost(ctx context.Context, orgID, id uuid.UUID, p HostPatch) (Host, error) {
	var sets []string
	args := []any{orgID, id}
	if p.GroupID != nil {
		sets = append(sets, fmt.Sprintf("group_id = $%d", len(args)+1))
		args = append(args, *p.GroupID)
	}
	if p.Hostname != nil {
		sets = append(sets, fmt.Sprintf("hostname = NULLIF($%d, '')", len(args)+1))
		args = append(args, *p.Hostname)
	}
	if p.OS != nil {
		sets = append(sets, fmt.Sprintf("os = NULLIF($%d, '')", len(args)+1))
		args = append(args, *p.OS)
	}
	if p.Mode != nil {
		sets = append(sets, fmt.Sprintf("mode = $%d", len(args)+1))
		args = append(args, *p.Mode)
	}
	if len(sets) > 0 {
		q := "UPDATE inventory_hosts SET " + strings.Join(sets, ", ") + " WHERE org_id = $1 AND id = $2"
		if _, err := s.pool.Exec(ctx, q, args...); err != nil {
			return Host{}, err
		}
	}
	return s.GetHost(ctx, orgID, id)
}

func (s *PostgresStore) DeleteHost(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM inventory_hosts WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	return err
}

func (s *PostgresStore) SetTags(ctx context.Context, hostID uuid.UUID, tags []Tag) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after successful Commit is a documented no-op (pgx returns ErrTxClosed, which is not an error condition here).

	if _, err := tx.Exec(ctx, `DELETE FROM inventory_tags WHERE host_id = $1`, hostID); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := tx.Exec(ctx,
			`INSERT INTO inventory_tags (host_id, key, value) VALUES ($1, $2, $3)`,
			hostID, t.Key, t.Value,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) GetTags(ctx context.Context, hostID uuid.UUID) ([]Tag, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, value FROM inventory_tags WHERE host_id = $1 ORDER BY key`,
		hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Tag{}
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ImportHosts inserts rows one-by-one inside a single transaction,
// using a SAVEPOINT per row so a unique or CHECK violation aborts only
// the failing row. With dryRun=true the outer transaction is rolled
// back so no inserts persist, but the counts remain informative.
//
// Classification:
//   - Duplicate = unique_violation (23505) on (org_id, hostname) or
//     (org_id, address) partial indexes.
//   - Rejected = any other constraint failure (e.g., check_violation
//     on os/mode).
func (s *PostgresStore) ImportHosts(ctx context.Context, orgID, groupID uuid.UUID, rows []ImportRow, dryRun bool) (ImportResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ImportResult{}, fmt.Errorf("import hosts: begin tx: %w", err)
	}
	// Unconditional rollback is safe even after a successful Commit
	// (pgx returns ErrTxClosed, which we ignore).
	defer tx.Rollback(ctx) //nolint:errcheck // Rollback after successful Commit is a documented pgx no-op (ErrTxClosed).

	var res ImportResult
	for i, row := range rows {
		if _, err := tx.Exec(ctx, `SAVEPOINT r`); err != nil {
			return ImportResult{}, fmt.Errorf("import hosts: savepoint: %w", err)
		}

		hostID := uuid.Must(uuid.NewV7())
		mode := row.Mode
		if mode == "" {
			mode = "agentless"
		}

		var addrArg any
		if row.Address != "" {
			addrArg = row.Address
		} else {
			addrArg = nil
		}
		var osArg any
		if row.OS != "" {
			osArg = row.OS
		} else {
			osArg = nil
		}
		var hostnameArg any
		if row.Hostname != "" {
			hostnameArg = row.Hostname
		} else {
			hostnameArg = nil
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO inventory_hosts (id, org_id, group_id, hostname, address, os, mode)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			hostID, orgID, groupID, hostnameArg, addrArg, osArg, mode,
		)
		if err != nil {
			res.Errors = append(res.Errors, ImportError{Row: i, Error: classifyImportError(err)})
			if isUniqueViolation(err) {
				res.Duplicates++
			} else {
				res.Rejected++
			}
			if _, rbErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT r`); rbErr != nil {
				return ImportResult{}, fmt.Errorf("import hosts: rollback to savepoint: %w", rbErr)
			}
			continue
		}

		// Insert tags. If any tag fails, roll the whole row back so
		// we never persist a partially-tagged host.
		tagErr := error(nil)
		for _, t := range row.Tags {
			if _, err := tx.Exec(ctx,
				`INSERT INTO inventory_tags (host_id, key, value) VALUES ($1, $2, $3)`,
				hostID, t.Key, t.Value,
			); err != nil {
				tagErr = err
				break
			}
		}
		if tagErr != nil {
			res.Errors = append(res.Errors, ImportError{Row: i, Error: "tag insert failed: " + classifyImportError(tagErr)})
			res.Rejected++
			if _, rbErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT r`); rbErr != nil {
				return ImportResult{}, fmt.Errorf("import hosts: rollback to savepoint: %w", rbErr)
			}
			continue
		}

		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT r`); err != nil {
			return ImportResult{}, fmt.Errorf("import hosts: release savepoint: %w", err)
		}
		res.Accepted++
	}

	if dryRun {
		// Explicit rollback so callers don't rely on the defer.
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return ImportResult{}, fmt.Errorf("import hosts: dry-run rollback: %w", err)
		}
		return res, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return ImportResult{}, fmt.Errorf("import hosts: commit: %w", err)
	}
	return res, nil
}

// isUniqueViolation reports whether err is a PostgreSQL 23505
// (unique_violation).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// classifyImportError turns a raw pgx error into a user-friendly
// message. Unknown errors fall through to err.Error() — operators
// should still see enough to debug.
func classifyImportError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return "hostname or address already exists"
		case "23514":
			return "invalid os or mode value"
		case "22P02":
			return "invalid address format"
		}
	}
	return err.Error()
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)
