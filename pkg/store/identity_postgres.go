package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// --- Organizations ---

func (s *PostgresStore) CreateOrg(ctx context.Context, org *Organization) error {
	now := time.Now().UTC()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = now
	}
	if org.UpdatedAt.IsZero() {
		org.UpdatedAt = now
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO organizations (id, name, executive_target_percent, executive_deadline_year, created_at, updated_at)
		 VALUES ($1, $2, COALESCE(NULLIF($3::numeric, 0), 80.0), COALESCE(NULLIF($4::integer, 0), 2030), $5, $6)`,
		org.ID, org.Name, org.ExecutiveTargetPercent, org.ExecutiveDeadlineYear, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: "organization with this id already exists"}
		}
		return fmt.Errorf("creating organization: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
	var org Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, executive_target_percent, executive_deadline_year, created_at, updated_at
		 FROM organizations WHERE id = $1`, id,
	).Scan(&org.ID, &org.Name, &org.ExecutiveTargetPercent, &org.ExecutiveDeadlineYear, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "organization", ID: id}
		}
		return nil, fmt.Errorf("getting organization: %w", err)
	}
	return &org, nil
}

func (s *PostgresStore) ListOrgs(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, executive_target_percent, executive_deadline_year, created_at, updated_at
		 FROM organizations ORDER BY name LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	defer rows.Close()

	orgs := []Organization{} // never return nil
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.ExecutiveTargetPercent, &o.ExecutiveDeadlineYear, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *PostgresStore) UpdateOrg(ctx context.Context, org *Organization) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE organizations SET name = $2,
			executive_target_percent = COALESCE(NULLIF($3::numeric, 0), executive_target_percent),
			executive_deadline_year = COALESCE(NULLIF($4::integer, 0), executive_deadline_year),
			updated_at = $5 WHERE id = $1`,
		org.ID, org.Name, org.ExecutiveTargetPercent, org.ExecutiveDeadlineYear, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("updating organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "organization", ID: org.ID}
	}
	return nil
}

func (s *PostgresStore) DeleteOrg(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "organization", ID: id}
	}
	return nil
}

// --- Users ---

func (s *PostgresStore) CreateUser(ctx context.Context, user *User) error {
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}
	if user.InvitedAt.IsZero() {
		// Anchor the invite expiry window to the creation timestamp
		// by default. Explicit caller values are preserved so tests
		// can backdate invitations.
		user.InvitedAt = now
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, role, password, must_change_password, invited_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		user.ID, user.OrgID, user.Email, user.Name, user.Role, user.Password,
		user.MustChangePassword, user.InvitedAt, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: "user with this email already exists"}
		}
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

const userSelectColumns = `id, org_id, email, name, role, password, must_change_password, invited_at, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.Password,
		&u.MustChangePassword, &u.InvitedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userSelectColumns+` FROM users WHERE id = $1`, id)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "user", ID: id}
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return user, nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userSelectColumns+` FROM users WHERE email = $1`, email)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "user", ID: email}
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return user, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context, filter UserFilter) ([]User, error) {
	query := `SELECT ` + userSelectColumns + ` FROM users WHERE 1=1`
	args := []any{}
	idx := 0
	if filter.OrgID != "" {
		idx++
		query += fmt.Sprintf(" AND org_id = $%d", idx)
		args = append(args, filter.OrgID)
	}
	if filter.Role != "" {
		idx++
		query += fmt.Sprintf(" AND role = $%d", idx)
		args = append(args, filter.Role)
	}
	query += " ORDER BY name LIMIT 1000"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	users := []User{} // never return nil
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// UpdateUser applies a narrow update. The UserUpdate type has no Role or
// OrgID field by design — the type system enforces split-identity invariants.
// Password and MustChangePassword are partial: empty/nil means "unchanged".
func (s *PostgresStore) UpdateUser(ctx context.Context, update UserUpdate) error {
	// Build a dynamic UPDATE so we don't write columns the caller didn't
	// intend to change. name is always written (callers must supply current
	// value if not changing it).
	setClauses := []string{"name = $2", "updated_at = $3"}
	args := []any{update.ID, update.Name, time.Now().UTC()}
	idx := 4

	if update.Password != "" {
		setClauses = append(setClauses, fmt.Sprintf("password = $%d", idx))
		args = append(args, update.Password)
		idx++
	}
	if update.MustChangePassword != nil {
		setClauses = append(setClauses, fmt.Sprintf("must_change_password = $%d", idx))
		args = append(args, *update.MustChangePassword)
		idx++ //nolint:ineffassign // defensive: keep the invariant for any future field added below
	}
	_ = idx // silence unused-after-last-write linter

	query := "UPDATE users SET " + joinSetClauses(setClauses) + " WHERE id = $1"
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "user", ID: update.ID}
	}
	return nil
}

// joinSetClauses joins SET clauses with ", ". Extracted for clarity.
func joinSetClauses(clauses []string) string {
	out := ""
	for i, c := range clauses {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "user", ID: id}
	}
	return nil
}

// ResendInvite rotates a pending invite: replaces the bcrypt password
// hash with a new one (caller generates and hashes a fresh temp
// password) AND sets invited_at to now so the invite-expiry gate
// resets. The must_change_password flag is untouched — callers invoke
// this only for users who still have mcp=true; the handler layer
// enforces that precondition.
//
// Caller is responsible for returning the new temp password to the
// admin out-of-band (UI modal, email). This store method never sees
// the plaintext.
func (s *PostgresStore) ResendInvite(ctx context.Context, userID, newPasswordHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users
		   SET password = $2, invited_at = now(), updated_at = now()
		 WHERE id = $1 AND must_change_password = TRUE`,
		userID, newPasswordHash,
	)
	if err != nil {
		return fmt.Errorf("resending invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the user doesn't exist OR their mcp flag is already
		// false (i.e., they've completed the first-login flow, so
		// resend is nonsensical). Collapse both to NotFound so the
		// handler returns a non-leaking 404.
		return &ErrNotFound{Resource: "user", ID: userID}
	}
	return nil
}

func (s *PostgresStore) CountUsersByOrg(ctx context.Context, orgID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE org_id = $1`, orgID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting users: %w", err)
	}
	return count, nil
}

// --- Sessions ---

func (s *PostgresStore) CreateSession(ctx context.Context, sess *Session) error {
	now := time.Now().UTC()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		sess.ID, sess.UserID, sess.TokenHash, sess.ExpiresAt, sess.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return &ErrConflict{Message: "session with this token hash already exists"}
		}
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

// GetSessionByHash returns a session only if it exists AND has not expired.
// Filtering at the SQL level ensures callers can rely on a successful fetch
// meaning "valid right now" — mirroring the C4 fix from the license server.
func (s *PostgresStore) GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, created_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash,
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &ErrNotFound{Resource: "session", ID: tokenHash}
		}
		return nil, fmt.Errorf("getting session: %w", err)
	}
	return &sess, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return fmt.Errorf("deleting expired sessions: %w", err)
	}
	return nil
}
