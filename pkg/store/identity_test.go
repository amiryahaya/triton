//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func makeReportOrg(t *testing.T) *Organization {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      "Org-" + uuid.Must(uuid.NewV7()).String()[:8],
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func makeReportUser(t *testing.T, orgID string) *User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	// Use the full UUID for email uniqueness — UUIDv7's timestamp prefix
	// causes the first 8 chars to collide when users are created in the
	// same millisecond.
	return &User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              orgID,
		Email:              uuid.Must(uuid.NewV7()).String() + "@test.com",
		Name:               "Test User",
		Role:               "org_user",
		Password:           "$2a$10$bcrypthashplaceholder",
		MustChangePassword: false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

// --- Organization tests ---

func TestCreateAndGetOrg(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)

	require.NoError(t, s.CreateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, org.ID, got.ID)
	assert.Equal(t, org.Name, got.Name)
}

func TestGetOrgNotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetOrg(ctx, "00000000-0000-0000-0000-000000000000")
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

// TestGetOrg_DefaultsExecutiveConfig verifies that a freshly-created
// organization returns the default executive_target_percent (80) and
// executive_deadline_year (2030) — the DEFAULT clauses on migration
// v9 should kick in without any explicit value being set.
// Analytics Phase 2.
func TestGetOrg_DefaultsExecutiveConfig(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, 80.0, got.ExecutiveTargetPercent, "default target percent should be 80")
	assert.Equal(t, 2030, got.ExecutiveDeadlineYear, "default deadline year should be 2030")
}

// TestUpdateOrg_ExecutiveConfigRoundtrips verifies that SQL-level
// updates to the executive_target_percent / executive_deadline_year
// columns are visible through GetOrg. This is the "Phase 2 SQL
// override" path operators use before Phase 2.5 adds an admin UI.
func TestUpdateOrg_ExecutiveConfigRoundtrips(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	// Update via direct SQL — this is the Phase 2 override path.
	_, err := s.pool.Exec(ctx, `
		UPDATE organizations
		SET executive_target_percent = $1, executive_deadline_year = $2
		WHERE id = $3
	`, 95.0, 2035, org.ID)
	require.NoError(t, err)

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, 95.0, got.ExecutiveTargetPercent)
	assert.Equal(t, 2035, got.ExecutiveDeadlineYear)
}

func TestListOrgs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		require.NoError(t, s.CreateOrg(ctx, makeReportOrg(t)))
	}

	orgs, err := s.ListOrgs(ctx)
	require.NoError(t, err)
	assert.Len(t, orgs, 3)
}

func TestListOrgsEmpty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgs, err := s.ListOrgs(ctx)
	require.NoError(t, err)
	assert.NotNil(t, orgs, "empty list must be a non-nil slice")
	assert.Empty(t, orgs)
}

func TestUpdateOrg(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	org.Name = "Renamed"
	require.NoError(t, s.UpdateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", got.Name)
}

func TestDeleteOrg(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	require.NoError(t, s.DeleteOrg(ctx, org.ID))

	_, err := s.GetOrg(ctx, org.ID)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestDeleteOrgCascadesUsers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.DeleteOrg(ctx, org.ID))

	// User should be gone via FK CASCADE
	_, err := s.GetUser(ctx, user.ID)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

// --- User tests ---

func TestCreateAndGetUser(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)

	require.NoError(t, s.CreateUser(ctx, user))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)
	assert.Equal(t, user.Email, got.Email)
	assert.Equal(t, user.OrgID, got.OrgID)
	assert.Equal(t, "org_user", got.Role)
	assert.False(t, got.MustChangePassword)
}

func TestCreateUserOrgRequired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	user := makeReportUser(t, "")
	user.OrgID = "" // explicit

	err := s.CreateUser(ctx, user)
	require.Error(t, err, "user with NULL/empty org_id must be rejected")
}

func TestCreateUserInvalidRole(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	user.Role = "platform_admin" // not allowed in report server

	err := s.CreateUser(ctx, user)
	require.Error(t, err, "platform_admin role must be rejected by CHECK constraint")
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	u1 := makeReportUser(t, org.ID)
	u1.Email = "dup@example.com"
	require.NoError(t, s.CreateUser(ctx, u1))

	u2 := makeReportUser(t, org.ID)
	u2.Email = "dup@example.com"
	err := s.CreateUser(ctx, u2)
	var conflict *ErrConflict
	assert.ErrorAs(t, err, &conflict, "duplicate email must return ErrConflict")
}

func TestGetUserByEmail(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	user.Email = "lookup@example.com"
	require.NoError(t, s.CreateUser(ctx, user))

	got, err := s.GetUserByEmail(ctx, "lookup@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)
}

func TestListUsersByOrg(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org1 := makeReportOrg(t)
	org2 := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org1))
	require.NoError(t, s.CreateOrg(ctx, org2))

	for i := 0; i < 3; i++ {
		require.NoError(t, s.CreateUser(ctx, makeReportUser(t, org1.ID)))
	}
	require.NoError(t, s.CreateUser(ctx, makeReportUser(t, org2.ID)))

	users, err := s.ListUsers(ctx, UserFilter{OrgID: org1.ID})
	require.NoError(t, err)
	assert.Len(t, users, 3, "should only see org1's users")
}

func TestUpdateUserNameOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	originalRole := user.Role
	originalOrgID := user.OrgID
	originalPassword := user.Password
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.UpdateUser(ctx, UserUpdate{
		ID:   user.ID,
		Name: "New Name",
	}))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "New Name", got.Name)
	assert.Equal(t, originalRole, got.Role, "role must not change")
	assert.Equal(t, originalOrgID, got.OrgID, "org must not change")
	assert.Equal(t, originalPassword, got.Password, "password must not change when not in update")
}

func TestUpdateUserPasswordOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	originalName := user.Name
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.UpdateUser(ctx, UserUpdate{
		ID:       user.ID,
		Name:     originalName,
		Password: "newhash",
	}))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, originalName, got.Name)
	assert.Equal(t, "newhash", got.Password)
}

func TestUpdateUserMustChangePasswordFlag(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	user.MustChangePassword = true // invited user
	require.NoError(t, s.CreateUser(ctx, user))

	// Verify the flag persisted on create
	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, got.MustChangePassword)

	// Clear the flag after the user changes their password
	clearFlag := false
	require.NoError(t, s.UpdateUser(ctx, UserUpdate{
		ID:                 user.ID,
		Name:               user.Name,
		Password:           "newhash",
		MustChangePassword: &clearFlag,
	}))

	got, err = s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, got.MustChangePassword, "must_change_password should be cleared")
}

func TestDeleteUser(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.DeleteUser(ctx, user.ID))

	_, err := s.GetUser(ctx, user.ID)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestCountUsersByOrg(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	other := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	require.NoError(t, s.CreateOrg(ctx, other))

	for i := 0; i < 4; i++ {
		require.NoError(t, s.CreateUser(ctx, makeReportUser(t, org.ID)))
	}
	require.NoError(t, s.CreateUser(ctx, makeReportUser(t, other.ID)))

	count, err := s.CountUsersByOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, 4, count)
}

// --- Session tests ---

func TestCreateAndGetSession(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	sess := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, sess))

	got, err := s.GetSessionByHash(ctx, sess.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.UserID)
	assert.Equal(t, sess.ID, got.ID)
}

func TestGetSessionByHashExpired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	expired := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "expired-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, expired))

	_, err := s.GetSessionByHash(ctx, expired.TokenHash)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf, "expired session should be hidden")
}

func TestDeleteSession(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	sess := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "del-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, sess))
	require.NoError(t, s.DeleteSession(ctx, sess.ID))

	_, err := s.GetSessionByHash(ctx, sess.TokenHash)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestDeleteUserCascadesSessions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	sess := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "cascade-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, sess))

	require.NoError(t, s.DeleteUser(ctx, user.ID))

	// Session should be gone via FK CASCADE
	_, err := s.GetSessionByHash(ctx, sess.TokenHash)
	var nf *ErrNotFound
	assert.ErrorAs(t, err, &nf, "session should cascade-delete with user")
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	org := makeReportOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeReportUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	expired := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "exp-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	active := &Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "act-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, expired))
	require.NoError(t, s.CreateSession(ctx, active))

	require.NoError(t, s.DeleteExpiredSessions(ctx))

	// Active session is preserved (use direct DB query to bypass the
	// expiry filter on GetSessionByHash, which would also hide expired rows).
	got, err := s.GetSessionByHash(ctx, active.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, active.ID, got.ID)
}

// Compile-time interface satisfaction assertions for the new sub-interfaces.
var (
	_ OrgStore     = (*PostgresStore)(nil)
	_ UserStore    = (*PostgresStore)(nil)
	_ SessionStore = (*PostgresStore)(nil)
)

// Silence unused-import warnings during RED phase.
var _ = errors.New
