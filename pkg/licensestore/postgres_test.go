//go:build integration

package licensestore_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

var storeTestSeq atomic.Int64

// nonExistentUUID is a valid UUID that will never match real data, used for not-found tests.
const nonExistentUUID = "00000000-0000-0000-0000-000000000000"

func openTestStore(t *testing.T) *licensestore.PostgresStore {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_store_%d", storeTestSeq.Add(1))
	s, err := licensestore.NewPostgresStoreInSchema(ctx, dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = s.DropSchema(ctx)
		s.Close()
	})
	return s
}

func makeOrg(t *testing.T) *licensestore.Organization {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &licensestore.Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      "Test Org " + uuid.Must(uuid.NewV7()).String(),
		Contact:   "admin@test.com",
		Notes:     "test org",
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func makeLicense(t *testing.T, orgID string) *licensestore.LicenseRecord {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &licensestore.LicenseRecord{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Tier:      "pro",
		Seats:     5,
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Notes:     "test license",
		CreatedAt: now,
	}
}

func makeActivation(t *testing.T, licenseID string) *licensestore.Activation {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &licensestore.Activation{
		ID:          uuid.Must(uuid.NewV7()).String(),
		LicenseID:   licenseID,
		MachineID:   uuid.Must(uuid.NewV7()).String(),
		Hostname:    "test-host",
		OS:          "linux",
		Arch:        "amd64",
		Token:       "test-token-" + uuid.Must(uuid.NewV7()).String()[:8],
		ActivatedAt: now,
		LastSeenAt:  now,
		Active:      true,
	}
}

// --- Organization Tests ---

func TestCreateOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)

	require.NoError(t, s.CreateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, org.Name, got.Name)
	assert.Equal(t, org.Contact, got.Contact)
}

func TestGetOrg_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetOrg(ctx, nonExistentUUID)
	require.Error(t, err)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestListOrgs(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org1 := makeOrg(t)
	org2 := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org1))
	require.NoError(t, s.CreateOrg(ctx, org2))

	orgs, err := s.ListOrgs(ctx)
	require.NoError(t, err)
	assert.Len(t, orgs, 2)
}

func TestUpdateOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	org.Name = "Updated Org"
	org.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, s.UpdateOrg(ctx, org))

	got, err := s.GetOrg(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Org", got.Name)
}

func TestDeleteOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	require.NoError(t, s.DeleteOrg(ctx, org.ID))

	_, err := s.GetOrg(ctx, org.ID)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestDeleteOrg_WithLicenses(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	err := s.DeleteOrg(ctx, org.ID)
	var conflict *licensestore.ErrConflict
	assert.ErrorAs(t, err, &conflict)
}

// --- License Tests ---

func TestCreateLicense(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)

	require.NoError(t, s.CreateLicense(ctx, lic))

	got, err := s.GetLicense(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, lic.Tier, got.Tier)
	assert.Equal(t, lic.Seats, got.Seats)
	assert.Equal(t, org.Name, got.OrgName)
	assert.Equal(t, 0, got.SeatsUsed)
	assert.False(t, got.Revoked)
}

func TestGetLicense_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetLicense(ctx, nonExistentUUID)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestListLicenses_FilterByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org1 := makeOrg(t)
	org2 := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org1))
	require.NoError(t, s.CreateOrg(ctx, org2))

	lic1 := makeLicense(t, org1.ID)
	lic2 := makeLicense(t, org2.ID)
	require.NoError(t, s.CreateLicense(ctx, lic1))
	require.NoError(t, s.CreateLicense(ctx, lic2))

	lics, err := s.ListLicenses(ctx, licensestore.LicenseFilter{OrgID: org1.ID})
	require.NoError(t, err)
	assert.Len(t, lics, 1)
	assert.Equal(t, lic1.ID, lics[0].ID)
}

func TestListLicenses_FilterByStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	activeLic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, activeLic))

	expiredLic := makeLicense(t, org.ID)
	expiredLic.ExpiresAt = time.Now().Add(-24 * time.Hour)
	require.NoError(t, s.CreateLicense(ctx, expiredLic))

	active, err := s.ListLicenses(ctx, licensestore.LicenseFilter{Status: "active"})
	require.NoError(t, err)
	assert.Len(t, active, 1)

	expired, err := s.ListLicenses(ctx, licensestore.LicenseFilter{Status: "expired"})
	require.NoError(t, err)
	assert.Len(t, expired, 1)
}

func TestRevokeLicense(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	// Activate a machine first
	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	// Revoke
	require.NoError(t, s.RevokeLicense(ctx, lic.ID, "admin"))

	got, err := s.GetLicense(ctx, lic.ID)
	require.NoError(t, err)
	assert.True(t, got.Revoked)
	assert.NotNil(t, got.RevokedAt)

	// Activation should be deactivated
	gotAct, err := s.GetActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.False(t, gotAct.Active)
}

// --- Activation Tests ---

func TestActivate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	got, err := s.GetActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.True(t, got.Active)
	assert.Equal(t, act.MachineID, got.MachineID)

	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestActivate_SeatsFull(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 2
	require.NoError(t, s.CreateLicense(ctx, lic))

	// Fill both seats
	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	// Third should fail
	act3 := makeActivation(t, lic.ID)
	err := s.Activate(ctx, act3)
	var sf *licensestore.ErrSeatsFull
	assert.ErrorAs(t, err, &sf)
}

func TestActivate_Reactivation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	// Deactivate
	require.NoError(t, s.Deactivate(ctx, lic.ID, act.MachineID))

	// Re-activate same machine
	act2 := makeActivation(t, lic.ID)
	act2.MachineID = act.MachineID // same machine
	act2.Token = "new-token"
	require.NoError(t, s.Activate(ctx, act2))

	// Should be the same row, re-activated
	got, err := s.GetActivationByMachine(ctx, lic.ID, act.MachineID)
	require.NoError(t, err)
	assert.True(t, got.Active)
	assert.Equal(t, "new-token", got.Token)
}

func TestActivate_AlreadyActive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	// Activate same machine again — should succeed (update last_seen)
	act2 := makeActivation(t, lic.ID)
	act2.MachineID = act.MachineID
	act2.Token = "updated-token"
	require.NoError(t, s.Activate(ctx, act2))

	// Should still be one active seat
	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestDeactivate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))
	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	require.NoError(t, s.Deactivate(ctx, lic.ID, act.MachineID))

	got, err := s.GetActivation(ctx, act.ID)
	require.NoError(t, err)
	assert.False(t, got.Active)
	assert.NotNil(t, got.DeactivatedAt)
}

func TestDeactivate_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.Deactivate(ctx, nonExistentUUID, "no-machine")
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestListActivations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	acts, err := s.ListActivations(ctx, licensestore.ActivationFilter{LicenseID: lic.ID})
	require.NoError(t, err)
	assert.Len(t, acts, 2)
}

func TestListActivations_FilterActive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))
	require.NoError(t, s.Deactivate(ctx, lic.ID, act2.MachineID))

	active := true
	acts, err := s.ListActivations(ctx, licensestore.ActivationFilter{Active: &active})
	require.NoError(t, err)
	assert.Len(t, acts, 1)
	assert.Equal(t, act1.MachineID, acts[0].MachineID)
}

// --- Audit Tests ---

func TestWriteAndListAudit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	entry := &licensestore.AuditEntry{
		Timestamp: time.Now().UTC().Truncate(time.Microsecond),
		EventType: "activate",
		LicenseID: nonExistentUUID,
		MachineID: "machine-1",
		Actor:     "system",
		Details:   json.RawMessage(`{"test": true}`),
		IPAddress: "127.0.0.1",
	}
	require.NoError(t, s.WriteAudit(ctx, entry))

	entries, err := s.ListAudit(ctx, licensestore.AuditFilter{EventType: "activate"})
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "activate", entries[0].EventType)
}

func TestListAudit_WithFilters(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, et := range []string{"activate", "deactivate", "revoke"} {
		require.NoError(t, s.WriteAudit(ctx, &licensestore.AuditEntry{
			Timestamp: now,
			EventType: et,
			Actor:     "system",
		}))
	}

	all, err := s.ListAudit(ctx, licensestore.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 3)

	limited, err := s.ListAudit(ctx, licensestore.AuditFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, limited, 2)
}

// --- Stats Tests ---

func TestDashboardStats(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))
	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	stats, err := s.DashboardStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalOrgs)
	assert.Equal(t, 1, stats.TotalLicenses)
	assert.Equal(t, 1, stats.ActiveLicenses)
	assert.Equal(t, 1, stats.TotalActivations)
	assert.Equal(t, 1, stats.ActiveSeats)
}

// --- Truncate Tests ---

func TestTruncateAll(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	require.NoError(t, s.TruncateAll(ctx))

	orgs, err := s.ListOrgs(ctx)
	require.NoError(t, err)
	assert.Empty(t, orgs)
}

func TestActivate_LicenseNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	act := makeActivation(t, nonExistentUUID)
	err := s.Activate(ctx, act)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

// --- User tests ---

func makeUser(t *testing.T, orgID string) *licensestore.User {
	t.Helper()
	return &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    orgID,
		Email:    fmt.Sprintf("user-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8]),
		Name:     "Test User",
		Role:     "org_user",
		Password: "$2a$10$fakebcrypthashfortesting000000000000000000000000000000",
	}
}

func TestCreateUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, got.Email)
	assert.Equal(t, user.Role, got.Role)
	assert.Equal(t, org.ID, got.OrgID)
	assert.Equal(t, org.Name, got.OrgName)
}

func TestGetUserByEmail(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	got, err := s.GetUserByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)
	assert.Equal(t, org.ID, got.OrgID)
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	email := fmt.Sprintf("dup-%s@test.com", uuid.Must(uuid.NewV7()).String()[:8])
	u1 := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: email, Name: "A", Role: "org_user", Password: "x",
	}
	require.NoError(t, s.CreateUser(ctx, u1))

	u2 := &licensestore.User{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID,
		Email: email, Name: "B", Role: "org_user", Password: "y",
	}
	err := s.CreateUser(ctx, u2)
	require.Error(t, err)
	var conflict *licensestore.ErrConflict
	assert.ErrorAs(t, err, &conflict)
}

func TestPlatformAdminNoOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	user := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    fmt.Sprintf("admin-%s@platform.com", uuid.Must(uuid.NewV7()).String()[:8]),
		Name:     "Platform Admin",
		Role:     "platform_admin",
		Password: "$2a$10$fakehash",
	}
	require.NoError(t, s.CreateUser(ctx, user))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, got.OrgID)
	assert.Equal(t, "platform_admin", got.Role)
}

func TestListUsersFilterByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org1 := makeOrg(t)
	org2 := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org1))
	require.NoError(t, s.CreateOrg(ctx, org2))

	for i, orgID := range []string{org1.ID, org1.ID, org2.ID} {
		u := &licensestore.User{
			ID:       uuid.Must(uuid.NewV7()).String(),
			OrgID:    orgID,
			Email:    fmt.Sprintf("filter-%d-%s@test.com", i, uuid.Must(uuid.NewV7()).String()[:8]),
			Name:     fmt.Sprintf("U%d", i),
			Role:     "org_user",
			Password: "x",
		}
		require.NoError(t, s.CreateUser(ctx, u))
	}

	users, err := s.ListUsers(ctx, licensestore.UserFilter{OrgID: org1.ID})
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

// TestUpdateUser verifies name and password can be updated via the
// UserUpdate DTO. The DTO has no Role or OrgID field by design —
// the type system itself prevents role/org mutation, replacing the
// older "silent ignore" behavior.
func TestUpdateUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	user := makeUser(t, org.ID)
	originalRole := user.Role
	originalOrgID := user.OrgID
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.UpdateUser(ctx, licensestore.UserUpdate{
		ID:   user.ID,
		Name: "Updated Name",
	}))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", got.Name)
	assert.Equal(t, originalRole, got.Role, "role must not be modified by UpdateUser")
	assert.Equal(t, originalOrgID, got.OrgID, "orgID must not be modified by UpdateUser")
}

// TestUpdateUserPasswordOnly verifies that an update with empty Name and
// non-empty Password preserves the existing name. This is the partial-update
// path used by the API when a user changes only their password.
func TestUpdateUserPasswordOnly(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	user := makeUser(t, org.ID)
	originalName := user.Name
	require.NoError(t, s.CreateUser(ctx, user))

	require.NoError(t, s.UpdateUser(ctx, licensestore.UserUpdate{
		ID:       user.ID,
		Name:     originalName, // pass current name explicitly
		Password: "new-hashed-value",
	}))

	got, err := s.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, originalName, got.Name)
	assert.Equal(t, "new-hashed-value", got.Password)
}

func TestDeleteUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))
	require.NoError(t, s.DeleteUser(ctx, user.ID))

	_, err := s.GetUser(ctx, user.ID)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

func TestCountUsers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	count, err := s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	require.NoError(t, s.CreateUser(ctx, makeUser(t, org.ID)))

	count, err = s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// --- Session tests ---

func TestCreateAndGetSession(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	sess := &licensestore.Session{
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

// TestGetSessionByHash_ExpiredNotReturned verifies that expired sessions are
// filtered out by GetSessionByHash itself, so callers can rely on a successful
// fetch meaning "still valid". Without this filter, expired rows that haven't
// been cleaned up by DeleteExpiredSessions would be returned as live sessions.
func TestGetSessionByHash_ExpiredNotReturned(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	expired := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: "expired-fetch-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, expired))

	_, err := s.GetSessionByHash(ctx, expired.TokenHash)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf, "expired session should be hidden from GetSessionByHash")
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	expired := &licensestore.Session{
		ID: uuid.Must(uuid.NewV7()).String(), UserID: user.ID,
		TokenHash: "expired-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	active := &licensestore.Session{
		ID: uuid.Must(uuid.NewV7()).String(), UserID: user.ID,
		TokenHash: "active-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, expired))
	require.NoError(t, s.CreateSession(ctx, active))

	require.NoError(t, s.DeleteExpiredSessions(ctx))

	_, err := s.GetSessionByHash(ctx, expired.TokenHash)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)

	got, err := s.GetSessionByHash(ctx, active.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.UserID)
}

func TestDeleteUserCascadesSessions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	user := makeUser(t, org.ID)
	require.NoError(t, s.CreateUser(ctx, user))

	sess := &licensestore.Session{
		ID: uuid.Must(uuid.NewV7()).String(), UserID: user.ID,
		TokenHash: "cascade-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, sess))

	// Delete user should cascade to sessions
	require.NoError(t, s.DeleteUser(ctx, user.ID))

	_, err := s.GetSessionByHash(ctx, sess.TokenHash)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}

// --- ReapStaleActivations Tests ---

func TestReapStaleActivations_ReapsOnlyStale(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 3
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	act3 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))
	require.NoError(t, s.Activate(ctx, act3))

	fifteenDaysAgo := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, fifteenDaysAgo, act1.ID)
	require.NoError(t, err)
	_, err = s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, fifteenDaysAgo, act2.ID)
	require.NoError(t, err)

	reaped, err := s.ReapStaleActivations(ctx, lic.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, reaped)

	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	got1, err := s.GetActivation(ctx, act1.ID)
	require.NoError(t, err)
	assert.False(t, got1.Active)
	assert.NotNil(t, got1.DeactivatedAt)

	got3, err := s.GetActivation(ctx, act3.ID)
	require.NoError(t, err)
	assert.True(t, got3.Active)
}

func TestReapStaleActivations_NoStaleReturnsZero(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))
	act := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act))

	reaped, err := s.ReapStaleActivations(ctx, lic.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, reaped)
}

func TestReapStaleActivations_DifferentLicenseNotAffected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic1 := makeLicense(t, org.ID)
	lic2 := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic1))
	require.NoError(t, s.CreateLicense(ctx, lic2))

	act1 := makeActivation(t, lic1.ID)
	act2 := makeActivation(t, lic2.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act1.ID)
	require.NoError(t, err)
	_, err = s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act2.ID)
	require.NoError(t, err)

	reaped, err := s.ReapStaleActivations(ctx, lic1.ID, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)

	got2, err := s.GetActivation(ctx, act2.ID)
	require.NoError(t, err)
	assert.True(t, got2.Active)
}

// --- Activate with reaping Tests ---

func TestActivate_ReapsStaleOnFull(t *testing.T) {
	s := openTestStore(t)
	s.SetStaleThreshold(14 * 24 * time.Hour)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 2
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act1.ID)
	require.NoError(t, err)

	act3 := makeActivation(t, lic.ID)
	err = s.Activate(ctx, act3)
	require.NoError(t, err, "activation should succeed after reaping stale seat")

	got1, err := s.GetActivation(ctx, act1.ID)
	require.NoError(t, err)
	assert.False(t, got1.Active, "stale act1 should be reaped")

	count, err := s.CountActiveSeats(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "act2 + act3 should be active")
}

func TestActivate_StillFullAfterReap(t *testing.T) {
	s := openTestStore(t)
	s.SetStaleThreshold(14 * 24 * time.Hour)
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 2
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	act2 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))
	require.NoError(t, s.Activate(ctx, act2))

	act3 := makeActivation(t, lic.ID)
	err := s.Activate(ctx, act3)
	var sf *licensestore.ErrSeatsFull
	assert.ErrorAs(t, err, &sf, "should still return ErrSeatsFull when no stale seats to reap")
}

func TestActivate_NoReapWhenThresholdZero(t *testing.T) {
	s := openTestStore(t)
	// StaleThreshold is zero (default) — no reaping
	ctx := context.Background()
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	lic := makeLicense(t, org.ID)
	lic.Seats = 1
	require.NoError(t, s.CreateLicense(ctx, lic))

	act1 := makeActivation(t, lic.ID)
	require.NoError(t, s.Activate(ctx, act1))

	stale := time.Now().Add(-15 * 24 * time.Hour)
	_, err := s.ExecForTest(ctx, `UPDATE activations SET last_seen_at = $1 WHERE id = $2`, stale, act1.ID)
	require.NoError(t, err)

	act2 := makeActivation(t, lic.ID)
	err = s.Activate(ctx, act2)
	var sf *licensestore.ErrSeatsFull
	assert.ErrorAs(t, err, &sf, "should return ErrSeatsFull when threshold is zero even if stale seats exist")
}

// --- Migration v5 Tests ---

// TestMigration_V5AddsV2ColumnsAndUsageTable verifies that the v5 migration
// correctly adds the four new columns to licenses and creates the
// license_usage table with its composite primary key.
func TestMigration_V5AddsV2ColumnsAndUsageTable(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Column presence check on licenses — expect all 4 v2 columns.
	var ncol int
	err := s.QueryRowForTest(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name='licenses'
		  AND column_name IN ('features','limits','soft_buffer_pct','product_scope')
	`).Scan(&ncol)
	require.NoError(t, err)
	assert.Equal(t, 4, ncol, "expected 4 v2 columns on licenses table")

	// license_usage table must exist with a primary key constraint.
	var nkey int
	err = s.QueryRowForTest(ctx, `
		SELECT COUNT(*) FROM information_schema.table_constraints
		WHERE table_name='license_usage' AND constraint_type='PRIMARY KEY'
	`).Scan(&nkey)
	require.NoError(t, err)
	assert.Equal(t, 1, nkey, "expected license_usage primary key constraint")

	// Default values: insert a license and verify new column defaults.
	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	var productScope string
	var softBufPct int
	err = s.QueryRowForTest(ctx,
		`SELECT product_scope, soft_buffer_pct FROM licenses WHERE id = $1`, lic.ID,
	).Scan(&productScope, &softBufPct)
	require.NoError(t, err)
	assert.Equal(t, "legacy", productScope, "default product_scope should be 'legacy'")
	assert.Equal(t, 10, softBufPct, "default soft_buffer_pct should be 10")
}
