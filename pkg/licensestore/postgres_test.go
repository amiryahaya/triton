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
		ID:        uuid.New().String(),
		Name:      "Test Org " + uuid.New().String()[:8],
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
		ID:        uuid.New().String(),
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
		ID:          uuid.New().String(),
		LicenseID:   licenseID,
		MachineID:   uuid.New().String(),
		Hostname:    "test-host",
		OS:          "linux",
		Arch:        "amd64",
		Token:       "test-token-" + uuid.New().String()[:8],
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

	_, err := s.GetOrg(ctx, "nonexistent")
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

	_, err := s.GetLicense(ctx, "nonexistent")
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

	err := s.Deactivate(ctx, "no-license", "no-machine")
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
		LicenseID: "lic-1",
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

	act := makeActivation(t, "nonexistent")
	err := s.Activate(ctx, act)
	var nf *licensestore.ErrNotFound
	assert.ErrorAs(t, err, &nf)
}
