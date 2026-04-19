//go:build integration

package managestore_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/managestore"
)

var storeTestSeq atomic.Int64

const nonExistentUUID = "00000000-0000-0000-0000-000000000000"

func openTestStore(t *testing.T) *managestore.PostgresStore {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_manage_%d", storeTestSeq.Add(1))
	s, err := managestore.NewPostgresStoreInSchema(context.Background(), dbURL, schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = s.DropSchema(context.Background())
		s.Close()
	})
	return s
}

func makeUser(t *testing.T) *managestore.ManageUser {
	t.Helper()
	// Use the full UUID string to guarantee uniqueness across rapid calls.
	suffix := uuid.Must(uuid.NewV7()).String()
	return &managestore.ManageUser{
		Email:        "test+" + suffix + "@example.com",
		Name:         "Test User",
		Role:         "admin",
		PasswordHash: "$2a$12$fakehashfor_testing_only_not_real",
	}
}

func makeSession(t *testing.T, userID string) *managestore.ManageSession {
	t.Helper()
	return &managestore.ManageSession{
		UserID:    userID,
		TokenHash: "hash-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// --- User Tests ---

func TestCreateUser_HappyPath(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u := makeUser(t)

	require.NoError(t, s.CreateUser(ctx, u))

	assert.NotEmpty(t, u.ID, "CreateUser should populate ID")
	assert.False(t, u.CreatedAt.IsZero(), "CreateUser should populate CreatedAt")
	assert.False(t, u.UpdatedAt.IsZero(), "CreateUser should populate UpdatedAt")

	byEmail, err := s.GetUserByEmail(ctx, u.Email)
	require.NoError(t, err)
	assert.Equal(t, u.ID, byEmail.ID)
	assert.Equal(t, u.Email, byEmail.Email)
	assert.Equal(t, u.Name, byEmail.Name)
	assert.Equal(t, u.Role, byEmail.Role)
	assert.Equal(t, u.PasswordHash, byEmail.PasswordHash)
	assert.False(t, byEmail.MustChangePW)

	byID, err := s.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, byID.ID)
	assert.Equal(t, u.Email, byID.Email)
}

func TestCreateUser_DuplicateEmail_Conflicts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u := makeUser(t)

	require.NoError(t, s.CreateUser(ctx, u))

	u2 := &managestore.ManageUser{
		Email:        u.Email, // same email
		Name:         "Another User",
		Role:         "network_engineer",
		PasswordHash: "$2a$12$another",
	}
	err := s.CreateUser(ctx, u2)
	require.Error(t, err)
	var conflict *managestore.ErrConflict
	assert.ErrorAs(t, err, &conflict, "duplicate email should return ErrConflict")
}

func TestCreateUser_InvalidRole_Errors(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u := makeUser(t)
	u.Role = "hacker"

	err := s.CreateUser(ctx, u)
	require.Error(t, err)
	assert.NotErrorIs(t, err, nil)
}

func TestListUsers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const n = 3
	for i := 0; i < n; i++ {
		require.NoError(t, s.CreateUser(ctx, makeUser(t)))
	}

	users, err := s.ListUsers(ctx)
	require.NoError(t, err)
	assert.Len(t, users, n, "ListUsers should return all created users")
}

func TestUpdateUserPassword(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u := makeUser(t)
	u.MustChangePW = true
	require.NoError(t, s.CreateUser(ctx, u))

	newHash := "$2a$12$newhashreplacement"
	require.NoError(t, s.UpdateUserPassword(ctx, u.ID, newHash))

	got, err := s.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, newHash, got.PasswordHash)
	assert.False(t, got.MustChangePW, "UpdateUserPassword should clear must_change_pw")
}

func TestUpdateUserPassword_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.UpdateUserPassword(ctx, nonExistentUUID, "$2a$12$hash")
	require.Error(t, err)
	var notFound *managestore.ErrNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestCountUsers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	count, err := s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "empty store should have 0 users")

	require.NoError(t, s.CreateUser(ctx, makeUser(t)))
	require.NoError(t, s.CreateUser(ctx, makeUser(t)))

	count, err = s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

// --- Session Tests ---

func TestCreateSession_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u := makeUser(t)
	require.NoError(t, s.CreateUser(ctx, u))

	sess := makeSession(t, u.ID)
	require.NoError(t, s.CreateSession(ctx, sess))

	assert.NotEmpty(t, sess.ID, "CreateSession should populate ID")
	assert.False(t, sess.CreatedAt.IsZero(), "CreateSession should populate CreatedAt")

	got, err := s.GetSessionByTokenHash(ctx, sess.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, u.ID, got.UserID)
	assert.Equal(t, sess.TokenHash, got.TokenHash)
	assert.WithinDuration(t, sess.ExpiresAt, got.ExpiresAt, time.Second)
}

func TestGetSessionByTokenHash_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetSessionByTokenHash(ctx, "nonexistent-hash")
	require.Error(t, err)
	var notFound *managestore.ErrNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestDeleteSession(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u := makeUser(t)
	require.NoError(t, s.CreateUser(ctx, u))

	sess := makeSession(t, u.ID)
	require.NoError(t, s.CreateSession(ctx, sess))

	require.NoError(t, s.DeleteSession(ctx, sess.ID))

	_, err := s.GetSessionByTokenHash(ctx, sess.TokenHash)
	require.Error(t, err, "session should be gone after delete")
	var notFound *managestore.ErrNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u := makeUser(t)
	require.NoError(t, s.CreateUser(ctx, u))

	// Expired session
	expired := &managestore.ManageSession{
		UserID:    u.ID,
		TokenHash: "expired-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, expired))

	// Future session
	future := makeSession(t, u.ID)
	require.NoError(t, s.CreateSession(ctx, future))

	pruned, err := s.DeleteExpiredSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned, "only the expired session should be pruned")

	_, err = s.GetSessionByTokenHash(ctx, future.TokenHash)
	require.NoError(t, err, "future session must survive pruning")
}

// --- Setup Tests ---

func TestGetSetup_DefaultRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	state, err := s.GetSetup(ctx)
	require.NoError(t, err)
	assert.False(t, state.AdminCreated)
	assert.False(t, state.LicenseActivated)
	assert.Empty(t, state.LicenseServerURL)
	assert.Empty(t, state.LicenseKey)
	assert.Empty(t, state.SignedToken)
	assert.Empty(t, state.InstanceID)
}

func TestMarkAdminCreated(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.MarkAdminCreated(ctx))

	state, err := s.GetSetup(ctx)
	require.NoError(t, err)
	assert.True(t, state.AdminCreated)

	// Idempotent
	require.NoError(t, s.MarkAdminCreated(ctx))
	state, err = s.GetSetup(ctx)
	require.NoError(t, err)
	assert.True(t, state.AdminCreated)
}

func TestSaveLicenseActivation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	serverURL := "https://license.example.com"
	key := "key-abc-123"
	signedToken := "signed.token.value"
	instanceID := uuid.Must(uuid.NewV7()).String()

	require.NoError(t, s.SaveLicenseActivation(ctx, serverURL, key, signedToken, instanceID))

	state, err := s.GetSetup(ctx)
	require.NoError(t, err)
	assert.True(t, state.LicenseActivated)
	assert.Equal(t, serverURL, state.LicenseServerURL)
	assert.Equal(t, key, state.LicenseKey)
	assert.Equal(t, signedToken, state.SignedToken)
	assert.Equal(t, instanceID, state.InstanceID)
}

func TestSaveLicenseActivation_BeforeAdmin(t *testing.T) {
	// Store layer has no ordering enforcement — that's the handler's job.
	// Simply assert the write succeeds regardless of admin_created flag.
	s := openTestStore(t)
	ctx := context.Background()

	state, err := s.GetSetup(ctx)
	require.NoError(t, err)
	require.False(t, state.AdminCreated, "precondition: admin not yet created")

	err = s.SaveLicenseActivation(ctx, "https://ls.example.com", "k", "tok", uuid.Must(uuid.NewV7()).String())
	require.NoError(t, err, "SaveLicenseActivation should succeed even before MarkAdminCreated")
}

func TestMigration_CreatesSingletonRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	var count int
	err := s.QueryRowForTest(ctx, "SELECT COUNT(*) FROM manage_setup").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "migration must insert exactly one singleton row")
}

// --- Schema versioning isolation ---

// TestMigrate_UsesManageSchemaVersionTable asserts the manage schema uses
// manage_schema_version (NOT schema_version) so it can cohabit a database
// with the Report Server's store, which owns schema_version.
func TestMigrate_UsesManageSchemaVersionTable(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// manage_schema_version table must exist after migrate.
	var exists bool
	err := s.QueryRowForTest(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = 'manage_schema_version'
		)`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "manage_schema_version table must exist after migrate")

	// schema_version table must NOT exist in the manage schema — that
	// name is owned by the Report Server's store.
	err = s.QueryRowForTest(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = 'schema_version'
		)`).Scan(&exists)
	require.NoError(t, err)
	assert.False(t, exists, "schema_version must NOT exist in the manage schema")

	// At least one migration row recorded.
	var count int
	err = s.QueryRowForTest(ctx, `SELECT COUNT(*) FROM manage_schema_version`).Scan(&count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "at least one applied migration must be recorded")
}
