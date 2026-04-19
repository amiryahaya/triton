//go:build integration

package managestore_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

// tableExists checks whether a table exists in the current schema.
func tableExists(t *testing.T, s *managestore.PostgresStore, name string) bool {
	t.Helper()
	var exists bool
	err := s.QueryRowForTest(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = $1
		)`, name).Scan(&exists)
	require.NoError(t, err)
	return exists
}

// columnExists checks whether a column exists on a table in the current schema.
func columnExists(t *testing.T, s *managestore.PostgresStore, table, column string) bool {
	t.Helper()
	var exists bool
	err := s.QueryRowForTest(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
		)`, table, column).Scan(&exists)
	require.NoError(t, err)
	return exists
}

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

// TestMigrate_V2_CreatesZonesAndHosts asserts migration v2 creates the
// zones, hosts, and zone_memberships tables used by the scanner orchestrator.
func TestMigrate_V2_CreatesZonesAndHosts(t *testing.T) {
	s := openTestStore(t)

	assert.True(t, tableExists(t, s, "manage_zones"), "manage_zones must exist")
	assert.True(t, tableExists(t, s, "manage_hosts"), "manage_hosts must exist")
	assert.True(t, tableExists(t, s, "manage_zone_memberships"), "manage_zone_memberships must exist")
}

// TestMigrate_V3_CreatesScanJobs asserts migration v3 creates manage_scan_jobs
// with the worker-pool control columns (cancel_requested, running_heartbeat_at,
// worker_id, progress_text, error_message).
func TestMigrate_V3_CreatesScanJobs(t *testing.T) {
	s := openTestStore(t)

	require.True(t, tableExists(t, s, "manage_scan_jobs"), "manage_scan_jobs must exist")

	required := []string{
		"cancel_requested",
		"running_heartbeat_at",
		"worker_id",
		"progress_text",
		"error_message",
	}
	for _, col := range required {
		assert.True(t, columnExists(t, s, "manage_scan_jobs", col),
			"manage_scan_jobs must have column %q", col)
	}
}

// TestMigrate_V4_CreatesResultQueueTables asserts migration v4 creates the
// result queue, dead-letter table, push credentials, and license state
// singleton. The license_state singleton row must be pre-seeded.
func TestMigrate_V4_CreatesResultQueueTables(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	assert.True(t, tableExists(t, s, "manage_scan_results_queue"),
		"manage_scan_results_queue must exist")
	assert.True(t, tableExists(t, s, "manage_scan_results_dead_letter"),
		"manage_scan_results_dead_letter must exist")
	assert.True(t, tableExists(t, s, "manage_push_creds"),
		"manage_push_creds must exist")
	assert.True(t, tableExists(t, s, "manage_license_state"),
		"manage_license_state must exist")

	var count int
	err := s.QueryRowForTest(ctx, "SELECT COUNT(*) FROM manage_license_state").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count,
		"migration must seed exactly one manage_license_state singleton row")
}

// TestMigrate_V5_CreatesCATables asserts migration v5 creates the Manage
// CA singleton plus the agents + cert-revocations tables used for agent
// mTLS enrolment.
func TestMigrate_V5_CreatesCATables(t *testing.T) {
	s := openTestStore(t)

	assert.True(t, tableExists(t, s, "manage_ca"),
		"manage_ca must exist")
	assert.True(t, tableExists(t, s, "manage_agents"),
		"manage_agents must exist")
	assert.True(t, tableExists(t, s, "manage_agent_cert_revocations"),
		"manage_agent_cert_revocations must exist")
}

// TestMigrate_V6_LoosenScanJobFKs asserts migration v6 drops NOT NULL on
// manage_scan_jobs.zone_id + host_id and switches their FK delete policy
// to SET NULL, so deleting a zone/host preserves historical scan jobs.
func TestMigrate_V6_LoosenScanJobFKs(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// zone_id and host_id must be nullable now.
	var isNullable string
	err := s.QueryRowForTest(ctx, `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'manage_scan_jobs'
		  AND column_name = 'zone_id'`).Scan(&isNullable)
	require.NoError(t, err)
	assert.Equal(t, "YES", isNullable, "zone_id must be nullable after v6")

	err = s.QueryRowForTest(ctx, `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'manage_scan_jobs'
		  AND column_name = 'host_id'`).Scan(&isNullable)
	require.NoError(t, err)
	assert.Equal(t, "YES", isNullable, "host_id must be nullable after v6")

	// Both FKs must have delete_rule = SET NULL. pg_constraint.confdeltype
	// is the authoritative lookup — 'n' = SET NULL, 'r' = RESTRICT,
	// 'c' = CASCADE, 'a' = NO ACTION (default).
	var setNullFKs int
	err = s.QueryRowForTest(ctx, `
		SELECT COUNT(*) FROM pg_constraint c
		JOIN pg_class t ON c.conrelid = t.oid
		JOIN pg_namespace n ON t.relnamespace = n.oid
		WHERE n.nspname = current_schema()
		  AND t.relname = 'manage_scan_jobs'
		  AND c.contype = 'f'
		  AND c.confdeltype = 'n'`).Scan(&setNullFKs)
	require.NoError(t, err)
	assert.Equal(t, 2, setNullFKs,
		"manage_scan_jobs must have exactly 2 FKs with ON DELETE SET NULL (zone_id + host_id)")

	// End-to-end: inserting a zone+host+job, then deleting the zone should
	// leave the job row with zone_id = NULL rather than erroring out.
	zoneID := uuid.Must(uuid.NewV7()).String()
	_, err = s.ExecForTest(ctx,
		`INSERT INTO manage_zones (id, name) VALUES ($1, $2)`, zoneID, "zone-"+zoneID)
	require.NoError(t, err)
	hostID := uuid.Must(uuid.NewV7()).String()
	_, err = s.ExecForTest(ctx,
		`INSERT INTO manage_hosts (id, hostname, zone_id) VALUES ($1, $2, $3)`,
		hostID, "host-"+hostID, zoneID)
	require.NoError(t, err)
	jobID := uuid.Must(uuid.NewV7()).String()
	tenantID := uuid.Must(uuid.NewV7()).String()
	_, err = s.ExecForTest(ctx,
		`INSERT INTO manage_scan_jobs (id, tenant_id, zone_id, host_id, profile)
		 VALUES ($1, $2, $3, $4, 'quick')`,
		jobID, tenantID, zoneID, hostID)
	require.NoError(t, err)

	_, err = s.ExecForTest(ctx, `DELETE FROM manage_zones WHERE id = $1`, zoneID)
	require.NoError(t, err, "deleting a zone must not error — FK should SET NULL")

	var gotZoneID, gotHostID *string
	err = s.QueryRowForTest(ctx,
		`SELECT zone_id, host_id FROM manage_scan_jobs WHERE id = $1`, jobID).
		Scan(&gotZoneID, &gotHostID)
	require.NoError(t, err, "scan job row must survive zone deletion")
	assert.Nil(t, gotZoneID, "zone_id must be NULL after zone deletion")
	assert.NotNil(t, gotHostID, "host_id must still be set")
}

// TestMigrate_ConcurrentCallsAreSafe asserts the advisory lock in Migrate
// serialises concurrent migrators so no caller sees a duplicate-key error
// on version-row inserts. Rolling deploys and parallel test runs can both
// invoke Migrate against the same pool after first boot.
//
// We pre-run Migrate once to establish manage_schema_version; the race
// that matters in production is concurrent migrators trying to insert
// duplicate version rows, not concurrent CREATE TABLE IF NOT EXISTS DDL
// (which has a well-known Postgres pg_type catalog quirk that is outside
// the scope of an advisory lock).
func TestMigrate_ConcurrentCallsAreSafe(t *testing.T) {
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_manage_lock_%d", storeTestSeq.Add(1))

	// Create the schema on a short-lived pool.
	setupPool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	ctx := context.Background()
	_, err = setupPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	require.NoError(t, err)
	_, err = setupPool.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	setupPool.Close()

	// Dedicated pool scoped to the isolated schema, shared by all goroutines.
	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
		// Teardown on a fresh short-lived pool since the scoped pool is closed.
		cleanupPool, cerr := pgxpool.New(context.Background(), dbURL)
		if cerr != nil {
			return
		}
		defer cleanupPool.Close()
		_, _ = cleanupPool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})

	// Initial migrate so manage_schema_version exists before the racing
	// goroutines start. This models the "rolling deploy" scenario where
	// the table already exists from an earlier boot.
	require.NoError(t, managestore.Migrate(ctx, pool))

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- managestore.Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "concurrent Migrate must not race on manage_schema_version")
	}

	// Exactly one row per migration — no duplicates inserted by racing callers.
	var countRows, distinctVersions int
	err = pool.QueryRow(ctx, "SELECT COUNT(*), COUNT(DISTINCT version) FROM manage_schema_version").
		Scan(&countRows, &distinctVersions)
	require.NoError(t, err)
	assert.Equal(t, countRows, distinctVersions, "no duplicate versions in manage_schema_version")
	assert.Greater(t, countRows, 0, "at least one migration must have been applied")
}
