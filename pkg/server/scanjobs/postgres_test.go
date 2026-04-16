//go:build integration

package scanjobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// fixture mirrors the credentials package's seed shape: org + user +
// engine + group + 2 hosts + a credentials profile so scan jobs that
// reference any of them can be created without further setup.
type fixture struct {
	pool      *pgxpool.Pool
	store     *PostgresStore
	scanStore *store.PostgresStore
	orgID     uuid.UUID
	userID    uuid.UUID
	engineID  uuid.UUID
	groupID   uuid.UUID
	hostIDs   []uuid.UUID
	profileID uuid.UUID
}

func setupFixture(t *testing.T) *fixture {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	ps, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	pool := ps.Pool()

	trunc := func() {
		_, _ = pool.Exec(ctx, `TRUNCATE scan_jobs CASCADE`)
		_, _ = pool.Exec(ctx,
			`TRUNCATE credential_test_results, credential_tests,
			          credential_deliveries, credentials_profiles CASCADE`)
		_, _ = pool.Exec(ctx, `TRUNCATE inventory_tags, inventory_hosts, inventory_groups CASCADE`)
		_, _ = pool.Exec(ctx, `TRUNCATE engines, engine_cas CASCADE`)
	}
	trunc()
	require.NoError(t, ps.TruncateAll(ctx))
	t.Cleanup(func() {
		trunc()
		_ = ps.TruncateAll(ctx)
		ps.Close()
	})

	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	engineID := uuid.Must(uuid.NewV7())

	_, err = pool.Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgID, "Org-"+orgID.String()[:8],
	)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, role, password, must_change_password, created_at, updated_at)
		 VALUES ($1, $2, $3, 'Test User', 'org_admin', '$2a$10$x', false, NOW(), NOW())`,
		userID, orgID, userID.String()+"@test.com",
	)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO engines (id, org_id, label, cert_fingerprint, status, bundle_issued_at)
		 VALUES ($1, $2, $3, $4, 'enrolled', NOW())`,
		engineID, orgID, "test-engine", newFingerprint(t),
	)
	require.NoError(t, err)

	groupID := uuid.Must(uuid.NewV7())
	_, err = pool.Exec(ctx,
		`INSERT INTO inventory_groups (id, org_id, name, created_by) VALUES ($1, $2, $3, $4)`,
		groupID, orgID, "default", userID,
	)
	require.NoError(t, err)

	hostIDs := make([]uuid.UUID, 2)
	for i := 0; i < 2; i++ {
		hostIDs[i] = uuid.Must(uuid.NewV7())
		_, err = pool.Exec(ctx,
			`INSERT INTO inventory_hosts (id, org_id, group_id, hostname, address, os, mode)
			 VALUES ($1, $2, $3, $4, $5, 'linux', 'agentless')`,
			hostIDs[i], orgID, groupID, "h-"+hostIDs[i].String()[24:], "10.0.0."+strconv.Itoa(i+1),
		)
		require.NoError(t, err)
	}

	// Credentials profile so jobs with credential_profile_id can be
	// created. auth_type='ssh-password' → port resolves to 22.
	profileID := uuid.Must(uuid.NewV7())
	_, err = pool.Exec(ctx,
		`INSERT INTO credentials_profiles
		 (id, org_id, engine_id, name, auth_type, matcher, secret_ref, created_by)
		 VALUES ($1, $2, $3, $4, 'ssh-password', '{}'::jsonb, $5, $6)`,
		profileID, orgID, engineID, "p-"+profileID.String()[:8],
		uuid.Must(uuid.NewV7()), userID,
	)
	require.NoError(t, err)

	return &fixture{
		pool:      pool,
		store:     NewPostgresStore(pool, ps),
		scanStore: ps,
		orgID:     orgID,
		userID:    userID,
		engineID:  engineID,
		groupID:   groupID,
		hostIDs:   hostIDs,
		profileID: profileID,
	}
}

func newFingerprint(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func newJob(f *fixture, withCred bool) Job {
	j := Job{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       f.orgID,
		EngineID:    f.engineID,
		GroupID:     &f.groupID,
		HostIDs:     f.hostIDs,
		ScanProfile: ProfileStandard,
		RequestedBy: f.userID,
	}
	if withCred {
		pid := f.profileID
		j.CredentialProfileID = &pid
	}
	return j
}

func TestScanJobs_CreateAndList(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j1, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	assert.Equal(t, StatusQueued, j1.Status)
	assert.Equal(t, 2, j1.ProgressTotal)
	// Sleep a hair so requested_at orders deterministically.
	time.Sleep(2 * time.Millisecond)
	j2, err := f.store.CreateJob(ctx, newJob(f, true))
	require.NoError(t, err)

	got, err := f.store.ListJobs(ctx, f.orgID, 10)
	require.NoError(t, err)
	require.Len(t, got, 2)
	// Most recent first.
	assert.Equal(t, j2.ID, got[0].ID)
	assert.Equal(t, j1.ID, got[1].ID)
	assert.NotNil(t, got[0].CredentialProfileID)
	assert.Equal(t, f.profileID, *got[0].CredentialProfileID)
}

func TestScanJobs_ClaimNext_EnrichesWithHostAddresses(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	_, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)

	payload, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, payload.Hosts, 2)

	addrs := map[string]bool{}
	for _, h := range payload.Hosts {
		addrs[h.Address] = true
		assert.Equal(t, 22, h.Port, "no credential profile → port 22 default")
		assert.Equal(t, "linux", h.OS)
	}
	assert.True(t, addrs["10.0.0.1"], "address from inventory_hosts.address (INET)")
	assert.True(t, addrs["10.0.0.2"])
}

func TestScanJobs_ClaimNext_WithCredential_SetsSecretRefAndAuthType(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	_, err := f.store.CreateJob(ctx, newJob(f, true))
	require.NoError(t, err)

	payload, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, payload.CredentialSecretRef)
	assert.Equal(t, "ssh-password", payload.CredentialAuthType)
	for _, h := range payload.Hosts {
		assert.Equal(t, 22, h.Port)
	}
}

func TestScanJobs_ClaimNext_SingleUse(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	_, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)

	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := f.store.ClaimNext(ctx, f.engineID)
			if err == nil && ok {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&winners),
		"exactly one goroutine claims the only queued job")
}

func TestScanJobs_CancelQueued_OK(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)

	require.NoError(t, f.store.CancelJob(ctx, f.orgID, j.ID))

	got, err := f.store.GetJob(ctx, f.orgID, j.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, got.Status)
}

func TestScanJobs_CancelRunning_NotCancellable(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	_, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	err = f.store.CancelJob(ctx, f.orgID, j.ID)
	assert.ErrorIs(t, err, ErrJobNotCancellable)
}

func TestScanJobs_CancelUnknown_NotFound(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	err := f.store.CancelJob(ctx, f.orgID, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, ErrJobNotFound)
}

func TestScanJobs_FinishJob_TerminalGuard(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	// Claim the job first so FinishJob's ownership guard passes.
	_, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, f.store.FinishJob(ctx, f.engineID, j.ID, StatusCompleted, ""))
	err = f.store.FinishJob(ctx, f.engineID, j.ID, StatusCompleted, "")
	assert.ErrorIs(t, err, ErrJobAlreadyTerminal)
}

func TestScanJobs_FinishJob_WrongEngine_RejectsNotOwned(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	_, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	rogueEngine := uuid.Must(uuid.NewV7())
	err = f.store.FinishJob(ctx, rogueEngine, j.ID, StatusCompleted, "")
	assert.ErrorIs(t, err, ErrJobNotOwned, "rogue engine should not finish another engine's job")
}

func TestScanJobs_UpdateProgress_FlipsClaimedToRunning(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	_, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, f.store.UpdateProgress(ctx, j.ID, 1, 0))

	got, err := f.store.GetJob(ctx, f.orgID, j.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, got.Status)
	assert.Equal(t, 1, got.ProgressDone)

	// Subsequent updates accumulate, status stays running.
	require.NoError(t, f.store.UpdateProgress(ctx, j.ID, 0, 1))
	got, err = f.store.GetJob(ctx, f.orgID, j.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, got.Status)
	assert.Equal(t, 1, got.ProgressDone)
	assert.Equal(t, 1, got.ProgressFailed)
}

func TestScanJobs_ReclaimStale(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)
	_, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	// Back-date claimed_at to 30 minutes ago.
	_, err = f.pool.Exec(ctx,
		`UPDATE scan_jobs SET claimed_at = NOW() - INTERVAL '30 minutes' WHERE id = $1`,
		j.ID,
	)
	require.NoError(t, err)

	cutoff := time.Now().Add(-15 * time.Minute)
	require.NoError(t, f.store.ReclaimStale(ctx, cutoff))

	got, err := f.store.GetJob(ctx, f.orgID, j.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusQueued, got.Status)
	assert.Nil(t, got.ClaimedAt)
}

func TestScanJobs_RecordScanResult_WritesTaggedScan(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	j, err := f.store.CreateJob(ctx, newJob(f, false))
	require.NoError(t, err)

	scanID := uuid.Must(uuid.NewV7())
	scan := model.ScanResult{
		ID:    scanID.String(),
		OrgID: f.orgID.String(),
		Metadata: model.ScanMetadata{
			Hostname:    "h-test",
			Timestamp:   time.Now().UTC(),
			ScanProfile: "standard",
		},
		Summary: model.Summary{TotalFindings: 0},
	}
	payload, err := json.Marshal(scan)
	require.NoError(t, err)

	require.NoError(t, f.store.RecordScanResult(ctx, j.ID, f.engineID, f.hostIDs[0], payload))

	var engineID, scanJobID uuid.UUID
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT engine_id, scan_job_id FROM scans WHERE id = $1`, scanID,
	).Scan(&engineID, &scanJobID))
	assert.Equal(t, f.engineID, engineID)
	assert.Equal(t, j.ID, scanJobID)
}
