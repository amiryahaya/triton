//go:build integration

package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// fixture carries the ids a test needs so individual cases stay short.
type fixture struct {
	pool     *pgxpool.Pool
	store    *PostgresStore
	orgID    uuid.UUID
	userID   uuid.UUID
	engineID uuid.UUID
}

func setup(t *testing.T) fixture {
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
		_, _ = pool.Exec(ctx, `TRUNCATE discovery_candidates, discovery_jobs CASCADE`)
		_, _ = pool.Exec(ctx, `TRUNCATE engines, engine_cas CASCADE`)
		_, _ = pool.Exec(ctx, `TRUNCATE inventory_tags, inventory_hosts, inventory_groups CASCADE`)
	}
	trunc()
	require.NoError(t, ps.TruncateAll(ctx))

	orgID := uuid.Must(uuid.NewV7())
	_, err = pool.Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgID, "Org-"+orgID.String()[:8],
	)
	require.NoError(t, err)

	userID := uuid.Must(uuid.NewV7())
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, role, password, invited_at)
		 VALUES ($1, $2, $3, $4, 'org_admin', 'x', NOW())`,
		userID, orgID, "u-"+userID.String()[:8]+"@x.test", "tester",
	)
	require.NoError(t, err)

	engineID := uuid.Must(uuid.NewV7())
	_, err = pool.Exec(ctx,
		`INSERT INTO engines (id, org_id, label, cert_fingerprint, status)
		 VALUES ($1, $2, $3, $4, 'enrolled')`,
		engineID, orgID, "eng-"+engineID.String()[:6], newFingerprint(t),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		trunc()
		_ = ps.TruncateAll(ctx)
		ps.Close()
	})

	return fixture{
		pool:     pool,
		store:    NewPostgresStore(pool),
		orgID:    orgID,
		userID:   userID,
		engineID: engineID,
	}
}

func newFingerprint(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func makeJob(f fixture) Job {
	return Job{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       f.orgID,
		EngineID:    f.engineID,
		RequestedBy: &f.userID,
		CIDRs:       []string{"10.0.0.0/24"},
		Ports:       []int{22, 443, 8443},
	}
}

func TestPostgresStore_CreateAndListJobs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	// Second engine so we can verify ListJobs returns jobs across engines.
	engine2 := uuid.Must(uuid.NewV7())
	_, err := f.pool.Exec(ctx,
		`INSERT INTO engines (id, org_id, label, cert_fingerprint, status)
		 VALUES ($1, $2, 'eng-two', $3, 'enrolled')`,
		engine2, f.orgID, newFingerprint(t),
	)
	require.NoError(t, err)

	j1 := makeJob(f)
	j2 := makeJob(f)
	j2.EngineID = engine2
	j2.Ports = []int{22}

	saved1, err := f.store.CreateJob(ctx, j1)
	require.NoError(t, err)
	assert.Equal(t, StatusQueued, saved1.Status)
	assert.Equal(t, []int{22, 443, 8443}, saved1.Ports)

	_, err = f.store.CreateJob(ctx, j2)
	require.NoError(t, err)

	list, err := f.store.ListJobs(ctx, f.orgID)
	require.NoError(t, err)
	require.Len(t, list, 2, "both jobs visible to org regardless of engine")
}

func TestPostgresStore_GetJob_NotFound(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	_, err := f.store.GetJob(ctx, f.orgID, uuid.Must(uuid.NewV7()))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrJobNotFound)
}

func TestPostgresStore_ClaimNext_IsSingleUse(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	_, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	const parallel = 10
	var wg sync.WaitGroup
	var claimed int32
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := f.store.ClaimNext(ctx, f.engineID)
			require.NoError(t, err)
			if ok {
				atomic.AddInt32(&claimed, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&claimed),
		"exactly one goroutine claims the single queued job")
}

func TestPostgresStore_ClaimNext_Empty_ReturnsNotFound(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	j, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, j.ID)
}

func TestPostgresStore_InsertCandidates_Idempotent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	saved, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	cand := Candidate{
		JobID:     saved.ID,
		Address:   net.ParseIP("10.0.0.5"),
		Hostname:  "host-a",
		OpenPorts: []int{22, 443},
	}
	require.NoError(t, f.store.InsertCandidates(ctx, saved.ID, []Candidate{cand}))
	require.NoError(t, f.store.InsertCandidates(ctx, saved.ID, []Candidate{cand}))

	list, err := f.store.ListCandidates(ctx, saved.ID)
	require.NoError(t, err)
	require.Len(t, list, 1, "ON CONFLICT DO NOTHING dedupes (job_id, address)")
	assert.True(t, list[0].Address.Equal(net.ParseIP("10.0.0.5")))
	assert.Equal(t, "host-a", list[0].Hostname)
	assert.Equal(t, []int{22, 443}, list[0].OpenPorts)
}

func TestPostgresStore_FinishJob_UpdatesFields(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	saved, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	require.NoError(t, f.store.FinishJob(ctx, saved.ID, StatusCompleted, "", 42))

	got, err := f.store.GetJob(ctx, f.orgID, saved.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, got.Status)
	assert.Equal(t, 42, got.CandidateCount)
	require.NotNil(t, got.CompletedAt)
	assert.Equal(t, "", got.Error)

	// Failed with message.
	saved2, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)
	require.NoError(t, f.store.FinishJob(ctx, saved2.ID, StatusFailed, "boom", 0))
	got2, err := f.store.GetJob(ctx, f.orgID, saved2.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, got2.Status)
	assert.Equal(t, "boom", got2.Error)
}

func TestPostgresStore_MarkCandidatesPromoted_Bulk(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	saved, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	cands := []Candidate{
		{JobID: saved.ID, Address: net.ParseIP("10.0.0.1"), OpenPorts: []int{22}},
		{JobID: saved.ID, Address: net.ParseIP("10.0.0.2"), OpenPorts: []int{22}},
		{JobID: saved.ID, Address: net.ParseIP("10.0.0.3"), OpenPorts: []int{22}},
	}
	require.NoError(t, f.store.InsertCandidates(ctx, saved.ID, cands))

	listed, err := f.store.ListCandidates(ctx, saved.ID)
	require.NoError(t, err)
	require.Len(t, listed, 3)

	ids := make([]uuid.UUID, len(listed))
	for i, c := range listed {
		ids[i] = c.ID
	}
	require.NoError(t, f.store.MarkCandidatesPromoted(ctx, ids))

	reread, err := f.store.ListCandidates(ctx, saved.ID)
	require.NoError(t, err)
	for _, c := range reread {
		assert.True(t, c.Promoted, "candidate %s must be promoted", c.ID)
	}
}

func TestPostgresStore_CancelJob_QueuedSucceeds(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	saved, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	require.NoError(t, f.store.CancelJob(ctx, f.orgID, saved.ID))

	got, err := f.store.GetJob(ctx, f.orgID, saved.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, got.Status)
}

func TestPostgresStore_CancelJob_ClaimedReturnsError(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	saved, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	claimed, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, saved.ID, claimed.ID)

	err = f.store.CancelJob(ctx, f.orgID, saved.ID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrJobNotCancellable),
		"claimed jobs are owned by the engine; cancel must fail with ErrJobNotCancellable, got: %v", err)
}

func TestPostgresStore_CancelJob_Missing_ReturnsNotFound(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	err := f.store.CancelJob(ctx, f.orgID, uuid.Must(uuid.NewV7()))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrJobNotFound))
}

func TestPostgresStore_ReclaimStale(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	// Three jobs: one stays queued, two get claimed. Of the claimed, one
	// gets its claimed_at backdated by 30m so ReclaimStale should pick
	// it up; the other stays fresh and must remain claimed.
	j1, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)
	j2, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)
	j3, err := f.store.CreateJob(ctx, makeJob(f))
	require.NoError(t, err)

	// Claim two of them.
	claim1, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)
	claim2, ok, err := f.store.ClaimNext(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	// Pick whichever landed first — order is requested_at ASC but
	// uuid.NewV7 is strictly monotonic so it's deterministic enough.
	stale, fresh := claim1.ID, claim2.ID

	// Backdate one claim by 30 minutes so ReclaimStale with a 15m
	// cutoff sees exactly one eligible row.
	_, err = f.pool.Exec(ctx,
		`UPDATE discovery_jobs SET claimed_at = NOW() - INTERVAL '30 minutes' WHERE id = $1`,
		stale,
	)
	require.NoError(t, err)

	cutoff := time.Now().Add(-15 * time.Minute)
	require.NoError(t, f.store.ReclaimStale(ctx, cutoff))

	gotStale, err := f.store.GetJob(ctx, f.orgID, stale)
	require.NoError(t, err)
	assert.Equal(t, StatusQueued, gotStale.Status, "stale claim must be reset to queued")
	assert.Nil(t, gotStale.ClaimedAt, "claimed_at must be cleared on reclaim")

	gotFresh, err := f.store.GetJob(ctx, f.orgID, fresh)
	require.NoError(t, err)
	assert.Equal(t, StatusClaimed, gotFresh.Status, "fresh claim must remain claimed")

	// The never-claimed job must stay queued untouched.
	if j1.ID != stale && j1.ID != fresh {
		gotJ1, err := f.store.GetJob(ctx, f.orgID, j1.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusQueued, gotJ1.Status)
	}
	_ = j2
	_ = j3
}
