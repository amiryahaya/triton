//go:build integration

package credentials

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

// fixture carries the DB pool + seeded parent rows required by the
// credentials FK chain (organizations, users, engines, inventory_hosts).
type fixture struct {
	pool     *pgxpool.Pool
	store    *PostgresStore
	orgID    uuid.UUID
	userID   uuid.UUID
	engineID uuid.UUID
	hostIDs  []uuid.UUID
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

	// Seed a group + 2 hosts so test-job FKs + matcher resolution work.
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
			// Use the last 12 hex chars (random segment) of the UUID for
			// the hostname — UUIDv7s generated back-to-back share their
			// millisecond-precision prefix and would collide on the
			// (org_id, hostname) unique index.
			hostIDs[i], orgID, groupID, "h-"+hostIDs[i].String()[24:], "10.0.0."+itoa(i+1),
		)
		require.NoError(t, err)
	}

	return &fixture{
		pool:     pool,
		store:    NewPostgresStore(pool),
		orgID:    orgID,
		userID:   userID,
		engineID: engineID,
		hostIDs:  hostIDs,
	}
}

// itoa is a tiny inline int->string to avoid pulling in strconv for
// just the fixture seed.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func newFingerprint(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func newProfile(f *fixture) Profile {
	return Profile{
		ID:        uuid.Must(uuid.NewV7()),
		OrgID:     f.orgID,
		EngineID:  f.engineID,
		Name:      "profile-" + uuid.Must(uuid.NewV7()).String()[:8],
		AuthType:  AuthSSHPassword,
		Matcher:   Matcher{OS: "linux"},
		SecretRef: uuid.Must(uuid.NewV7()),
		CreatedBy: f.userID,
	}
}

func TestCredentials_CreateProfileWithDelivery(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	ct := []byte("pretend-this-is-sealed-ciphertext")
	created, err := f.store.CreateProfileWithDelivery(ctx, p, ct)
	require.NoError(t, err)
	assert.NotZero(t, created.CreatedAt)

	// Profile row persisted.
	got, err := f.store.GetProfile(ctx, f.orgID, p.ID)
	require.NoError(t, err)
	assert.Equal(t, p.Name, got.Name)
	assert.Equal(t, "linux", got.Matcher.OS)

	// Delivery row also persisted with ciphertext.
	var kind string
	var ciphertext []byte
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT kind, ciphertext FROM credential_deliveries WHERE profile_id = $1`,
		p.ID,
	).Scan(&kind, &ciphertext))
	assert.Equal(t, "push", kind)
	assert.Equal(t, ct, ciphertext)
}

func TestCredentials_DeleteSurvivesProfileRemoval(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x-sealed"))
	require.NoError(t, err)

	require.NoError(t, f.store.DeleteProfileWithDelivery(ctx, f.orgID, p.ID))

	// Profile row gone.
	_, err = f.store.GetProfile(ctx, f.orgID, p.ID)
	assert.ErrorIs(t, err, ErrProfileNotFound)

	// Delete-kind delivery still exists, ciphertext NULL.
	var kind string
	var ct []byte
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT kind, ciphertext FROM credential_deliveries
		 WHERE profile_id = $1 AND kind = 'delete'`,
		p.ID,
	).Scan(&kind, &ct))
	assert.Equal(t, "delete", kind)
	assert.Nil(t, ct)
}

func TestCredentials_UniqueNamePerOrg_Conflict(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p1 := newProfile(f)
	p2 := newProfile(f)
	p2.Name = p1.Name

	_, err := f.store.CreateProfileWithDelivery(ctx, p1, []byte("x"))
	require.NoError(t, err)
	_, err = f.store.CreateProfileWithDelivery(ctx, p2, []byte("x"))
	assert.Error(t, err, "duplicate name must fail")
}

func TestCredentials_ClaimNextDelivery_SingleUse(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := f.store.ClaimNextDelivery(ctx, f.engineID)
			if err == nil && ok {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&winners), "exactly one goroutine claims the only queued delivery")
}

func TestCredentials_AckDelivery_TerminalGuard(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	d, ok, err := f.store.ClaimNextDelivery(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, f.store.AckDelivery(ctx, d.ID, ""))
	err = f.store.AckDelivery(ctx, d.ID, "")
	assert.ErrorIs(t, err, ErrDeliveryAlreadyAcked)
}

func TestCredentials_ReclaimStaleDeliveries(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	d, ok, err := f.store.ClaimNextDelivery(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)

	// Back-date claimed_at to 30 minutes ago.
	_, err = f.pool.Exec(ctx,
		`UPDATE credential_deliveries SET claimed_at = NOW() - INTERVAL '30 minutes' WHERE id = $1`,
		d.ID,
	)
	require.NoError(t, err)

	cutoff := time.Now().Add(-15 * time.Minute)
	require.NoError(t, f.store.ReclaimStaleDeliveries(ctx, cutoff))

	var status string
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT status FROM credential_deliveries WHERE id = $1`, d.ID,
	).Scan(&status))
	assert.Equal(t, "queued", status)
}

func TestCredentials_CreateTestJob_AndClaim(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	tj := TestJob{
		ID:        uuid.Must(uuid.NewV7()),
		OrgID:     f.orgID,
		EngineID:  f.engineID,
		ProfileID: p.ID,
		HostIDs:   f.hostIDs,
	}
	created, err := f.store.CreateTestJob(ctx, tj)
	require.NoError(t, err)
	assert.Equal(t, "queued", created.Status)

	claimed, ok, err := f.store.ClaimNextTest(ctx, f.engineID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, tj.ID, claimed.ID)
	assert.ElementsMatch(t, f.hostIDs, claimed.HostIDs)
}

func TestCredentials_FinishTestJob_TerminalGuard(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	tj := TestJob{
		ID: uuid.Must(uuid.NewV7()), OrgID: f.orgID, EngineID: f.engineID,
		ProfileID: p.ID, HostIDs: f.hostIDs,
	}
	_, err = f.store.CreateTestJob(ctx, tj)
	require.NoError(t, err)

	require.NoError(t, f.store.FinishTestJob(ctx, tj.ID, "completed", ""))
	err = f.store.FinishTestJob(ctx, tj.ID, "completed", "")
	assert.ErrorIs(t, err, ErrTestAlreadyTerminal)
}

func TestCredentials_InsertTestResults_Idempotent(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	p := newProfile(f)
	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	tj := TestJob{
		ID: uuid.Must(uuid.NewV7()), OrgID: f.orgID, EngineID: f.engineID,
		ProfileID: p.ID, HostIDs: f.hostIDs,
	}
	_, err = f.store.CreateTestJob(ctx, tj)
	require.NoError(t, err)

	first := []TestResult{{TestID: tj.ID, HostID: f.hostIDs[0], Success: false, Error: "timeout"}}
	require.NoError(t, f.store.InsertTestResults(ctx, first))

	// Retry with a better outcome — second insert must overwrite.
	second := []TestResult{{TestID: tj.ID, HostID: f.hostIDs[0], Success: true, LatencyMs: 42}}
	require.NoError(t, f.store.InsertTestResults(ctx, second))

	results, err := f.store.ListTestResults(ctx, tj.ID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Success)
	assert.Equal(t, 42, results[0].LatencyMs)
	assert.Empty(t, results[0].Error)
}

func TestCredentials_MatcherJSONBRoundtrip(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	complex := Matcher{
		GroupIDs: []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())},
		OS:       "linux",
		CIDR:     "10.0.0.0/24",
		Tags:     map[string]string{"env": "prod", "team": "sre"},
	}
	p := newProfile(f)
	p.Matcher = complex

	_, err := f.store.CreateProfileWithDelivery(ctx, p, []byte("x"))
	require.NoError(t, err)

	got, err := f.store.GetProfile(ctx, f.orgID, p.ID)
	require.NoError(t, err)
	assert.Equal(t, complex.OS, got.Matcher.OS)
	assert.Equal(t, complex.CIDR, got.Matcher.CIDR)
	assert.ElementsMatch(t, complex.GroupIDs, got.Matcher.GroupIDs)
	assert.Equal(t, complex.Tags, got.Matcher.Tags)
}

func TestCredentials_GetEngineEncryptionPubkey(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	// Engine exists but no pubkey set yet → (nil, nil).
	pk, err := f.store.GetEngineEncryptionPubkey(ctx, f.engineID)
	require.NoError(t, err)
	assert.Nil(t, pk)

	// Set a pubkey and round-trip it.
	want := make([]byte, 32)
	_, err = rand.Read(want)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx,
		`UPDATE engines SET encryption_pubkey = $2 WHERE id = $1`,
		f.engineID, want,
	)
	require.NoError(t, err)

	pk, err = f.store.GetEngineEncryptionPubkey(ctx, f.engineID)
	require.NoError(t, err)
	assert.Equal(t, want, pk)
}

// Helper — silences unused-import errors when we prune tests during
// development. net is imported for future host/matcher variants.
var _ = net.ParseIP
