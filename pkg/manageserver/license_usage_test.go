//go:build integration

package manageserver_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// TestCollectUsage_RecordsScansIntoGuard is the D1 guardrail: without
// RecordUsage being called on the Guard, CurrentUsage("scans","monthly")
// stays permanently 0 and the soft-buffer cap arithmetic degrades from
// `used + expected > ceiling` to `expected > ceiling`. Small-batch
// incremental scans would never trip the cap even at 10x over quota.
//
// This test seeds 5 completed scan jobs in the current month, activates
// a real licence (so s.licenceGuard is populated), and calls
// collectUsage. It asserts (a) the returned metric reflects the DB
// count and (b) Guard.CurrentUsage("scans","monthly") has been
// mirrored to 5 — which is what makes the soft-buffer cap work
// between pusher ticks.
func TestCollectUsage_RecordsScansIntoGuard(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic-d1",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_d1_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	})

	// instance_id in SetupState drives collectUsage's tenant filter.
	// Use a fixed UUID so we can parse+seed jobs against the same id.
	instanceID := uuid.Must(uuid.NewV7())
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	require.NoError(t, store.SaveLicenseActivation(context.Background(),
		"http://localhost:0", "lic-uuid-d1", signed, instanceID.String()))

	// Seed one zone + one host. Enqueue 5 jobs against that tenant,
	// then mark them running + completed so finished_at >= monthStart.
	pool := store.Pool()
	ctx := context.Background()
	var zoneID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name) VALUES ('d1-zone') RETURNING id`,
	).Scan(&zoneID))

	hostsStore := hosts.NewPostgresStore(pool)
	// 5 hosts so Enqueue produces 5 jobs in a single call.
	for i := 0; i < 5; i++ {
		_, err := hostsStore.Create(ctx, hosts.Host{
			Hostname: fmt.Sprintf("d1-host-%d", i), ZoneID: &zoneID,
		})
		require.NoError(t, err)
	}

	sjStore := scanjobs.NewPostgresStore(pool)
	jobs, err := sjStore.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: instanceID,
		ZoneIDs:  []uuid.UUID{zoneID},
		Profile:  scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 5)

	// Claim + complete each job via the real Store API so the row
	// transitions queued → running → completed and finished_at
	// stamps to NOW(). That's exactly what the orchestrator does,
	// and what CountCompletedSince will measure.
	for i := 0; i < 5; i++ {
		claimed, ok, err := sjStore.ClaimNext(ctx, fmt.Sprintf("test-worker-%d", i))
		require.NoError(t, err)
		require.True(t, ok, "claim must succeed on iteration %d", i)
		require.NoError(t, sjStore.Complete(ctx, claimed.ID))
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	guard := manageserver.LicenceGuardForTest(srv)
	require.NotNil(t, guard, "licence guard must be wired for collectUsage to mirror into")

	// Pre-condition: without ever having pushed, CurrentUsage is 0.
	assert.Equal(t, int64(0), guard.CurrentUsage("scans", "monthly"),
		"CurrentUsage must start at 0 before collectUsage runs")

	// ---- collectUsage is the D1 system-under-test.
	metrics := manageserver.CollectUsageForTest(srv)
	require.Len(t, metrics, 1, "collectUsage must emit exactly one scans/monthly metric")
	assert.Equal(t, "scans", metrics[0].Metric)
	assert.Equal(t, "monthly", metrics[0].Window)
	assert.Equal(t, int64(5), metrics[0].Value, "returned metric must reflect 5 completed scans")

	// And the critical invariant: the Guard mirrors the count so the
	// soft-buffer cap arithmetic between pusher ticks uses a real
	// `used` figure.
	assert.Equal(t, int64(5), guard.CurrentUsage("scans", "monthly"),
		"Guard.CurrentUsage must be mirrored by collectUsage (D1: soft-buffer cap correctness)")
}

// TestCollectUsage_NilGuard_Noop confirms that when the licence has
// NOT been activated (s.licenceGuard == nil), collectUsage returns
// nil without panicking and without reading the DB. The UsagePusher
// is never constructed in this path, so this is a defence-in-depth
// test against misuse (e.g. a future refactor wiring the pusher
// before the guard).
func TestCollectUsage_NilGuard_Noop(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	require.Nil(t, manageserver.LicenceGuardForTest(srv),
		"fresh server must have nil licenceGuard")

	metrics := manageserver.CollectUsageForTest(srv)
	assert.Nil(t, metrics, "collectUsage with nil guard must return nil")
}
