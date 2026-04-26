//go:build integration

package scanjobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// TestScanRunner_QuickProfile_Localhost exercises the real scanner
// through the scan runner to pin that:
//
//   - NewScanFunc resolves the host via the Store.
//   - scannerconfig.BuildConfig accepts "quick".
//   - Engine.Scan returns a non-nil ScanResult with the host's
//     hostname stamped into metadata.
//
// We do NOT assert findings count: quick-profile modules (certs/keys/
// packages) may legitimately find nothing in CI. The point of the
// test is the wiring, not the scanner's content.
func TestScanRunner_QuickProfile_Localhost(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	hs := hosts.NewPostgresStore(pool)
	h, err := hs.Create(ctx, hosts.Host{Hostname: "localhost", IP: "127.0.0.1"})
	require.NoError(t, err)

	runner := scanjobs.NewScanFunc(hs)

	// A generous timeout so the real scanner has time to walk the
	// default OS-local filesystem targets. If this ever proves flaky
	// in CI, we can layer a custom Config with a narrower ScanTargets
	// set — but the point of D6 is to exercise the canonical wiring.
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	j := scanjobs.Job{
		ID:       uuid.Must(uuid.NewV7()),
		HostID:   h.ID,
		Profile:  scanjobs.ProfileQuick,
		TenantID: uuid.Must(uuid.NewV7()),
	}
	res, err := runner(runCtx, j)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "localhost", res.Metadata.Hostname, "SetHostnameOverride must flow into metadata")
	assert.Equal(t, "quick", res.Metadata.ScanProfile)
}

// TestScanRunner_MissingHost_ReturnsError pins the error surface when
// the job's HostID doesn't resolve — the orchestrator will map this
// to Store.Fail via its normal error path.
func TestScanRunner_MissingHost_ReturnsError(t *testing.T) {
	pool := newTestPool(t)

	runner := scanjobs.NewScanFunc(hosts.NewPostgresStore(pool))

	j := scanjobs.Job{
		ID:      uuid.Must(uuid.NewV7()),
		HostID:  uuid.Must(uuid.NewV7()), // never inserted
		Profile: scanjobs.ProfileQuick,
	}
	_, err := runner(context.Background(), j)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve host")
}
