//go:build integration

package manageserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGatewayRetry_BootstrapsMidRun starts Server.Run with the CA absent
// (openOperationalServerWithRetryInterval seeds admin + license directly
// via the store, bypassing handlers_setup.go's Bootstrap call). The
// retry loop must observe gatewayState=pending_setup, then flip to up
// within a couple of retry intervals once the CA is bootstrapped
// out-of-band — proving the :8443 listener self-recovers without a
// process restart.
func TestGatewayRetry_BootstrapsMidRun(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithRetryInterval(t, 100*time.Millisecond)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// Initial state: pending_setup (0). Wait one retry interval so the
	// loop has had a chance to tick at least once with no CA present.
	require.Eventually(t, func() bool {
		return srv.GatewayStateForTest() == 0 /* pendingSetup */
	}, 500*time.Millisecond, 25*time.Millisecond,
		"initial gatewayState should be pending_setup")

	// Bootstrap CA out-of-band — simulates what /setup/license does
	// once the admin has entered a license token post-Run.
	setup, err := srv.StoreForTest().GetSetup(ctx)
	require.NoError(t, err)
	_, err = srv.CAStoreForTest().Bootstrap(ctx, setup.InstanceID)
	require.NoError(t, err)

	// Within a few retry intervals the listener should be up.
	assert.Eventually(t, func() bool {
		return srv.GatewayStateForTest() == 2 /* up */
	}, 3*time.Second, 50*time.Millisecond,
		"gatewayState should flip to up within a few retry intervals")

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Server.Run did not exit within 3s of cancel")
	}
}

// TestGatewayRetry_CancelStopsRetryLoop verifies that cancelling the
// context while the retry loop is polling (CA never bootstrapped) causes
// Server.Run to exit promptly, rather than leaving the loop stuck.
func TestGatewayRetry_CancelStopsRetryLoop(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithRetryInterval(t, 100*time.Millisecond)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// Let the retry loop tick at least twice before cancelling so we
	// exercise the select-on-ctx.Done path (not the first-iteration
	// cancel-before-tick path).
	time.Sleep(250 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Run did not exit within 2s of cancel (retry loop stuck)")
	}
}
