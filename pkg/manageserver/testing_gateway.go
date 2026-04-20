//go:build integration

package manageserver

import (
	"context"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// GatewayStateForTest exposes the atomic gateway state for integration
// tests that assert the retry loop + listener-up transitions. Returns
// one of the gatewayState* constants (pendingSetup=0, retryLoop=1,
// up=2, failed=3).
func (s *Server) GatewayStateForTest() int32 { return s.gatewayState.Load() }

// StoreForTest returns the underlying managestore.Store so integration
// tests can read setup state (e.g. fetch the instance_id before
// bootstrapping the CA to simulate post-Run recovery).
func (s *Server) StoreForTest() managestore.Store { return s.store }

// CAStoreForTest returns the underlying ca.PostgresStore so integration
// tests can manually bootstrap the CA (to simulate the /setup/license
// path landing the CA after Server.Run has started).
func (s *Server) CAStoreForTest() *ca.PostgresStore { return s.caStore }

// BootstrapGatewayForTest mints the gateway server leaf synchronously
// without spawning the real :8443 listener. Intended for tests that
// need gatewayState=Up + serverLeaf populated but can't share the port
// with an httptest.Server on the admin router.
//
// Bootstraps the CA first (idempotent) using the instance_id from the
// setup state. Flips gatewayState to Up on success.
func (s *Server) BootstrapGatewayForTest(ctx context.Context) error {
	setup, err := s.store.GetSetup(ctx)
	if err != nil {
		return err
	}
	if _, err := s.caStore.Bootstrap(ctx, setup.InstanceID); err != nil {
		return err
	}
	cert, err := s.caStore.IssueServerCert(ctx, s.cfg.GatewayHostname)
	if err != nil {
		return err
	}
	s.serverLeaf.Store(cert)
	s.gatewayState.Store(gatewayStateUp)
	return nil
}
