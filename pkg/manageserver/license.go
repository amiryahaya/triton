package manageserver

import (
	"context"
	"fmt"

	"github.com/amiryahaya/triton/internal/license"
)

// startLicence brings the licence guard + usage pusher online based on the
// current SetupState. Idempotent: a no-op when the server is still in setup
// mode. Safe to call on Server construction AND after /setup/license succeeds.
//
// Failures here are returned so /setup/license can log + surface; callers
// invoking startLicence at boot should log and continue — a bad persisted
// token should not block the server starting its HTTP listener (admins can
// re-activate via the API once the process is up).
func (s *Server) startLicence(ctx context.Context) error {
	state, err := s.store.GetSetup(ctx)
	if err != nil {
		return fmt.Errorf("read setup state: %w", err)
	}
	if !state.LicenseActivated {
		// Not activated yet — server stays in setup mode; nothing to run.
		return nil
	}

	guard := license.NewGuardFromToken(state.SignedToken, s.cfg.PublicKey)
	if guard == nil || !guard.HasFeature("manage") {
		// Either the token fails to parse (bad sig / expired / wrong pubkey)
		// or it parses but the manage feature is absent. We DO NOT auto-revert
		// setup state here — admin re-activation is explicit via /setup/license.
		return fmt.Errorf("licence parse failed or missing manage feature")
	}

	pusher := license.NewUsagePusher(license.UsagePusherConfig{
		LicenseServer: state.LicenseServerURL,
		LicenseID:     state.LicenseKey,
		InstanceID:    state.InstanceID,
		Source:        s.collectUsage,
	})

	pCtx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	// If a previous startLicence already spawned a pusher (e.g. boot path ran,
	// then /setup/license ran), cancel the old goroutine first so we don't
	// leak one per re-activation.
	if s.licenceCancel != nil {
		s.licenceCancel()
	}
	s.licenceGuard = guard
	s.licencePusher = pusher
	s.licenceCancel = cancel
	s.mu.Unlock()

	go pusher.Run(pCtx)
	return nil
}

// collectUsage reports current usage metrics to the License Server. B1 has
// no counted metrics yet (hosts, zones, tenants, scans all arrive in B2), so
// it returns an empty slice. The pusher still issues a heartbeat POST every
// Interval, which LS uses to detect live instances.
func (s *Server) collectUsage() []license.UsageMetric {
	return []license.UsageMetric{}
}

// stopLicence cancels any running usage pusher. Called during Server.Run
// shutdown. Safe to call when no pusher is running.
func (s *Server) stopLicence() {
	s.mu.Lock()
	cancel := s.licenceCancel
	s.licenceCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
