package manageserver

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

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
		OnPushSuccess: s.onUsagePushSuccess,
		OnPushFailure: s.onUsagePushFailure,
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

	// Propagate the guard into every sub-handler package so that hosts
	// (H2), scan-jobs (H3) and agents (H4) cap enforcement fires in
	// production. Without this, only H1 (seat cap) would work — the
	// other sub-handlers read their own `Guard` field directly, which
	// would otherwise stay nil forever. Tests that swap a fake via
	// Set*CapGuardForTest win because their override sets the same
	// field under the same mu critical section.
	if s.hostsAdmin != nil {
		s.hostsAdmin.Guard = guard
	}
	if s.scanjobsAdmin != nil {
		s.scanjobsAdmin.Guard = guard
	}
	if s.agentsAdmin != nil {
		s.agentsAdmin.Guard = guard
	}
	s.mu.Unlock()

	go pusher.Run(pCtx)
	return nil
}

// collectUsage reports current usage metrics to the License Server
// AND mirrors them into the in-memory Guard so the soft-buffer scan
// cap arithmetic (`used + expected > SoftBufferCeiling`) has a
// non-zero `used` to work with.
//
// Without the RecordUsage mirror here, Guard.CurrentUsage("scans",
// "monthly") would stay permanently 0 and the soft-buffered scan cap
// would degrade from `used + expected > ceiling` to `expected >
// ceiling` — meaning no matter how many small batches an operator
// submits, the per-batch expected count never tops the ceiling and
// incremental drift past the cap goes undetected.
//
// Window boundary: scans/monthly rolls over at the first moment of
// each calendar month in UTC. Matches the License Server's own
// month-aligned reset and avoids local-timezone ambiguity across
// Manage Server instances in different regions. Consequence: an
// operator in UTC+8 sees the counter roll over at 08:00 local on
// the 1st.
//
// Nil Guard (licence not yet activated) → returns nil without
// touching the DB, so the pusher's heartbeat still fires but carries
// no metrics.
func (s *Server) collectUsage() []license.UsageMetric {
	s.mu.RLock()
	guard := s.licenceGuard
	scanjobsStore := s.scanjobsStore
	s.mu.RUnlock()

	if guard == nil || scanjobsStore == nil {
		return nil
	}

	ctx := context.Background()
	state, err := s.store.GetSetup(ctx)
	if err != nil {
		log.Printf("manageserver/license: collectUsage: read setup state: %v", err)
		return nil
	}
	if state.InstanceID == "" {
		return nil
	}
	tenantID, err := uuid.Parse(state.InstanceID)
	if err != nil {
		log.Printf("manageserver/license: collectUsage: parse instance_id %q: %v",
			state.InstanceID, err)
		return nil
	}

	// UTC month start — fixed across regions so the monthly cap resets
	// deterministically and matches the License Server's own alignment.
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	scanCount, err := scanjobsStore.CountCompletedSince(ctx, tenantID, monthStart)
	if err != nil {
		log.Printf("manageserver/license: collectUsage: count completed scans: %v", err)
		return nil
	}

	metrics := []license.UsageMetric{
		{Metric: "scans", Window: "monthly", Value: scanCount},
	}

	// Mirror into the Guard so CurrentUsage is accurate regardless of
	// whether the subsequent LS push succeeds. This is what lets the
	// soft-buffer cap enforce `used + expected > ceiling` between LS
	// pushes — in particular, when the LS is briefly unreachable.
	for _, m := range metrics {
		guard.RecordUsage(m.Metric, m.Window, m.Value)
	}
	return metrics
}

// onUsagePushSuccess stamps manage_license_state.last_pushed_at +
// last_pushed_metrics after a successful LS push. Hook fires
// synchronously on the UsagePusher's goroutine; kept narrow — one
// DB write — so the pusher tick cadence isn't perturbed.
//
// No-ops when resultsStore is nil (tests that don't exercise the
// drain pipeline). DB errors are logged so sustained failures don't
// silently drop metric freshness.
func (s *Server) onUsagePushSuccess(ctx context.Context, metricsJSON []byte) {
	if s.resultsStore == nil {
		return
	}
	if err := s.resultsStore.RecordPushSuccess(ctx, metricsJSON); err != nil {
		log.Printf("manageserver/license: record push success: %v", err)
	}
}

// onUsagePushFailure increments manage_license_state.consecutive_failures
// and stashes the reason. Same lifecycle as onUsagePushSuccess.
func (s *Server) onUsagePushFailure(ctx context.Context, reason string) {
	if s.resultsStore == nil {
		return
	}
	if err := s.resultsStore.RecordPushFailure(ctx, reason); err != nil {
		log.Printf("manageserver/license: record push failure: %v", err)
	}
}

// stopLicence cancels any running usage pusher and clears all licence fields.
// Called during Server.Run shutdown. Safe to call when no pusher is running.
//
// All three licence fields (guard, pusher, cancel) are cleared under the same
// locked critical section so that feature-gated middleware reading
// s.licenceGuard after shutdown sees a clean nil state rather than a stale
// guard pointing at a cancelled pusher.
func (s *Server) stopLicence() {
	s.mu.Lock()
	cancel := s.licenceCancel
	s.licenceGuard = nil
	s.licencePusher = nil
	s.licenceCancel = nil
	// Mirror the propagation in startLicence so a clean shutdown
	// doesn't leave sub-handlers holding a guard that points at a
	// cancelled pusher. ClearSeatCapGuardForTest already clears these
	// fields in test tear-down — the same surface just for the
	// production Run() shutdown path.
	if s.hostsAdmin != nil {
		s.hostsAdmin.Guard = nil
	}
	if s.scanjobsAdmin != nil {
		s.scanjobsAdmin.Guard = nil
	}
	if s.agentsAdmin != nil {
		s.agentsAdmin.Guard = nil
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
