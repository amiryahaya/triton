package manageserver

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
)

// runDeactivationWatcher polls at cfg.WatcherTickInterval (default 10s) while pending_deactivation
// is set. It fires deactivateNow once CountActive returns 0.
// Exits when ctx is cancelled, when the flag is cleared (cancel case),
// or after firing deactivation.
func (s *Server) runDeactivationWatcher(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.WatcherTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state, err := s.store.GetSetup(ctx)
			if err != nil {
				log.Printf("deactivation watcher: read setup: %v", err)
				continue
			}
			if !state.PendingDeactivation {
				// Flag was cleared (admin cancelled). Exit watcher.
				return
			}

			var active int64
			if state.InstanceID != "" {
				if tenantID, err := uuid.Parse(state.InstanceID); err == nil {
					active, _ = s.scanjobsStore.CountActive(ctx, tenantID)
				}
			}
			if active > 0 {
				continue
			}

			if err := s.deactivateNow(ctx); err != nil {
				log.Printf("deactivation watcher: deactivateNow failed, will retry: %v", err)
				continue
			}
			return
		}
	}
}
