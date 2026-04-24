package manageserver

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
)

// runDeactivationWatcher polls every 10 seconds while pending_deactivation
// is set. It fires deactivateNow once CountActive returns 0.
// Exits when ctx is cancelled, when the flag is cleared (cancel case),
// or after firing deactivation.
func (s *Server) runDeactivationWatcher(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
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
				log.Printf("deactivation watcher: deactivateNow: %v", err)
			}
			return
		}
	}
}
