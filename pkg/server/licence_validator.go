package server

import (
	"context"
	"log"
	"time"
)

const (
	licenceValidatorInterval = 24 * time.Hour
	licenceGracePeriod       = 30 * 24 * time.Hour
	licenceWarnBefore        = 14 * 24 * time.Hour
)

// startLicenceValidator launches a goroutine that validates all tenant
// licences every 24 hours. It stops when ctx is cancelled.
//
// If licencePortalClient is nil, the validator is not started and
// licenceValidatorDone is never closed — callers awaiting it should
// guard with a context timeout.
func (s *Server) startLicenceValidator(ctx context.Context) {
	if s.licencePortalClient == nil {
		return
	}
	go func() {
		defer close(s.licenceValidatorDone)
		ticker := time.NewTicker(licenceValidatorInterval)
		defer ticker.Stop()
		// Run immediately on startup so the first validation doesn't wait 24 h.
		s.runLicenceValidation(ctx)
		for {
			select {
			case <-ticker.C:
				s.runLicenceValidation(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) runLicenceValidation(ctx context.Context) {
	licences, err := s.store.ListTenantLicences(ctx)
	if err != nil {
		log.Printf("licence validator: list licences: %v", err)
		return
	}

	inst, err := s.store.GetOrCreateInstance(ctx)
	if err != nil {
		log.Printf("licence validator: get instance: %v", err)
		return
	}

	for _, tl := range licences {
		if tl.Status == "expired" {
			continue
		}

		machineID := inst.ID + "/" + tl.OrgID
		resp, err := s.licencePortalClient.ValidateForTenant(tl.LicenceID, tl.Token, machineID)
		if err != nil {
			log.Printf("licence validator: validate %s: %v (using cached expires_at)", tl.OrgID, err)
		} else if resp.Valid {
			expiresAt, parseErr := time.Parse(time.RFC3339, resp.ExpiresAt)
			if parseErr == nil && !expiresAt.IsZero() {
				tl.ExpiresAt = expiresAt
			}
			now := time.Now().UTC()
			tl.RenewedAt = &now
		}

		tl.Status = computeLicenceStatus(tl.ExpiresAt)
		if err := s.store.UpsertTenantLicence(ctx, &tl); err != nil {
			log.Printf("licence validator: upsert %s: %v", tl.OrgID, err)
		}
	}
}

// computeLicenceStatus derives the licence status from expiry time:
//
//	active:  expires_at is in the future.
//	grace:   expired within the last 30 days.
//	expired: expired more than 30 days ago.
func computeLicenceStatus(expiresAt time.Time) string {
	now := time.Now().UTC()
	if expiresAt.After(now) {
		return "active"
	}
	if now.Sub(expiresAt) <= licenceGracePeriod {
		return "grace"
	}
	return "expired"
}
