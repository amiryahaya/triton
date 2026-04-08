package licenseserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// ProvisionOrgInput is the user-level intent for creating a new org.
// Admin fields are optional — if empty, provisioning is a single-server
// operation (license server only) and no report server / email side
// effects occur. If present, both AdminEmail and AdminName must be
// validated by the caller BEFORE calling ProvisionOrgWithAdmin.
type ProvisionOrgInput struct {
	Name       string
	Contact    string
	Notes      string
	AdminEmail string // optional — leave empty to skip admin provisioning
	AdminName  string // required iff AdminEmail is non-empty
}

// ProvisionResult is what ProvisionOrgWithAdmin returns on success. The
// AdminBlock is nil when the input had no admin fields. When present,
// AdminBlock.TempPassword is plaintext and must be handled with care
// (returned once in the API response, emailed via Mailer, not logged).
type ProvisionResult struct {
	Org   *licensestore.Organization
	Admin *AdminProvisionResult // nil = no admin was provisioned
}

// AdminProvisionResult describes the admin user that was created on
// the report server and the outcome of email delivery.
type AdminProvisionResult struct {
	Email          string
	TempPassword   string
	EmailDelivered bool // true if Mailer.SendInviteEmail succeeded, false on failure (non-fatal)
}

// ProvisionOrgWithAdmin performs the org-create-with-admin workflow:
//
//  1. Create the org in the license store
//  2. If admin fields present: generate temp password + call report server
//  3. On report server failure: roll back the license store org
//  4. If success: send invite email via Mailer (best effort — failure
//     is logged but does not abort the operation)
//
// The returned errStatus is an HTTP status code to surface to the
// caller (0 = success). This keeps the handler a thin adapter: it
// parses/validates the request and writes the response, but all the
// business logic — creation, rollback, email — lives here.
//
// Extracted per Phase 1.7/1.8 architecture review finding #7: the
// handler was ~140 lines with too many concerns, making it hard to
// test in isolation.
func (s *Server) ProvisionOrgWithAdmin(ctx context.Context, input ProvisionOrgInput) (result *ProvisionResult, errStatus int, err error) {
	wantAdmin := input.AdminEmail != ""

	// Dependency check: admin provisioning requires a configured
	// report client. The handler also checks this up-front so the
	// caller can distinguish "not configured" from other errors.
	if wantAdmin && s.reportAPIClient == nil {
		return nil, 503, errors.New("report server not configured")
	}

	now := time.Now().UTC()
	org := &licensestore.Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      input.Name,
		Contact:   input.Contact,
		Notes:     input.Notes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if storeErr := s.store.CreateOrg(ctx, org); storeErr != nil {
		var conflict *licensestore.ErrConflict
		if errors.As(storeErr, &conflict) {
			return nil, 409, conflict
		}
		log.Printf("provision: create org error: %v", storeErr)
		return nil, 500, fmt.Errorf("creating org: %w", storeErr)
	}

	result = &ProvisionResult{Org: org}

	if !wantAdmin {
		return result, 0, nil
	}

	// Generate temp password and call the report server.
	tempPassword, tpErr := GenerateTempPassword()
	if tpErr != nil {
		log.Printf("provision: temp password generation failed: %v", tpErr)
		s.rollbackOrg(ctx, org.ID)
		return nil, 500, fmt.Errorf("generating temp password: %w", tpErr)
	}

	_, provErr := s.reportAPIClient.ProvisionOrg(ctx, ProvisionOrgRequest{
		ID:                org.ID,
		Name:              org.Name,
		AdminEmail:        input.AdminEmail,
		AdminName:         input.AdminName,
		AdminTempPassword: tempPassword,
	})
	if provErr != nil {
		log.Printf("provision: report server provisioning failed: %v", provErr)
		s.rollbackOrg(ctx, org.ID)
		return nil, 502, fmt.Errorf("report server provisioning: %w", provErr)
	}

	// Best-effort email delivery. Failure is logged but does not abort
	// the operation — the temp password is still returned in the API
	// response for out-of-band delivery.
	emailDelivered := true
	if s.config.Mailer != nil {
		emailErr := s.config.Mailer.SendInviteEmail(ctx, InviteEmailData{
			ToEmail:      input.AdminEmail,
			ToName:       input.AdminName,
			OrgName:      org.Name,
			TempPassword: tempPassword,
			LoginURL:     s.config.ReportServerInviteURL,
		})
		if emailErr != nil {
			log.Printf("provision: invite email delivery failed (non-fatal): %v", emailErr)
			emailDelivered = false
		}
	} else {
		// No mailer configured — caller must deliver manually.
		emailDelivered = false
	}

	result.Admin = &AdminProvisionResult{
		Email:          input.AdminEmail,
		TempPassword:   tempPassword,
		EmailDelivered: emailDelivered,
	}
	return result, 0, nil
}

// rollbackOrg is a best-effort delete of an org that failed provisioning.
// Uses context.WithoutCancel so a cancelled request context (client
// disconnect mid-flow) doesn't silently skip the rollback and leave an
// orphan org (D1 lesson from the Phase 1.7/1.8 review).
func (s *Server) rollbackOrg(ctx context.Context, orgID string) {
	rollbackCtx := context.WithoutCancel(ctx)
	if delErr := s.store.DeleteOrg(rollbackCtx, orgID); delErr != nil {
		log.Printf("provision: ROLLBACK FAILED — orphan org %s: %v", orgID, delErr)
	}
}
