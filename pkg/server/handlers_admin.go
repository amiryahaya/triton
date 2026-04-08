package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
)

// minProvisionPasswordLen aliases auth.MinPasswordLength so the org
// provisioning endpoint stays in lockstep with the rest of the password
// policy. Canonical value lives in internal/auth/password.go.
const minProvisionPasswordLen = auth.MinPasswordLength

type provisionOrgRequest struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	AdminEmail        string `json:"admin_email"`
	AdminName         string `json:"admin_name"`
	AdminTempPassword string `json:"admin_temp_password"`
}

// handleProvisionOrg accepts an org provisioning request from the license
// server and creates the organization + first admin user on the report
// server side. The license server is expected to generate the temporary
// password and email it to the admin separately (Phase 1.7).
//
// Idempotent: if the org with the supplied ID already exists with the
// same name, the call returns 200 with the existing org and does not
// create a duplicate user. If the existing org has a different name,
// returns 409 (real conflict).
//
// The created admin user has role=org_admin and must_change_password=true
// — they will be forced to change the password on first login (Phase 1.5e).
//
// Authentication: this handler runs behind ServiceKeyAuth — only callers
// presenting the correct X-Triton-Service-Key may invoke it.
func (s *Server) handleProvisionOrg(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req provisionOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation. Order matches the field names so error messages are
	// straightforwardly mappable from the request payload.
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.AdminEmail))
	if email == "" || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "valid admin_email is required")
		return
	}
	if req.AdminName == "" {
		writeError(w, http.StatusBadRequest, "admin_name is required")
		return
	}
	if len(req.AdminTempPassword) < minProvisionPasswordLen {
		writeError(w, http.StatusBadRequest, "admin_temp_password must be at least 12 characters")
		return
	}

	ctx := r.Context()

	// Idempotency check: if the org already exists, treat as a no-op
	// success (license server retried). If the existing org has a
	// different name, that's a real conflict.
	if existing, err := s.store.GetOrg(ctx, req.ID); err == nil {
		if existing.Name != req.Name {
			writeError(w, http.StatusConflict, "organization with this id exists with a different name")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"org":            existing,
			"already_exists": true,
		})
		return
	}

	// Hash the temp password before any DB write so we don't have to
	// undo on hash failure.
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.AdminTempPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("provision: bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	now := time.Now().UTC()
	org := &store.Organization{
		ID:        req.ID,
		Name:      req.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateOrg(ctx, org); err != nil {
		// Race: two concurrent provisioning calls for the same org ID
		// can both pass the GetOrg idempotency check above and reach
		// CreateOrg. The PK collision lands here as ErrConflict. Treat
		// it as the loser of the race rather than a 500 — the winner
		// already created the org with the correct name (or a different
		// name, in which case the user-creation step below would also
		// fail with the email constraint, which is a real conflict
		// either way).
		var conflict *store.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, "organization already exists")
			return
		}
		log.Printf("provision: create org error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              req.ID,
		Email:              email,
		Name:               req.AdminName,
		Role:               "org_admin",
		Password:           string(hashed),
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.store.CreateUser(ctx, user); err != nil {
		// Best-effort cleanup so we don't leave an orphan org. The store
		// interface doesn't currently expose transactions; when it does,
		// wrap CreateOrg + CreateUser in a single tx and remove this.
		// TODO(phase-1.5-followup): replace cleanup-on-failure with a
		// real transactional CreateOrgWithAdmin store method.
		//
		// Log (don't swallow) the rollback failure — an orphan org would
		// need manual cleanup, and the only signal ops has is the log.
		if delErr := s.store.DeleteOrg(ctx, org.ID); delErr != nil {
			log.Printf("provision: ROLLBACK FAILED — orphan org %s: %v", org.ID, delErr)
		}

		var conflict *store.ErrConflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, "user with this email already exists")
			return
		}
		log.Printf("provision: create user error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"org":           org,
		"admin_user_id": user.ID,
	})
}
