//go:build integration

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// TestAudit_UserCreateDeleteCycle verifies Phase 5 Sprint 3 B2:
// creating and deleting a user via the CRUD API writes two
// audit events that the admin can list via GET /api/v1/audit.
func TestAudit_UserCreateDeleteCycle(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, token := loginAsRole(t, srv, db, "org_admin")

	// Create a user — should emit user.create.
	wCreate := authReq(t, srv, http.MethodPost, "/api/v1/users", token, map[string]any{
		"email":    "audit-target@example.com",
		"name":     "Audit Target",
		"role":     "org_user",
		"password": "audit-password-12",
	})
	require.Equal(t, http.StatusCreated, wCreate.Code)
	var created map[string]any
	require.NoError(t, json.NewDecoder(wCreate.Body).Decode(&created))
	targetID := created["id"].(string)

	// Delete the user — should emit user.delete.
	wDel := authReq(t, srv, http.MethodDelete, "/api/v1/users/"+targetID, token, nil)
	require.Equal(t, http.StatusOK, wDel.Code)

	// Audit writes are fire-and-forget via a goroutine. Wait until
	// both events are visible rather than sleeping — bounded retry.
	var events []store.AuditEvent
	for i := 0; i < 20; i++ {
		wList := authReq(t, srv, http.MethodGet, "/api/v1/audit/", token, nil)
		require.Equal(t, http.StatusOK, wList.Code, "audit GET body: %s", wList.Body.String())
		require.NoError(t, json.NewDecoder(wList.Body).Decode(&events))
		if len(events) >= 2 {
			break
		}
		// Minimal sleep — the goroutine is in-process, so a short
		// yield is almost always enough.
		waitForAudit()
	}
	require.GreaterOrEqual(t, len(events), 2,
		"create + delete should have emitted two audit events")

	// Events are newest-first; the delete should be index 0, create index 1.
	// A looser assertion: both types must be present in the list.
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.EventType] = true
	}
	assert.True(t, seen[auditUserCreate], "user.create event must be present")
	assert.True(t, seen[auditUserDelete], "user.delete event must be present")
}

// TestAudit_TenantIsolation verifies that one org cannot read
// another org's audit events. Two separate admins in two separate
// orgs each create a user; each admin's audit query returns ONLY
// their own org's events.
func TestAudit_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, _, tokenA := loginAsRole(t, srv, db, "org_admin")
	_, _, tokenB := loginAsRole(t, srv, db, "org_admin")

	// Each admin creates a user in their own org.
	wA := authReq(t, srv, http.MethodPost, "/api/v1/users", tokenA, map[string]any{
		"email":    "alice-audit@example.com",
		"name":     "Alice",
		"role":     "org_user",
		"password": "alice-pw-123456",
	})
	require.Equal(t, http.StatusCreated, wA.Code)
	wB := authReq(t, srv, http.MethodPost, "/api/v1/users", tokenB, map[string]any{
		"email":    "bob-audit@example.com",
		"name":     "Bob",
		"role":     "org_user",
		"password": "bob-pw-1234567",
	})
	require.Equal(t, http.StatusCreated, wB.Code)

	// Bounded wait for both async audit writes to land.
	for i := 0; i < 20; i++ {
		wListA := authReq(t, srv, http.MethodGet, "/api/v1/audit/", tokenA, nil)
		var eventsA []store.AuditEvent
		_ = json.NewDecoder(wListA.Body).Decode(&eventsA)
		wListB := authReq(t, srv, http.MethodGet, "/api/v1/audit/", tokenB, nil)
		var eventsB []store.AuditEvent
		_ = json.NewDecoder(wListB.Body).Decode(&eventsB)
		if len(eventsA) >= 1 && len(eventsB) >= 1 {
			// Each admin sees EXACTLY one create event — their own.
			assert.Len(t, eventsA, 1, "admin A must see only their own org's event")
			assert.Len(t, eventsB, 1, "admin B must see only their own org's event")
			return
		}
		waitForAudit()
	}
	t.Fatal("audit events did not propagate within the wait budget")
}
