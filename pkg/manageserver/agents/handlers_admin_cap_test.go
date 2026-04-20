//go:build integration

package agents_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// fakeAgentCapGuard satisfies agents.AgentCapGuard with a fixed
// "<metric>/<window>" -> cap map. Unknown entries → -1 (unlimited).
type fakeAgentCapGuard struct {
	caps map[string]int64
}

func (f *fakeAgentCapGuard) LimitCap(metric, window string) int64 {
	if v, ok := f.caps[metric+"/"+window]; ok {
		return v
	}
	return -1
}

// TestAgentsAdmin_Enrol_CapExceeded_Returns403 asserts that the cap
// check runs BEFORE minting a cert: pre-seed N agents up to the cap,
// then attempt to enrol one more.
func TestAgentsAdmin_Enrol_CapExceeded_Returns403(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-cap-test")
	require.NoError(t, err)

	// Seed the cap+1 enrolments to reach the cap via the unguarded
	// handler, then swap in the cap guard for the next (rejected)
	// request.
	openH := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	openSrv := mountEnrol(t, openH)

	const cap = 2
	for i := 0; i < cap; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
			strings.NewReader(`{"name":"seeded"}`))
		rec := httptest.NewRecorder()
		openSrv.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "seed %d: %s", i, rec.Body.String())
	}

	// Sanity-check the agent count before switching the cap guard in.
	n, err := agentStore.Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(cap), n)

	fakeGuard := &fakeAgentCapGuard{caps: map[string]int64{"agents/total": cap}}
	guardedH := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second,
		func() agents.AgentCapGuard { return fakeGuard })
	guardedSrv := mountEnrol(t, guardedH)

	// cap+1 enrol must be rejected.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"tipping-point"}`))
	rec := httptest.NewRecorder()
	guardedSrv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "agent cap")

	// No new row persisted.
	n, err = agentStore.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(cap), n, "cap-exceeded enrol must not have persisted")
}

// TestAgentsAdmin_Enrol_NoGuard_Unrestricted confirms the nil-guard
// path leaves enrolment unrestricted.
func TestAgentsAdmin_Enrol_NoGuard_Unrestricted(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-noguard-test")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"unrestricted"}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "nil guard must not block enrol")
}
