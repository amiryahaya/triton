//go:build integration

package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetrics_ExposesExpectedSeries verifies Phase 5 Sprint 3 B4:
// GET /api/v1/metrics emits a Prometheus-format response that
// contains every series the operator runbook refers to. A missing
// series would break dashboards the moment this ships.
func TestMetrics_ExposesExpectedSeries(t *testing.T) {
	srv, _ := testServer(t)

	w := authReq(t, srv, http.MethodGet, "/api/v1/metrics", "", nil)
	require.Equal(t, http.StatusOK, w.Code)

	ct := w.Header().Get("Content-Type")
	assert.Contains(t, ct, "text/plain",
		"metrics response must be text/plain (Prometheus exposition format)")
	assert.Contains(t, ct, "version=0.0.4",
		"Content-Type must advertise Prometheus text format 0.0.4")

	body := w.Body.String()
	expected := []string{
		"triton_login_rate_limiter_tracked",
		"triton_login_rate_limiter_locked",
		"triton_request_rate_limiter_tracked",
		"triton_go_goroutines",
		"triton_go_memstats_alloc_bytes",
		"triton_go_memstats_sys_bytes",
		"triton_go_memstats_gc_runs",
		// Analytics Phase 1 — backfill observability.
		"triton_backfill_scans_processed_total",
		"triton_backfill_scans_failed_total",
		"triton_backfill_in_progress",
	}
	for _, series := range expected {
		// Each series must appear with both a HELP comment and a
		// TYPE comment followed by the value line.
		assert.True(t, strings.Contains(body, "# HELP "+series),
			"missing HELP comment for %s", series)
		assert.True(t, strings.Contains(body, "# TYPE "+series),
			"missing TYPE declaration for %s", series)
	}
}

// TestMetrics_BackfillFlagReflectsState verifies that the
// triton_backfill_in_progress gauge emits 1 when the Server's
// backfillInProgress atomic flag is set and 0 otherwise. This is the
// signal the UI uses to decide whether to show the X-Backfill-In-
// Progress banner on analytics views.
func TestMetrics_BackfillFlagReflectsState(t *testing.T) {
	srv, _ := testServer(t)

	// Flag unset — expect "triton_backfill_in_progress 0".
	w := authReq(t, srv, http.MethodGet, "/api/v1/metrics", "", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "triton_backfill_in_progress 0")

	// Set the flag, scrape again, expect "1".
	srv.BackfillInProgress().Store(true)
	defer srv.BackfillInProgress().Store(false)

	w2 := authReq(t, srv, http.MethodGet, "/api/v1/metrics", "", nil)
	require.Equal(t, http.StatusOK, w2.Code)
	assert.Contains(t, w2.Body.String(), "triton_backfill_in_progress 1")
}

// TestMetrics_PublicAccess verifies that the metrics endpoint is
// reachable without any auth header — Prometheus scrapers don't
// authenticate, and operators restrict access at the network
// level. This test guards against an accidental regression that
// puts the endpoint behind JWTAuth.
func TestMetrics_PublicAccess(t *testing.T) {
	srv, _ := testServer(t)

	// Empty token intentionally — no Authorization header set.
	w := authReq(t, srv, http.MethodGet, "/api/v1/metrics", "", nil)
	assert.Equal(t, http.StatusOK, w.Code,
		"metrics endpoint must be publicly reachable (no auth required)")
}
