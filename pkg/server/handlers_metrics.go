package server

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime"
)

// GET /api/v1/metrics — Phase 5 Sprint 3 B4.
//
// Emits Prometheus text-format (version 0.0.4) metrics covering the
// rate limiters, runtime, and a handful of counters every operator
// will want on day one. Kept dependency-free on purpose: pulling in
// the official prometheus client library would be a ~10MB increase
// on the container image for metrics a text/plain endpoint handles
// just fine.
//
// Exposition format reference:
//
//	https://prometheus.io/docs/instrumenting/exposition_formats/
//
// Security note: the endpoint is intentionally outside the
// authenticated route group because scrapers are usually bound to
// the internal network and cannot authenticate as a user. Operators
// who want to restrict access should put the server behind a
// reverse proxy that filters on source IP or TLS client cert. See
// DEPLOYMENT_GUIDE.md §10c.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	loginStats := s.loginLimiter.Stats()
	reqStats := s.requestLimiter.Stats()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Build the body in a buffer first so a single Write fires at
	// the network, and any fmt errors are captured by bytes.Buffer
	// (which never fails) rather than being lint-nagged on every
	// individual Fprintln. This also lets the test assert on a
	// complete snapshot rather than a stream-interleaved view.
	var body bytes.Buffer
	fmt.Fprintln(&body, "# HELP triton_login_rate_limiter_tracked Per-email login buckets currently held in memory.")
	fmt.Fprintln(&body, "# TYPE triton_login_rate_limiter_tracked gauge")
	fmt.Fprintf(&body, "triton_login_rate_limiter_tracked %d\n", loginStats.Tracked)

	fmt.Fprintln(&body, "# HELP triton_login_rate_limiter_locked Emails currently in the locked-out state.")
	fmt.Fprintln(&body, "# TYPE triton_login_rate_limiter_locked gauge")
	fmt.Fprintf(&body, "triton_login_rate_limiter_locked %d\n", loginStats.LockedEmails)

	fmt.Fprintln(&body, "# HELP triton_request_rate_limiter_tracked Per-tenant request buckets currently held in memory.")
	fmt.Fprintln(&body, "# TYPE triton_request_rate_limiter_tracked gauge")
	fmt.Fprintf(&body, "triton_request_rate_limiter_tracked %d\n", reqStats.Tracked)

	fmt.Fprintln(&body, "# HELP triton_go_goroutines Number of live goroutines.")
	fmt.Fprintln(&body, "# TYPE triton_go_goroutines gauge")
	fmt.Fprintf(&body, "triton_go_goroutines %d\n", runtime.NumGoroutine())

	fmt.Fprintln(&body, "# HELP triton_go_memstats_alloc_bytes Heap allocation (live) in bytes.")
	fmt.Fprintln(&body, "# TYPE triton_go_memstats_alloc_bytes gauge")
	fmt.Fprintf(&body, "triton_go_memstats_alloc_bytes %d\n", memStats.Alloc)

	fmt.Fprintln(&body, "# HELP triton_go_memstats_sys_bytes Total bytes obtained from the OS.")
	fmt.Fprintln(&body, "# TYPE triton_go_memstats_sys_bytes gauge")
	fmt.Fprintf(&body, "triton_go_memstats_sys_bytes %d\n", memStats.Sys)

	fmt.Fprintln(&body, "# HELP triton_go_memstats_gc_runs Total number of completed GC cycles.")
	fmt.Fprintln(&body, "# TYPE triton_go_memstats_gc_runs counter")
	fmt.Fprintf(&body, "triton_go_memstats_gc_runs %d\n", memStats.NumGC)

	// Single Write — ignore error intentionally; a broken pipe on
	// the scraper side is not actionable from the handler and
	// every other JSON handler in this package follows the same
	// pattern via writeJSON.
	_, _ = w.Write(body.Bytes())
}
