package scanjobs_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// fakeScanCapGuard satisfies scanjobs.ScanCapGuard with injected values
// for cap + used + ceiling on the scans/monthly metric. Other metrics
// return -1 (unlimited) / 0 (no usage), matching the real guard's
// semantics.
type fakeScanCapGuard struct {
	cap     int64
	used    int64
	ceiling int64
}

func (f *fakeScanCapGuard) LimitCap(metric, window string) int64 {
	if metric == "scans" && window == "monthly" {
		return f.cap
	}
	return -1
}

func (f *fakeScanCapGuard) CurrentUsage(metric, window string) int64 {
	if metric == "scans" && window == "monthly" {
		return f.used
	}
	return 0
}

func (f *fakeScanCapGuard) SoftBufferCeiling(metric, window string) int64 {
	if metric == "scans" && window == "monthly" {
		return f.ceiling
	}
	return -1
}

// TestScanJobsAdmin_Create_CapExceeded_SoftBuffer_Returns403 asserts
// that when used + expected exceeds the soft-buffer ceiling, Enqueue
// is rejected with 403 and no jobs are written.
//
// Setup: cap=100, used=95, ceiling=110 (10% soft buffer).
// Batch size = 20 zones → 20 expected jobs (fake store PlanEnqueueCount
// returns len(zones)) → 95 + 20 = 115 > 110 ⇒ reject.
func TestScanJobsAdmin_Create_CapExceeded_SoftBuffer_Returns403(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	guard := &fakeScanCapGuard{cap: 100, used: 95, ceiling: 110}
	ts := newTestServerWithGuard(t, store, tenantID, guard)

	zones := make([]string, 20)
	for i := range zones {
		zones[i] = uuid.Must(uuid.NewV7()).String()
	}
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   zones,
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	b, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(b), "scan cap")
	assert.Contains(t, string(b), "soft-buffered")

	// Enqueue must not have been invoked.
	assert.NotContains(t, store.calls, "Enqueue")
}

// TestScanJobsAdmin_Create_WithinBuffer_Succeeds verifies the green
// path: cap+headroom accommodates the batch.
//
// Setup: cap=100, used=50, ceiling=110. Batch = 1 → 50+1=51 < 110 ⇒ pass.
func TestScanJobsAdmin_Create_WithinBuffer_Succeeds(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	guard := &fakeScanCapGuard{cap: 100, used: 50, ceiling: 110}
	ts := newTestServerWithGuard(t, store, tenantID, guard)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var out struct {
		Jobs []scanjobs.Job `json:"jobs"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Len(t, out.Jobs, 1)
}

// TestScanJobsAdmin_Create_NoGuard_Unrestricted confirms the nil-guard
// path: cap check never fires; Enqueue proceeds regardless.
func TestScanJobsAdmin_Create_NoGuard_Unrestricted(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	ts := newTestServerWithGuard(t, store, tenantID, nil)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestScanJobsAdmin_Create_UnlimitedCap_Unrestricted confirms that a
// guard whose LimitCap returns -1 for scans/monthly behaves like no
// guard — CurrentUsage + SoftBufferCeiling are never consulted.
func TestScanJobsAdmin_Create_UnlimitedCap_Unrestricted(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	guard := &fakeScanCapGuard{cap: -1, used: 9999, ceiling: -1}
	ts := newTestServerWithGuard(t, store, tenantID, guard)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestScanJobsAdmin_Create_CapCheckRunsAfterBackpressure asserts the
// ordering: saturation check happens before cap check. A saturated
// queue short-circuits with 503 even when the licence cap would also
// fire, because backpressure is about operator visibility into the
// upstream and licence caps are about billing.
func TestScanJobsAdmin_Create_CapCheckRunsAfterBackpressure(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())

	// Wire both: saturated queue + tripping guard. Mount inline so the
	// test owns both deps unambiguously.
	saturated := &fakeQueueDepther{Depth: 10_000}
	guard := &fakeScanCapGuard{cap: 1, used: 1000, ceiling: 1}

	injectTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(orgctx.WithInstanceID(r.Context(), tenantID)))
		})
	}
	r := chi.NewRouter()
	var scanProvider func() scanjobs.ScanCapGuard
	if guard != nil {
		scanProvider = func() scanjobs.ScanCapGuard { return guard }
	}
	r.Route("/api/v1/admin/scan-jobs", func(r chi.Router) {
		r.Use(injectTenant)
		scanjobs.MountAdminRoutes(r, scanjobs.NewAdminHandlers(store, saturated, scanProvider))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"backpressure must win over cap-exceeded")
}
