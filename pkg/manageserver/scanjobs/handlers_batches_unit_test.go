package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// saturatedStore is a minimal BatchStore stub that simulates a queue at capacity.
type saturatedStore struct {
	pendingCount int64
}

func (s *saturatedStore) EnqueueBatch(_ context.Context, _ scanjobs.BatchEnqueueReq, _ []scanjobs.JobSpec, _ []scanjobs.SkippedJob) (scanjobs.BatchEnqueueResp, error) {
	return scanjobs.BatchEnqueueResp{}, nil
}
func (s *saturatedStore) GetBatch(_ context.Context, _ uuid.UUID) (scanjobs.Batch, error) {
	return scanjobs.Batch{}, nil
}
func (s *saturatedStore) ListBatches(_ context.Context, _ uuid.UUID, _ int) ([]scanjobs.Batch, error) {
	return nil, nil
}
func (s *saturatedStore) CountPendingJobs(_ context.Context) (int64, error) {
	return s.pendingCount, nil
}

// emptyHostsGetter returns an empty slice for any host ID list.
type emptyHostsGetter struct{}

func (e *emptyHostsGetter) GetByIDs(_ context.Context, _ []uuid.UUID) ([]hosts.Host, error) {
	return nil, nil
}

func newSaturatedHandlerServer(t *testing.T, pendingCount int64) string {
	t.Helper()
	tenantID := uuid.New()
	h := scanjobs.NewBatchHandlers(&saturatedStore{pendingCount: pendingCount}, &emptyHostsGetter{})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
			next.ServeHTTP(w, rq.WithContext(orgctx.WithInstanceID(rq.Context(), tenantID)))
		})
	})
	r.Post("/", h.EnqueueBatch)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestBatchHandler_QueueSaturated_Returns503(t *testing.T) {
	url := newSaturatedHandlerServer(t, 10_000)

	body, _ := json.Marshal(map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "standard",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestBatchHandler_QueueBelowCap_Proceeds(t *testing.T) {
	// 9999 pending — below the 10,000 cap — should not return 503.
	// emptyHostsGetter returns no hosts so jobs_created will be 0,
	// but the 503 guard must not trigger.
	url := newSaturatedHandlerServer(t, 9_999)

	body, _ := json.Marshal(map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "standard",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	// Not 503 — the saturation guard did not fire.
	assert.NotEqual(t, http.StatusServiceUnavailable, resp.StatusCode)
}
