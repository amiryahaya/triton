//go:build integration

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

	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// setupScheduleServer creates a test server with the ScheduleHandlers mounted.
// tenantID is a fixed UUID injected via orgctx middleware.
func setupScheduleServer(t *testing.T) (baseURL string, store *scanjobs.PostgresStore, tenantID uuid.UUID) {
	t.Helper()
	pool := newTestPool(t)
	store = scanjobs.NewPostgresStore(pool)
	h := scanjobs.NewScheduleHandlers(store)
	tenantID = uuid.New()

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
			next.ServeHTTP(w, rq.WithContext(orgctx.WithInstanceID(rq.Context(), tenantID)))
		})
	})
	r.Post("/", h.CreateSchedule)
	r.Get("/", h.ListSchedules)
	r.Patch("/{id}", h.PatchSchedule)
	r.Delete("/{id}", h.DeleteSchedule)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv.URL, store, tenantID
}

func TestScheduleHandler_Create_ValidCron(t *testing.T) {
	url, _, _ := setupScheduleServer(t)
	body, _ := json.Marshal(map[string]any{
		"name":      "Weekly Monday",
		"job_types": []string{"port_survey"},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "quick",
		"cron_expr": "0 2 * * 1",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var sched scanjobs.Schedule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sched))
	assert.NotEqual(t, uuid.Nil, sched.ID)
	assert.Equal(t, "0 2 * * 1", sched.CronExpr)
	assert.True(t, sched.Enabled)
}

func TestScheduleHandler_Create_InvalidCron_Returns400(t *testing.T) {
	url, _, _ := setupScheduleServer(t)
	for _, bad := range []string{"not-a-cron", "60 * * * *", ""} {
		body, _ := json.Marshal(map[string]any{
			"name":      "bad",
			"job_types": []string{"port_survey"},
			"host_ids":  []string{uuid.New().String()},
			"profile":   "quick",
			"cron_expr": bad,
		})
		resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "cron %q must return 400", bad)
	}
}

func TestScheduleHandler_List_TenantScoped(t *testing.T) {
	url, _, _ := setupScheduleServer(t)
	url2, _, _ := setupScheduleServer(t) // different tenantID

	// Create one schedule in each tenant.
	body, _ := json.Marshal(map[string]any{
		"name": "Listed", "job_types": []string{"port_survey"},
		"host_ids": []string{uuid.New().String()}, "profile": "quick",
		"cron_expr": "0 * * * *",
	})
	resp1, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusCreated, resp1.StatusCode)

	resp2, err := http.Post(url2+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusCreated, resp2.StatusCode)

	// Listing from tenant 1 should see only its own schedule.
	listResp, err := http.Get(url + "/")
	require.NoError(t, err)
	defer listResp.Body.Close()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)
	var list []scanjobs.Schedule
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&list))
	assert.Len(t, list, 1, "tenant 1 must see only its own schedule")
}

func TestScheduleHandler_Create_InvalidProfile_Returns400(t *testing.T) {
	url, _, _ := setupScheduleServer(t)
	body, _ := json.Marshal(map[string]any{
		"name": "bad-profile", "job_types": []string{"port_survey"},
		"host_ids": []string{uuid.New().String()}, "profile": "ultra",
		"cron_expr": "0 * * * *",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScheduleHandler_Patch_Toggle(t *testing.T) {
	url, store, tenantID := setupScheduleServer(t)
	sched, _ := store.CreateSchedule(context.Background(), makeScheduleReq(tenantID, "0 * * * *"))

	disabled := false
	body, _ := json.Marshal(map[string]any{"enabled": disabled})
	req, _ := http.NewRequest(http.MethodPatch, url+"/"+sched.ID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var patched scanjobs.Schedule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&patched))
	assert.False(t, patched.Enabled)
}

func TestScheduleHandler_Delete(t *testing.T) {
	url, store, tenantID := setupScheduleServer(t)
	sched, _ := store.CreateSchedule(context.Background(), makeScheduleReq(tenantID, "0 * * * *"))

	req, _ := http.NewRequest(http.MethodDelete, url+"/"+sched.ID.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestScheduleHandler_Patch_NotFound(t *testing.T) {
	url, _, _ := setupScheduleServer(t)
	body, _ := json.Marshal(map[string]any{"enabled": false})
	req, _ := http.NewRequest(http.MethodPatch, url+"/"+uuid.New().String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
