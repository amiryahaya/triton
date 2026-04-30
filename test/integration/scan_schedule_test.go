//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var schedSchemaSeq atomic.Int64

type schedFixture struct {
	store    *scanjobs.PostgresStore
	tenantID uuid.UUID
	srv      *httptest.Server
	cleanup  func()
}

func newSchedFixture(t *testing.T) *schedFixture {
	t.Helper()
	schema := fmt.Sprintf("test_schedule_%d", schedSchemaSeq.Add(1))
	ms, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	pool := ms.Pool()
	tenantID := uuid.New()

	hostsStore := hosts.NewPostgresStore(pool)
	store := scanjobs.NewPostgresStore(pool)

	hostsH := hosts.NewAdminHandlers(hostsStore, nil)
	schedH := scanjobs.NewScheduleHandlers(store)

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
			next.ServeHTTP(w, rq.WithContext(orgctx.WithInstanceID(rq.Context(), tenantID)))
		})
	})
	hosts.MountAdminRoutes(r, hostsH)
	r.Route("/scan-schedules", func(r chi.Router) {
		scanjobs.MountScheduleRoutes(r, schedH)
	})

	srv := httptest.NewServer(r)
	return &schedFixture{
		store:    store,
		tenantID: tenantID,
		srv:      srv,
		cleanup: func() {
			srv.Close()
			_ = ms.DropSchema(context.Background())
			_ = ms.Close()
		},
	}
}

func postSchedAPI(t *testing.T, baseURL string, body any) (int, scanjobs.Schedule) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/scan-schedules", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	var sched scanjobs.Schedule
	if resp.StatusCode == http.StatusCreated {
		_ = json.NewDecoder(resp.Body).Decode(&sched)
	}
	return resp.StatusCode, sched
}

func TestScheduleAPI_CreateAndList(t *testing.T) {
	f := newSchedFixture(t)
	defer f.cleanup()

	hostID := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "sched-01", IP: "10.5.0.1", ConnectionType: "ssh"})

	code, sched := postSchedAPI(t, f.srv.URL, map[string]any{
		"name":      "Daily midnight",
		"job_types": []string{"port_survey"},
		"host_ids":  []string{hostID.String()},
		"profile":   "quick",
		"cron_expr": "0 0 * * *",
	})
	require.Equal(t, http.StatusCreated, code)
	assert.NotEqual(t, uuid.Nil, sched.ID)
	assert.True(t, sched.NextRunAt.After(time.Now()))
	assert.True(t, sched.Enabled)

	listResp, err := http.Get(f.srv.URL + "/scan-schedules")
	require.NoError(t, err)
	defer listResp.Body.Close()
	var list []scanjobs.Schedule
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&list))
	assert.Len(t, list, 1)
	assert.Equal(t, sched.ID, list[0].ID)
}

func TestScheduleAPI_InvalidCron_Returns400(t *testing.T) {
	f := newSchedFixture(t)
	defer f.cleanup()

	hostID := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "sched-bad", IP: "10.6.0.1", ConnectionType: "ssh"})
	code, _ := postSchedAPI(t, f.srv.URL, map[string]any{
		"name": "Bad", "job_types": []string{"port_survey"},
		"host_ids": []string{hostID.String()}, "profile": "quick",
		"cron_expr": "not-valid",
	})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestScheduleAPI_PatchDisable(t *testing.T) {
	f := newSchedFixture(t)
	defer f.cleanup()

	hostID := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "sched-patch", IP: "10.7.0.1", ConnectionType: "ssh"})
	_, sched := postSchedAPI(t, f.srv.URL, map[string]any{
		"name": "Patch me", "job_types": []string{"port_survey"},
		"host_ids": []string{hostID.String()}, "profile": "quick",
		"cron_expr": "0 * * * *",
	})

	disabled := false
	body, _ := json.Marshal(map[string]any{"enabled": disabled})
	req, _ := http.NewRequest(http.MethodPatch, f.srv.URL+"/scan-schedules/"+sched.ID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var patched scanjobs.Schedule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&patched))
	assert.False(t, patched.Enabled)
}

func TestScheduleAPI_Delete_RemovesSchedule(t *testing.T) {
	f := newSchedFixture(t)
	defer f.cleanup()

	hostID := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "sched-del", IP: "10.8.0.1", ConnectionType: "ssh"})
	_, sched := postSchedAPI(t, f.srv.URL, map[string]any{
		"name": "Delete me", "job_types": []string{"port_survey"},
		"host_ids": []string{hostID.String()}, "profile": "quick",
		"cron_expr": "0 * * * *",
	})

	req, _ := http.NewRequest(http.MethodDelete, f.srv.URL+"/scan-schedules/"+sched.ID.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	listResp, err := http.Get(f.srv.URL + "/scan-schedules")
	require.NoError(t, err)
	defer listResp.Body.Close()
	var list []scanjobs.Schedule
	_ = json.NewDecoder(listResp.Body).Decode(&list)
	assert.Empty(t, list)
}
