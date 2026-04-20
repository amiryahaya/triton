package scanresults_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/model"
)

// fakeStatusStore is the narrowest scanresults.Store that satisfies
// AdminHandlers.Status — only LoadLicenseState matters; the other
// methods no-op with sensible defaults so we can satisfy the Store
// interface contract without touching a database.
type fakeStatusStore struct {
	status    scanresults.Status
	statusErr error
}

func (f *fakeStatusStore) Enqueue(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ *model.ScanResult) error {
	return nil
}
func (f *fakeStatusStore) ClaimDue(_ context.Context, _ int) ([]scanresults.QueueRow, error) {
	return nil, nil
}
func (f *fakeStatusStore) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeStatusStore) Defer(_ context.Context, _ uuid.UUID, _ time.Time, _ string) error {
	return nil
}
func (f *fakeStatusStore) DeadLetter(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (f *fakeStatusStore) QueueDepth(_ context.Context) (int64, error)               { return 0, nil }
func (f *fakeStatusStore) OldestAge(_ context.Context) (time.Duration, error)        { return 0, nil }
func (f *fakeStatusStore) LoadPushCreds(_ context.Context) (scanresults.PushCreds, error) {
	return scanresults.PushCreds{}, nil
}
func (f *fakeStatusStore) SavePushCreds(_ context.Context, _ scanresults.PushCreds) error {
	return nil
}
func (f *fakeStatusStore) RecordPushSuccess(_ context.Context, _ []byte) error { return nil }
func (f *fakeStatusStore) RecordPushFailure(_ context.Context, _ string) error { return nil }
func (f *fakeStatusStore) LoadLicenseState(_ context.Context) (scanresults.Status, error) {
	return f.status, f.statusErr
}

func newStatusTestServer(t *testing.T, s scanresults.Store) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/push-status", func(r chi.Router) {
		scanresults.MountAdminRoutes(r, scanresults.NewAdminHandlers(s))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func TestPushStatus_Status_Success(t *testing.T) {
	now := time.Date(2026, 4, 19, 14, 22, 0, 0, time.UTC)
	store := &fakeStatusStore{
		status: scanresults.Status{
			QueueDepth:          42,
			OldestRowAgeSeconds: 123,
			LastPushError:       "",
			ConsecutiveFailures: 0,
			LastPushedAt:        &now,
		},
	}
	ts := newStatusTestServer(t, store)

	resp, err := http.Get(ts.URL + "/api/v1/admin/push-status/")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body scanresults.Status
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, int64(42), body.QueueDepth)
	assert.Equal(t, int64(123), body.OldestRowAgeSeconds)
	assert.Equal(t, 0, body.ConsecutiveFailures)
	require.NotNil(t, body.LastPushedAt)
	assert.True(t, body.LastPushedAt.Equal(now))
}

func TestPushStatus_Status_NullLastPushedAt(t *testing.T) {
	store := &fakeStatusStore{
		status: scanresults.Status{
			QueueDepth:          0,
			OldestRowAgeSeconds: 0,
			ConsecutiveFailures: 0,
			LastPushedAt:        nil, // omitempty
		},
	}
	ts := newStatusTestServer(t, store)

	resp, err := http.Get(ts.URL + "/api/v1/admin/push-status/")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var raw map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))
	_, ok := raw["last_pushed_at"]
	assert.False(t, ok, "null last_pushed_at must be omitted by omitempty")
}

func TestPushStatus_Status_FailureCounters(t *testing.T) {
	store := &fakeStatusStore{
		status: scanresults.Status{
			QueueDepth:          12,
			OldestRowAgeSeconds: 300,
			LastPushError:       "HTTP 500",
			ConsecutiveFailures: 3,
		},
	}
	ts := newStatusTestServer(t, store)

	resp, err := http.Get(ts.URL + "/api/v1/admin/push-status/")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body scanresults.Status
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 3, body.ConsecutiveFailures)
	assert.Equal(t, "HTTP 500", body.LastPushError)
}

func TestPushStatus_Status_StoreError_Returns500(t *testing.T) {
	store := &fakeStatusStore{statusErr: errors.New("boom: pg table manage_license_state")}
	ts := newStatusTestServer(t, store)

	resp, err := http.Get(ts.URL + "/api/v1/admin/push-status/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
