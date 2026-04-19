package hosts_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
)

// fakeHostCapGuard satisfies hosts.HostCapGuard with a fixed
// "<metric>/<window>" -> cap map. Values outside the map return -1
// (unlimited), matching the real guard's semantics.
type fakeHostCapGuard struct {
	caps map[string]int64
}

func (f *fakeHostCapGuard) LimitCap(metric, window string) int64 {
	if v, ok := f.caps[metric+"/"+window]; ok {
		return v
	}
	return -1
}

// newTestServerWithGuard mounts the hosts admin routes with the
// caller-supplied cap guard. Useful for driving the 403 branch without
// constructing a signed licence.
func newTestServerWithGuard(t *testing.T, s hosts.Store, guard hosts.HostCapGuard) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/hosts", func(r chi.Router) {
		hosts.MountAdminRoutes(r, hosts.NewAdminHandlers(s, guard))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

// TestHostsAdmin_Create_CapExceeded_Returns403 verifies that when the
// licence guard reports `hosts/total` cap=3 and 3 rows already exist,
// the 4th Create is rejected with 403 and no row is persisted.
func TestHostsAdmin_Create_CapExceeded_Returns403(t *testing.T) {
	store := newFakeStore()
	// Seed 3 rows so the next Create trips the cap.
	for _, name := range []string{"h1", "h2", "h3"} {
		_, err := store.Create(context.Background(), hosts.Host{Hostname: name})
		require.NoError(t, err)
	}
	ts := newTestServerWithGuard(t, store, &fakeHostCapGuard{
		caps: map[string]int64{"hosts/total": 3},
	})

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/",
		map[string]string{"hostname": "h4"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body["error"], "host cap")

	// Row count must not have grown past the cap.
	c, _ := store.Count(context.Background())
	assert.Equal(t, int64(3), c, "Create must not persist when cap tripped")
}

// TestHostsAdmin_BulkCreate_CapExceeded_Returns403_WithShortfall asserts
// the bulk variant surfaces how many rows the batch exceeds the cap by.
func TestHostsAdmin_BulkCreate_CapExceeded_Returns403_WithShortfall(t *testing.T) {
	store := newFakeStore()
	// Seed 2; cap is 3; batch of 5 = shortfall of 4.
	for _, name := range []string{"seed-1", "seed-2"} {
		_, err := store.Create(context.Background(), hosts.Host{Hostname: name})
		require.NoError(t, err)
	}
	ts := newTestServerWithGuard(t, store, &fakeHostCapGuard{
		caps: map[string]int64{"hosts/total": 3},
	})

	body := map[string]any{
		"hosts": []map[string]string{
			{"hostname": "b1"}, {"hostname": "b2"}, {"hostname": "b3"},
			{"hostname": "b4"}, {"hostname": "b5"},
		},
	}
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/bulk", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	var out map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, out["error"], "host cap")
	assert.Contains(t, out["error"], "requested 5",
		"shortfall-aware error should surface the batch size")

	// BulkCreate must not have been invoked at all when the pre-flight
	// cap check refuses the batch.
	assert.NotContains(t, store.calls, "BulkCreate")
}

// TestHostsAdmin_Create_NoGuard_Unrestricted confirms the nil-guard
// path is a pass-through: the cap check never fires, and Create proceeds
// regardless of current row count.
func TestHostsAdmin_Create_NoGuard_Unrestricted(t *testing.T) {
	store := newFakeStore()
	// Pre-seed 1000 rows — a hard cap would reject, a nil guard won't.
	for i := 0; i < 1000; i++ {
		_, _ = store.Create(context.Background(), hosts.Host{Hostname: hostname(i)})
	}
	ts := newTestServerWithGuard(t, store, nil)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/",
		map[string]string{"hostname": "unrestricted"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"nil guard must disable cap enforcement")
}

// TestHostsAdmin_Create_UnlimitedCap_Unrestricted confirms that a guard
// whose LimitCap returns -1 for hosts/total behaves like no guard.
func TestHostsAdmin_Create_UnlimitedCap_Unrestricted(t *testing.T) {
	store := newFakeStore()
	ts := newTestServerWithGuard(t, store, &fakeHostCapGuard{
		caps: map[string]int64{}, // no entry → LimitCap returns -1
	})

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/",
		map[string]string{"hostname": "open-cap"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// hostname returns a stable unique hostname per index — helper for
// pre-seeding loops that don't care about specific names.
func hostname(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	return "h-" + string(alphabet[i%len(alphabet)]) + string(alphabet[(i/26)%len(alphabet)]) + "-" +
		intToStr(i)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
