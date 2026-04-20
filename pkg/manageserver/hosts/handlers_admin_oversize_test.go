package hosts_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

// TestHostsAdmin_Create_OversizeBodyRejected asserts defence-in-depth
// body-size capping: a 2 MiB JSON payload is rejected by the handler's
// MaxBytesReader wrapper before json.Decode ever sees the stream, so
// the response is a clean 400 rather than OOM risk or a 500.
func TestHostsAdmin_Create_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"hostname":"h1","os":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/hosts/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"oversize body on Create must be rejected with 400")
}

// TestHostsAdmin_Update_OversizeBodyRejected — same coverage for the
// Update handler, the second body-decoding entrypoint.
func TestHostsAdmin_Update_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Seed a host to PATCH against.
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/",
		map[string]string{"hostname": "seed"})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	id := created["id"].(string)

	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"hostname":"seed","os":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req, err := http.NewRequest(http.MethodPatch,
		ts.URL+"/api/v1/admin/hosts/"+id, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode,
		"oversize body on Update must be rejected with 400")
}

// TestHostsAdmin_BulkCreate_OversizeBodyRejected is the bulk variant:
// bulk imports are the most likely legitimate source of large bodies
// so the cap has the biggest operational impact here.
func TestHostsAdmin_BulkCreate_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Build a 2 MiB hosts array. Each host row is tiny; the padding
	// goes into the last row's `os` field so the shape is otherwise
	// legal.
	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"hosts":[{"hostname":"h1","os":"`), padding...)
	body = append(body, []byte(`"}]}`)...)

	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/hosts/bulk", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"oversize body on BulkCreate must be rejected with 400")
}
