package zones_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

// TestZonesAdmin_Create_OversizeBodyRejected asserts that a request
// body larger than limits.MaxRequestBody is rejected at the decoder
// surface as a 400 (not a 500, and not silently accepted). Defence-in-
// depth — admin endpoints are JWT-gated but a hostile authenticated
// client should not be able to wedge the decoder with a gigabyte
// payload.
//
// The handler wraps r.Body in http.MaxBytesReader before json.Decode;
// the decoder surfaces the excess as an error, and the handler
// translates that into a 400 "invalid JSON body" response.
func TestZonesAdmin_Create_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Build a JSON object whose description field is well beyond the
	// 1 MiB cap. 2 MiB of padding is enough to deterministically
	// trip MaxBytesReader without being too slow.
	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"name":"big","description":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/zones/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"oversize body must be rejected with 400, not 500 or 200")
}

// TestZonesAdmin_Update_OversizeBodyRejected mirrors the Create test
// for the Update handler — the second entrypoint that decodes a JSON
// body. Both must guard against body-size DoS.
func TestZonesAdmin_Update_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Seed a zone so we have a valid :id to PATCH against.
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/zones/",
		map[string]string{"name": "seed"})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	id := created["id"].(string)

	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"name":"seed","description":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req, err := http.NewRequest(http.MethodPatch,
		ts.URL+"/api/v1/admin/zones/"+id, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode,
		"oversize body on Update must be rejected with 400")
}
