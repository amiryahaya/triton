package scanjobs_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

// TestScanJobsAdmin_Enqueue_OversizeBodyRejected asserts defence-in-
// depth body capping on the Enqueue handler: a 2 MiB JSON payload is
// rejected by MaxBytesReader before json.Decode reads it, so the
// handler returns 400 instead of a 500 or memory spike.
func TestScanJobsAdmin_Enqueue_OversizeBodyRejected(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	ts := newTestServer(t, store, tenantID)

	// target_filter is a free-form string — convenient field to pad.
	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"zones":["`+uuid.Must(uuid.NewV7()).String()+`"],"profile":"quick","target_filter":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/scan-jobs/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"oversize body on Enqueue must be rejected with 400")
}
