//go:build integration

package agents_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

// TestAgentsAdmin_Enrol_OversizeBodyRejected asserts defence-in-depth
// body capping on the Enrol handler: a 2 MiB JSON payload is rejected
// by MaxBytesReader before json.Decode, so the handler returns 400
// rather than minting a cert against arbitrary user input or wedging
// its decoder.
func TestAgentsAdmin_Enrol_OversizeBodyRejected(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-oversize-test")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	// name is a bounded string field so pad it to trip the cap.
	padding := bytes.Repeat([]byte("a"), int(limits.MaxRequestBody)+int(limits.MaxRequestBody))
	body := append([]byte(`{"name":"`), padding...)
	body = append(body, []byte(`"}`)...)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/enrol/agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"oversize body on Enrol must be rejected with 400")
}
