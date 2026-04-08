package licenseserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReportServer returns an httptest server that records the last
// provisioning request received and emits the given response.
func fakeReportServer(t *testing.T, status int, responseBody map[string]any, wantKey string) (*httptest.Server, *ProvisionOrgRequest) {
	t.Helper()
	var received ProvisionOrgRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/v1/admin/orgs" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if wantKey != "" && r.Header.Get("X-Triton-Service-Key") != wantKey {
			http.Error(w, "wrong key", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(responseBody)
	}))
	t.Cleanup(func() { ts.Close() })
	return ts, &received
}

// --- Construction ---

func TestNewReportAPIClient_EmptyFieldsReturnsNil(t *testing.T) {
	assert.Nil(t, NewReportAPIClient("", "key"))
	assert.Nil(t, NewReportAPIClient("http://report", ""))
	assert.Nil(t, NewReportAPIClient("", ""))
	assert.NotNil(t, NewReportAPIClient("http://report", "key"))
}

// --- ProvisionOrg ---

func TestReportAPIClient_ProvisionOrg_Success(t *testing.T) {
	ts, received := fakeReportServer(t, http.StatusCreated, map[string]any{
		"org":           map[string]any{"id": "org-123", "name": "Acme"},
		"admin_user_id": "user-456",
	}, "shared-secret")
	client := NewReportAPIClient(ts.URL, "shared-secret")

	resp, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID:                "org-123",
		Name:              "Acme",
		AdminEmail:        "alice@acme.com",
		AdminName:         "Alice Admin",
		AdminTempPassword: "correct-horse-battery-staple",
	})
	require.NoError(t, err)
	assert.Equal(t, "org-123", resp.Org.ID)
	assert.Equal(t, "Acme", resp.Org.Name)
	assert.Equal(t, "user-456", resp.AdminUserID)
	assert.False(t, resp.AlreadyExists, "201 means newly created, not idempotent retry")

	// Verify the request body the fake received.
	assert.Equal(t, "org-123", received.ID)
	assert.Equal(t, "alice@acme.com", received.AdminEmail)
	assert.Equal(t, "correct-horse-battery-staple", received.AdminTempPassword)
}

func TestReportAPIClient_ProvisionOrg_IdempotentRetry(t *testing.T) {
	// Fake returns 200 (already exists) instead of 201.
	ts, _ := fakeReportServer(t, http.StatusOK, map[string]any{
		"org":            map[string]any{"id": "org-123", "name": "Acme"},
		"already_exists": true,
	}, "shared-secret")
	client := NewReportAPIClient(ts.URL, "shared-secret")

	resp, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "org-123", Name: "Acme",
		AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery-staple",
	})
	require.NoError(t, err)
	assert.True(t, resp.AlreadyExists, "200 response must mark result as idempotent retry")
}

func TestReportAPIClient_ProvisionOrg_SendsServiceKey(t *testing.T) {
	// If the fake rejects because of a missing/wrong key, the test fails
	// with "provision failed: status 403" — proving the header is checked
	// and the client is sending the right value.
	ts, _ := fakeReportServer(t, http.StatusCreated, map[string]any{
		"org": map[string]any{"id": "x", "name": "y"}, "admin_user_id": "u",
	}, "strict-key")
	client := NewReportAPIClient(ts.URL, "strict-key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.NoError(t, err)
}

func TestReportAPIClient_ProvisionOrg_WrongKey(t *testing.T) {
	ts, _ := fakeReportServer(t, http.StatusCreated, map[string]any{}, "expected-key")
	client := NewReportAPIClient(ts.URL, "wrong-key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestReportAPIClient_ProvisionOrg_ServerUnreachable(t *testing.T) {
	// Point at a closed port — connection will be refused.
	client := NewReportAPIClient("http://127.0.0.1:1", "any-key")
	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	// Network error must wrap ErrReportServerUnreachable so callers can
	// distinguish it from a 4xx/5xx response (D4 fix).
	assert.ErrorIs(t, err, ErrReportServerUnreachable)
}

// TestReportAPIClient_ProvisionOrg_PropagatesRequestID verifies that the
// X-Request-ID from the incoming context is forwarded to the report
// server so distributed tracing works across the cross-server hop.
// (Arch #10 from the Phase 1.7/1.8 review.)
func TestReportAPIClient_ProvisionOrg_PropagatesRequestID(t *testing.T) {
	var receivedReqID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedReqID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org": map[string]any{"id": "x", "name": "y"}, "admin_user_id": "u",
		})
	}))
	defer ts.Close()
	client := NewReportAPIClient(ts.URL, "key")

	// Stuff a request ID into the context using the same chi middleware
	// key the server side uses. We can't easily import the unexported
	// key, so use chi's exported helper pattern: set via a fake request
	// that middleware.RequestID would populate.
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "test-req-id-42")

	_, err := client.ProvisionOrg(ctx, ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-req-id-42", receivedReqID, "X-Request-ID must propagate across the cross-server hop")
}

func TestReportAPIClient_ProvisionOrg_BadJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer ts.Close()
	client := NewReportAPIClient(ts.URL, "key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing provision response")
}

// GenerateTempPassword tests moved to internal/auth/password_test.go
// as part of the Phase 5 Sprint 2 convergence — the canonical
// implementation lives in internal/auth.
