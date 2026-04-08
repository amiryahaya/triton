package licenseserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestNewReportClient_EmptyFieldsReturnsNil(t *testing.T) {
	assert.Nil(t, NewReportClient("", "key"))
	assert.Nil(t, NewReportClient("http://report", ""))
	assert.Nil(t, NewReportClient("", ""))
	assert.NotNil(t, NewReportClient("http://report", "key"))
}

// --- ProvisionOrg ---

func TestReportClient_ProvisionOrg_Success(t *testing.T) {
	ts, received := fakeReportServer(t, http.StatusCreated, map[string]any{
		"org":           map[string]any{"id": "org-123", "name": "Acme"},
		"admin_user_id": "user-456",
	}, "shared-secret")
	client := NewReportClient(ts.URL, "shared-secret")

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

func TestReportClient_ProvisionOrg_IdempotentRetry(t *testing.T) {
	// Fake returns 200 (already exists) instead of 201.
	ts, _ := fakeReportServer(t, http.StatusOK, map[string]any{
		"org":            map[string]any{"id": "org-123", "name": "Acme"},
		"already_exists": true,
	}, "shared-secret")
	client := NewReportClient(ts.URL, "shared-secret")

	resp, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "org-123", Name: "Acme",
		AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery-staple",
	})
	require.NoError(t, err)
	assert.True(t, resp.AlreadyExists, "200 response must mark result as idempotent retry")
}

func TestReportClient_ProvisionOrg_SendsServiceKey(t *testing.T) {
	// If the fake rejects because of a missing/wrong key, the test fails
	// with "provision failed: status 403" — proving the header is checked
	// and the client is sending the right value.
	ts, _ := fakeReportServer(t, http.StatusCreated, map[string]any{
		"org": map[string]any{"id": "x", "name": "y"}, "admin_user_id": "u",
	}, "strict-key")
	client := NewReportClient(ts.URL, "strict-key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.NoError(t, err)
}

func TestReportClient_ProvisionOrg_WrongKey(t *testing.T) {
	ts, _ := fakeReportServer(t, http.StatusCreated, map[string]any{}, "expected-key")
	client := NewReportClient(ts.URL, "wrong-key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestReportClient_ProvisionOrg_ServerUnreachable(t *testing.T) {
	// Point at a closed port — connection will be refused.
	client := NewReportClient("http://127.0.0.1:1", "any-key")
	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	// Network error must wrap ErrReportServerUnreachable so callers can
	// distinguish it from a 4xx/5xx response (D4 fix).
	assert.ErrorIs(t, err, ErrReportServerUnreachable)
}

func TestReportClient_ProvisionOrg_BadJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer ts.Close()
	client := NewReportClient(ts.URL, "key")

	_, err := client.ProvisionOrg(context.Background(), ProvisionOrgRequest{
		ID: "x", Name: "y", AdminEmail: "a@b.c", AdminName: "A", AdminTempPassword: "correct-horse-battery",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing provision response")
}

// --- GenerateTempPassword ---

func TestGenerateTempPassword_Uniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := GenerateTempPassword()
		require.NoError(t, err)
		assert.False(t, seen[p], "generated passwords must be unique")
		seen[p] = true
	}
}

func TestGenerateTempPassword_MeetsMinLength(t *testing.T) {
	// Must be at least 12 chars (the report server's minimum).
	for i := 0; i < 10; i++ {
		p, err := GenerateTempPassword()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(p), 12)
	}
}

func TestGenerateTempPassword_URLSafe(t *testing.T) {
	// Base64url chars only: A-Z a-z 0-9 - _
	p, err := GenerateTempPassword()
	require.NoError(t, err)
	assert.False(t, strings.ContainsAny(p, "+/="), "temp password must be base64url (no +, /, =)")
}
