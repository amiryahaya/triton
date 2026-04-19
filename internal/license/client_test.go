package license

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerClient_Health(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	err := client.Health()
	require.NoError(t, err)
}

func TestServerClient_Health_Unreachable(t *testing.T) {
	client := NewServerClient("http://127.0.0.1:1") // unreachable
	err := client.Health()
	require.Error(t, err)
}

func TestServerClient_Activate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.NotEmpty(t, req["machineID"])
		assert.Equal(t, "lic-123", req["licenseID"])

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "test-token",
			"activationID": "act-1",
			"tier":         "pro",
			"seats":        5,
			"seatsUsed":    1,
			"expiresAt":    "2027-01-01T00:00:00Z",
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Activate("lic-123")
	require.NoError(t, err)
	assert.Equal(t, "test-token", resp.Token)
	assert.Equal(t, "pro", resp.Tier)
	assert.Equal(t, 5, resp.Seats)
	assert.Equal(t, 1, resp.SeatsUsed)
}

func TestServerClient_Activate_SeatsFull(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "seats full"})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	_, err := client.Activate("lic-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "seats")
}

func TestServerClient_Deactivate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deactivated"})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	err := client.Deactivate("lic-123")
	require.NoError(t, err)
}

func TestServerClient_Validate_Valid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "tier": "pro",
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Validate("lic-123", "token")
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "pro", resp.Tier)
}

func TestServerClient_Validate_ParsesOrgInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid":   true,
			"tier":    "pro",
			"orgID":   "01234567-89ab-cdef-0123-456789abcdef",
			"orgName": "Acme Corp",
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Validate("lic-123", "token")
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "01234567-89ab-cdef-0123-456789abcdef", resp.OrgID)
	assert.Equal(t, "Acme Corp", resp.OrgName)
}

// TestServerClient_Validate_ParsesCacheTTL verifies that the client struct
// surfaces the cacheTTL field from the validate response so the report
// server's Phase 2.1 cache can honor the server-owned trust window.
func TestServerClient_Validate_ParsesCacheTTL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid":    true,
			"tier":     "pro",
			"cacheTTL": 300,
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Validate("lic-123", "token")
	require.NoError(t, err)
	assert.Equal(t, 300, resp.CacheTTL)
}

func TestServerClient_Validate_Invalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": false, "reason": "license revoked",
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Validate("lic-123", "token")
	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.Equal(t, "license revoked", resp.Reason)
}

func TestServerClient_Activate_Forbidden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "license revoked"})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	_, err := client.Activate("lic-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestServerClient_Activate_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	_, err := client.Activate("lic-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestServerClient_Activate_ParsesV2Fields verifies the additive v2 response
// fields (features, limits, soft_buffer_pct, product_scope) round-trip off
// the wire into the ActivateResponse struct so callers (e.g. Manage Server)
// can enforce feature/product scope client-side after activation.
func TestServerClient_Activate_ParsesV2Fields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"token":        "signed-token",
			"activationID": "act-v2",
			"tier":         "pro",
			"seats":        10,
			"seatsUsed":    1,
			"expiresAt":    "2027-01-01T00:00:00Z",
			"features": {
				"report":  true,
				"manage":  true,
				"diff_trend": true,
				"export_formats": ["html", "pdf"]
			},
			"limits": [
				{"metric": "hosts",  "window": "total", "cap": 50},
				{"metric": "tenants","window": "total", "cap": 5}
			],
			"soft_buffer_pct": 15,
			"product_scope":   "bundle"
		}`))
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Activate("lic-v2")
	require.NoError(t, err)

	// v1 fields still work.
	assert.Equal(t, "signed-token", resp.Token)
	assert.Equal(t, "pro", resp.Tier)

	// v2 fields populated.
	assert.True(t, resp.Features.Report)
	assert.True(t, resp.Features.Manage)
	assert.True(t, resp.Features.DiffTrend)
	assert.Equal(t, []string{"html", "pdf"}, resp.Features.ExportFormats)
	require.Len(t, resp.Limits, 2)
	assert.Equal(t, "hosts", resp.Limits[0].Metric)
	assert.Equal(t, int64(50), resp.Limits[0].Cap)
	assert.Equal(t, 15, resp.SoftBufferPct)
	assert.Equal(t, "bundle", resp.ProductScope)
}

// TestServerClient_Activate_V1ResponseStillWorks verifies back-compat: a v1
// licence server (no v2 fields) round-trips to a zero-value Features / Limits
// and empty scalars.
func TestServerClient_Activate_V1ResponseStillWorks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "tok",
			"activationID": "act-v1",
			"tier":         "free",
			"seats":        1,
			"seatsUsed":    0,
			"expiresAt":    "2099-01-01T00:00:00Z",
		})
	}))
	defer ts.Close()

	client := NewServerClient(ts.URL)
	resp, err := client.Activate("lic-v1")
	require.NoError(t, err)

	assert.Equal(t, "free", resp.Tier)
	assert.False(t, resp.Features.Manage)
	assert.Empty(t, resp.Limits)
	assert.Equal(t, 0, resp.SoftBufferPct)
	assert.Empty(t, resp.ProductScope)
}
