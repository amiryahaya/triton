package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandPoller_Empty204(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/agent/commands/poll", r.URL.Path)
		assert.Equal(t, "token-x", r.Header.Get("X-Triton-License-Token"))
		assert.Equal(t, "midval", r.Header.Get("X-Triton-Machine-ID"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "token-x", MachineID: "midval"}
	resp, err := c.Poll(t.Context())
	require.NoError(t, err)
	assert.Nil(t, resp, "empty 204 should yield nil response")
}

func TestCommandPoller_Commands(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state": map[string]any{"pausedUntil": "2026-05-01T00:00:00Z"},
			"commands": []map[string]any{
				{
					"id": "cmd-1", "type": "cancel", "args": map[string]any{},
					"issuedAt":  "2026-04-19T00:00:00Z",
					"expiresAt": "2026-04-19T01:00:00Z",
				},
			},
		})
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	resp, err := c.Poll(t.Context())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), resp.State.PausedUntil)
	require.Len(t, resp.Commands, 1)
	assert.Equal(t, "cancel", resp.Commands[0].Type)
	assert.Equal(t, "cmd-1", resp.Commands[0].ID)
}

func TestCommandPoller_Non2xxReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", http.StatusBadGateway)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	_, err := c.Poll(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestCommandPoller_PostResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/agent/commands/cmd-1/result", r.URL.Path)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "executed", body["status"])
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	err := c.PostResult(t.Context(), "cmd-1", "executed", json.RawMessage(`{"findings":3}`))
	require.NoError(t, err)
}

func TestCommandPoller_PostResultRejectsNonOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()

	c := &CommandPoller{BaseURL: ts.URL, LicenseToken: "t", MachineID: "m"}
	err := c.PostResult(t.Context(), "cmd-1", "executed", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}
