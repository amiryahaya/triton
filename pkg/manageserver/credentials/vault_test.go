package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mockVaultServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"auth": map[string]any{
					"client_token":   "s.test-token",
					"lease_duration": 3600,
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}}) //nolint:errcheck
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"data": map[string]any{
					"data": map[string]any{
						"username": "ubuntu",
						"password": "secret",
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestVaultClient_TokenAuth_WriteReadDelete(t *testing.T) {
	srv, calls := mockVaultServer(t)
	c := &VaultClient{
		addr:  srv.URL,
		mount: "secret",
		http:  &http.Client{Timeout: 5 * time.Second},
		token: "s.static",
	}
	ctx := context.Background()
	payload := SecretPayload{Username: "ubuntu", Password: "secret"}
	if err := c.Write(ctx, "triton/t1/credentials/c1", payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := c.Read(ctx, "triton/t1/credentials/c1")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Username != "ubuntu" {
		t.Errorf("username: got %q want %q", got.Username, "ubuntu")
	}
	if err := c.Delete(ctx, "triton/t1/credentials/c1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_ = calls
}

func TestVaultClient_AppRoleLogin(t *testing.T) {
	srv, calls := mockVaultServer(t)
	c, err := NewVaultClient(srv.URL, "secret", "", "role-id", "secret-id")
	if err != nil {
		t.Fatalf("NewVaultClient with AppRole: %v", err)
	}
	if c.token != "s.test-token" {
		t.Errorf("token after AppRole login: got %q want %q", c.token, "s.test-token")
	}
	found := false
	for _, call := range *calls {
		if call == "POST /v1/auth/approle/login" {
			found = true
		}
	}
	if !found {
		t.Error("expected AppRole login call")
	}
}

func TestNewVaultClientFromEnv_NilWhenNotConfigured(t *testing.T) {
	c, err := NewVaultClientFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Error("expected nil client when vault not configured")
	}
}
