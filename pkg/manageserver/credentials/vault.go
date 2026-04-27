package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned by Read when the secret path does not exist in Vault.
var ErrNotFound = errors.New("vault: secret not found")

// VaultClient is a thin Vault KV v2 HTTP wrapper. No Vault SDK dependency.
type VaultClient struct {
	addr  string
	mount string
	client *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time // zero = never expires (static token mode)

	roleID   string
	secretID string
}

// NewVaultClientFromEnv reads TRITON_VAULT_ADDR, TRITON_VAULT_MOUNT,
// TRITON_VAULT_TOKEN, TRITON_VAULT_ROLE_ID, TRITON_VAULT_SECRET_ID.
// Returns nil (no error) when TRITON_VAULT_ADDR is not set — callers return 503.
func NewVaultClientFromEnv() (*VaultClient, error) {
	addr := os.Getenv("TRITON_VAULT_ADDR")
	if addr == "" {
		return nil, nil
	}
	mount := os.Getenv("TRITON_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	token := os.Getenv("TRITON_VAULT_TOKEN")
	roleID := os.Getenv("TRITON_VAULT_ROLE_ID")
	secretID := os.Getenv("TRITON_VAULT_SECRET_ID")
	return NewVaultClient(addr, mount, token, roleID, secretID)
}

// NewVaultClient constructs a VaultClient. If roleID is set, performs an
// AppRole login immediately. If only token is set, uses it as a static token.
func NewVaultClient(addr, mount, token, roleID, secretID string) (*VaultClient, error) {
	c := &VaultClient{
		addr:     strings.TrimRight(addr, "/"),
		mount:    mount,
		client:   &http.Client{Timeout: 10 * time.Second},
		roleID:   roleID,
		secretID: secretID,
	}
	if roleID != "" {
		// No goroutines exist yet; safe to call loginLocked without mu.Lock.
		if err := c.loginLocked(); err != nil {
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
	} else {
		c.token = token
	}
	return c, nil
}

// loginLocked performs AppRole login. Caller must hold mu OR be in constructor
// (where no concurrent goroutines can observe c yet).
func (c *VaultClient) loginLocked() error {
	body, err := json.Marshal(map[string]string{
		"role_id":   c.roleID,
		"secret_id": c.secretID,
	})
	if err != nil {
		return err
	}
	resp, err := c.client.Post(
		c.addr+"/v1/auth/approle/login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("approle login request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("approle login: status %d", resp.StatusCode)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode approle login response: %w", err)
	}
	c.token = out.Auth.ClientToken
	if out.Auth.LeaseDuration > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
	}
	return nil
}

// authHeader returns the current Vault token, re-logging via AppRole if the
// token is expired. Safe for concurrent callers.
func (c *VaultClient) authHeader() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Only attempt renewal when AppRole is configured AND we have an expiry set
	// AND the token is within 60 seconds of expiry (renew proactively).
	if c.roleID != "" && !c.tokenExpiry.IsZero() && time.Now().After(c.tokenExpiry.Add(-60*time.Second)) {
		if err := c.loginLocked(); err != nil {
			return "", fmt.Errorf("vault token renewal: %w", err)
		}
	}
	return c.token, nil
}

// doReq executes an authenticated HTTP request against the Vault API.
func (c *VaultClient) doReq(ctx context.Context, method, urlPath string, body any) (*http.Response, error) {
	tok, err := c.authHeader()
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+urlPath, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

// kvPath returns the /v1/{mount}/data/{path} URL suffix for KV v2.
func (c *VaultClient) kvPath(path string) string {
	return fmt.Sprintf("/v1/%s/data/%s", c.mount, path)
}

// Write stores a SecretPayload at the given KV v2 path.
func (c *VaultClient) Write(ctx context.Context, path string, payload SecretPayload) error {
	resp, err := c.doReq(ctx, http.MethodPut, c.kvPath(path), map[string]any{"data": payload})
	if err != nil {
		return fmt.Errorf("vault write: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("vault write: status %d", resp.StatusCode)
	}
	return nil
}

// Read fetches the latest version of a SecretPayload from the given KV v2 path.
func (c *VaultClient) Read(ctx context.Context, path string) (SecretPayload, error) {
	resp, err := c.doReq(ctx, http.MethodGet, c.kvPath(path), nil)
	if err != nil {
		return SecretPayload{}, fmt.Errorf("vault read: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return SecretPayload{}, fmt.Errorf("vault read: %w", ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return SecretPayload{}, fmt.Errorf("vault read: status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Data SecretPayload `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return SecretPayload{}, fmt.Errorf("vault read decode: %w", err)
	}
	return out.Data.Data, nil
}

// Delete removes the latest version of the secret at the given KV v2 path.
func (c *VaultClient) Delete(ctx context.Context, path string) error {
	resp, err := c.doReq(ctx, http.MethodDelete, c.kvPath(path), nil)
	if err != nil {
		return fmt.Errorf("vault delete: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("vault delete: status %d", resp.StatusCode)
	}
	return nil
}
