//go:build integration

// Credentials — Manage Server integration tests.
//
// Covers the full operator flow:
//
//  1. Create a credential via POST /api/v1/admin/credentials (writes to fake Vault).
//  2. List credentials — sees the new entry.
//  3. Delete credential blocked when a host references it (409).
//  4. Assign credential to a host, enqueue port survey — job inherits credentials_ref.
//  5. Worker API can fetch the secret via GET /api/v1/worker/credentials/{id}.
//
// A fake in-process Vault stub (httptest.Server) serves the KV v2 endpoints so
// no real Vault installation is required. Tests that would additionally need a
// real Vault (e.g. AppRole login) are covered in pkg/manageserver/credentials/vault_test.go.

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// credSchemaSeq allocates unique PG schemas for credential integration tests.
var credSchemaSeq atomic.Int64

// fakeVaultServer starts an httptest.Server that acts as a Vault KV v2
// endpoint. Secrets are stored in memory; the mount is always "secret".
// Handles PUT (write), GET (read), DELETE on /v1/secret/data/{path…}.
// Returns 404 for paths that were never written.
func fakeVaultServer(t *testing.T) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	secrets := map[string]json.RawMessage{} // path → raw data JSON

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /v1/secret/data/ prefix to get the logical path key.
		const prefix = "/v1/secret/data/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)

		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusInternalServerError)
				return
			}
			// Vault KV v2 write body: {"data": {...}}
			var wrapper struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(body, &wrapper); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			secrets[key] = wrapper.Data
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			data, ok := secrets[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// Vault KV v2 read response: {"data": {"data": {...}}}
			resp := map[string]any{
				"data": map[string]any{"data": json.RawMessage(data)},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp) //nolint:errcheck // test helper

		case http.MethodDelete:
			delete(secrets, key)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
}

// credManageServer holds everything needed by a credential integration test.
type credManageServer struct {
	url       string // http://127.0.0.1:PORT of httptest.Server
	jwt       string // admin Bearer token (already past setup + login)
	workerKey string // X-Worker-Key value for Worker API calls
}

// requireCredManageServer spins up a Manage Server with a fake Vault, completes
// setup (admin + license), logs in, and returns the test harness.
// The server and fake Vault are cleaned up via t.Cleanup.
func requireCredManageServer(t *testing.T) credManageServer {
	t.Helper()

	// Fake Vault.
	vault := fakeVaultServer(t)
	t.Cleanup(vault.Close)

	// Ed25519 keypair for license tokens — same pattern as manage_setup_test.go.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "cred-int-test-lic",
		Tier:      license.TierPro,
		Org:       "CredIntegrationTest",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	ls := newManageStubLicenseServer(t, stubLicenseServerConfig{
		signedToken:  signed,
		activationID: uuid.NewString(),
		tier:         "pro",
		features:     licensestore.Features{Manage: true},
	})
	t.Cleanup(ls.Close)

	// Isolated DB schema.
	schema := fmt.Sprintf("test_cred_int_%d", credSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	})

	const workerKey = "cred-int-test-worker-key"

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: manageJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
		VaultAddr:     vault.URL,
		VaultMount:    "secret",
		VaultToken:    "test-token",
		WorkerKey:     workerKey,
	}
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")

	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// Complete setup via API (same as TestManageServerSetupFlow).
	const adminEmail = "cred-admin@example.com"
	const adminPassword = "supersecret-password-42"

	resp := postJSON(t, ts.URL+"/api/v1/setup/admin", map[string]any{
		"email": adminEmail, "name": "Cred Test Admin", "password": adminPassword,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin failed")

	resp = postJSON(t, ts.URL+"/api/v1/setup/license", map[string]any{
		"license_server_url": ls.URL,
		"license_key":        "cred-int-test-lic",
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license failed")

	loginResp := postJSON(t, ts.URL+"/api/v1/auth/login", map[string]any{
		"email": adminEmail, "password": adminPassword,
	})
	loginBodyBytes, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login failed: %s", loginBodyBytes)

	var loginBody map[string]any
	require.NoError(t, json.Unmarshal(loginBodyBytes, &loginBody))
	token, _ := loginBody["token"].(string)
	require.NotEmpty(t, token, "login returned no token")

	return credManageServer{url: ts.URL, jwt: token, workerKey: workerKey}
}

// credDo performs an authenticated HTTP request to the manage server.
func credDo(t *testing.T, method, url, jwt string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// credDoWorker performs a worker-authenticated request (X-Worker-Key).
func credDoWorker(t *testing.T, method, url, workerKey string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	req.Header.Set("X-Worker-Key", workerKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// decodeBody reads and decodes a JSON response body, closing it.
func credDecodeBody(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	require.NoError(t, json.Unmarshal(b, out), "decode body: %s", b)
}

// ---

func TestCredentials_CRUD(t *testing.T) {
	h := requireCredManageServer(t)

	// Create — ssh-key type.
	createResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/credentials", h.jwt, map[string]any{
		"name":        "prod-ssh-key",
		"auth_type":   "ssh-key",
		"username":    "ubuntu",
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----",
	})
	defer createResp.Body.Close()
	createBody, _ := io.ReadAll(createResp.Body)
	require.Equal(t, http.StatusCreated, createResp.StatusCode, "create credential: %s", createBody)

	var created map[string]any
	require.NoError(t, json.Unmarshal(createBody, &created))
	credID, _ := created["id"].(string)
	require.NotEmpty(t, credID)
	assert.Equal(t, "prod-ssh-key", created["name"])
	assert.Equal(t, "ssh-key", created["auth_type"])
	// vault_path must NOT appear in the response.
	_, hasVaultPath := created["vault_path"]
	assert.False(t, hasVaultPath, "vault_path must not be exposed in response")

	// List — credential appears.
	listResp := credDo(t, http.MethodGet, h.url+"/api/v1/admin/credentials", h.jwt, nil)
	var list []map[string]any
	credDecodeBody(t, listResp, &list)
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	require.Len(t, list, 1)
	assert.Equal(t, credID, list[0]["id"])
	assert.Equal(t, float64(0), list[0]["in_use_count"], "in_use_count should be 0")

	// Delete — no hosts referencing it, should succeed.
	delResp := credDo(t, http.MethodDelete, h.url+"/api/v1/admin/credentials/"+credID, h.jwt, nil)
	delBody, _ := io.ReadAll(delResp.Body)
	delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode, "delete: %s", delBody)

	// List after delete — empty.
	listResp2 := credDo(t, http.MethodGet, h.url+"/api/v1/admin/credentials", h.jwt, nil)
	var list2 []map[string]any
	credDecodeBody(t, listResp2, &list2)
	assert.Empty(t, list2)
}

func TestCredentials_DeleteBlockedByHostReference(t *testing.T) {
	h := requireCredManageServer(t)

	// Create credential.
	createResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/credentials", h.jwt, map[string]any{
		"name":        "blocked-cred",
		"auth_type":   "ssh-password",
		"username":    "root",
		"password":    "hunter2",
	})
	var cred map[string]any
	credDecodeBody(t, createResp, &cred)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	credID := cred["id"].(string)

	// Create host referencing the credential.
	credUUID := uuid.MustParse(credID)
	hostResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts", h.jwt, map[string]any{
		"hostname":        "db-01",
		"ip":              "10.0.0.2",
		"credentials_ref": credUUID,
		"access_port":     22,
	})
	hostBody, _ := io.ReadAll(hostResp.Body)
	hostResp.Body.Close()
	require.Equal(t, http.StatusCreated, hostResp.StatusCode, "create host: %s", hostBody)

	// in_use_count should now be 1.
	listResp := credDo(t, http.MethodGet, h.url+"/api/v1/admin/credentials", h.jwt, nil)
	var list []map[string]any
	credDecodeBody(t, listResp, &list)
	require.Len(t, list, 1)
	assert.Equal(t, float64(1), list[0]["in_use_count"])

	// Delete — must be blocked.
	delResp := credDo(t, http.MethodDelete, h.url+"/api/v1/admin/credentials/"+credID, h.jwt, nil)
	delBody, _ := io.ReadAll(delResp.Body)
	delResp.Body.Close()
	assert.Equal(t, http.StatusConflict, delResp.StatusCode, "delete should be blocked: %s", delBody)

	var errBody map[string]any
	require.NoError(t, json.Unmarshal(delBody, &errBody))
	errMsg, _ := errBody["error"].(string)
	assert.Contains(t, errMsg, "in use", "error message should mention in-use")
}

func TestCredentials_PortSurveyJobInheritsCredentialsRef(t *testing.T) {
	h := requireCredManageServer(t)

	// Create credential.
	createResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/credentials", h.jwt, map[string]any{
		"name":      "survey-cred",
		"auth_type": "ssh-password",
		"username":  "scanner",
		"password":  "sc4nn3r!",
	})
	var cred map[string]any
	credDecodeBody(t, createResp, &cred)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	credID := cred["id"].(string)

	// Create host with credentials_ref.
	credUUID := uuid.MustParse(credID)
	hostResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/hosts", h.jwt, map[string]any{
		"hostname":        "web-01",
		"ip":              "10.0.0.10",
		"credentials_ref": credUUID,
		"access_port":     22,
	})
	var host map[string]any
	credDecodeBody(t, hostResp, &host)
	require.Equal(t, http.StatusCreated, hostResp.StatusCode)
	hostID := host["id"].(string)

	// Enqueue port survey job.
	jobResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/scan-jobs/port-survey", h.jwt, map[string]any{
		"host_ids": []string{hostID},
		"profile":  "standard",
	})
	jobBody, _ := io.ReadAll(jobResp.Body)
	jobResp.Body.Close()
	require.Equal(t, http.StatusCreated, jobResp.StatusCode, "enqueue port survey: %s", jobBody)

	var jobs []map[string]any
	require.NoError(t, json.Unmarshal(jobBody, &jobs))
	require.Len(t, jobs, 1, "expected exactly one job created")

	job := jobs[0]
	assert.Equal(t, "port_survey", job["job_type"])
	assert.Equal(t, hostID, job["host_id"])

	jobCredRef, _ := job["credentials_ref"].(string)
	assert.Equal(t, credID, jobCredRef, "job must inherit credentials_ref from host")
}

func TestCredentials_WorkerCanFetchSecret(t *testing.T) {
	h := requireCredManageServer(t)

	const wantUsername = "ops-user"
	const wantPassword = "s3cr3t!"

	// Create credential.
	createResp := credDo(t, http.MethodPost, h.url+"/api/v1/admin/credentials", h.jwt, map[string]any{
		"name":      "worker-fetch-cred",
		"auth_type": "ssh-password",
		"username":  wantUsername,
		"password":  wantPassword,
	})
	var cred map[string]any
	credDecodeBody(t, createResp, &cred)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	credID := cred["id"].(string)

	// Worker API: GET /api/v1/worker/credentials/{id}.
	secretResp := credDoWorker(t, http.MethodGet,
		h.url+"/api/v1/worker/credentials/"+credID, h.workerKey)
	var secret map[string]any
	credDecodeBody(t, secretResp, &secret)
	require.Equal(t, http.StatusOK, secretResp.StatusCode)

	assert.Equal(t, wantUsername, secret["username"])
	assert.Equal(t, wantPassword, secret["password"])
	_, hasPrivKey := secret["private_key"]
	assert.False(t, hasPrivKey, "ssh-password type must not return private_key")

	// Wrong worker key → 401.
	badResp := credDoWorker(t, http.MethodGet,
		h.url+"/api/v1/worker/credentials/"+credID, "wrong-key")
	io.Copy(io.Discard, badResp.Body) //nolint:errcheck // test helper
	badResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, badResp.StatusCode)
}
