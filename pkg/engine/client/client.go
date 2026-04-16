// Package client implements the HTTP client used by the triton-engine
// binary to phone home to the Triton portal. It loads the onboarding
// bundle (engine.json + engine.crt + engine.key + portal-ca.crt) from
// disk, parses the manifest, and builds an mTLS-configured *http.Client
// pre-loaded with the engine's client certificate.
//
// ## TLS trust model
//
// The portal's 8443 gateway listener terminates TLS with a self-signed
// certificate (see Task 10 in docs/plans/2026-04-14-onboarding-phase-2...).
// The portal-ca.crt shipped in the bundle is the org's *engine-CA* —
// the CA that signed the engine's client cert. It is NOT the CA that
// signed the portal's server certificate.
//
// For MVP we therefore set InsecureSkipVerify=true when dialing the
// portal. Trust of the portal URL is established out-of-band (the
// operator downloads the bundle from the authenticated admin UI and
// copies it to the engine host). A follow-up task will ship a portal
// server-CA alongside the bundle so the engine can pin it.
package client

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	srvdisc "github.com/amiryahaya/triton/pkg/server/discovery"
	"github.com/amiryahaya/triton/pkg/server/engine"
)

// Client is the engine-side HTTP client. It carries the parsed manifest
// (engine ID, portal URL) and a pre-configured *http.Client with mTLS
// client auth and InsecureSkipVerify for the server cert (see package
// docs for why).
type Client struct {
	PortalURL string
	EngineID  string
	HTTP      *http.Client
	TLSCert   tls.Certificate // engine's mTLS cert+key from bundle
}

// requestTimeout is the per-request timeout applied to the underlying
// *http.Client. Retries are the responsibility of the caller (see
// pkg/engine/loop).
const requestTimeout = 30 * time.Second

// maxResponseBody caps how many bytes we'll read from the portal even
// for a 200 response. Bundle gateway responses are tiny JSON blobs;
// an unexpectedly large body signals a misconfigured intermediary and
// we'd rather fail fast than hang.
const maxResponseBody = 64 * 1024

// New opens the bundle at bundlePath, extracts its four files in
// memory, and returns a Client wired up to talk to the portal named
// in the manifest.
func New(bundlePath string) (*Client, error) {
	raw, err := os.ReadFile(bundlePath) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	files, err := extractTarGz(raw)
	if err != nil {
		return nil, fmt.Errorf("extract bundle: %w", err)
	}

	manifestRaw, ok := files["engine.json"]
	if !ok {
		return nil, fmt.Errorf("bundle missing engine.json")
	}
	var manifest engine.BundleManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("parse engine.json: %w", err)
	}
	if manifest.ReportServerURL == "" {
		return nil, fmt.Errorf("engine.json: report_server_url is empty")
	}

	certPEM, ok := files["engine.crt"]
	if !ok {
		return nil, fmt.Errorf("bundle missing engine.crt")
	}
	keyPEM, ok := files["engine.key"]
	if !ok {
		return nil, fmt.Errorf("bundle missing engine.key")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse engine keypair: %w", err)
	}

	// portal-ca.crt is the org engine-CA; unused for server auth in
	// MVP but we still require it in the bundle as a sanity check.
	if _, ok := files["portal-ca.crt"]; !ok {
		return nil, fmt.Errorf("bundle missing portal-ca.crt")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// InsecureSkipVerify is DELIBERATE — see package docs.
		// Trust of the portal URL is out-of-band.
		InsecureSkipVerify: true, //nolint:gosec // documented tradeoff
		MinVersion:         tls.VersionTLS12,
	}
	return &Client{
		PortalURL: manifest.ReportServerURL,
		EngineID:  manifest.EngineID.String(),
		TLSCert:   cert,
		HTTP: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}, nil
}

// Enroll issues POST {portal}/api/v1/engine/enroll. A 200 response
// means the portal recorded our first-seen timestamp (or recognised
// us as already enrolled).
func (c *Client) Enroll(ctx context.Context) error {
	return c.post(ctx, "/api/v1/engine/enroll", true)
}

// Heartbeat issues POST {portal}/api/v1/engine/heartbeat. A 204 is
// expected on success.
func (c *Client) Heartbeat(ctx context.Context) error {
	return c.post(ctx, "/api/v1/engine/heartbeat", false)
}

// pollTimeout bounds a single discovery long-poll round-trip. The
// server holds the connection open for up to 30s, so we set the
// client-side budget a bit higher to avoid racing the server's
// deadline.
const pollTimeout = 45 * time.Second

// longPollClient returns a dedicated *http.Client that shares the
// mTLS-configured transport from c.HTTP but raises the per-request
// timeout to accommodate server-side long-polling.
func (c *Client) longPollClient() *http.Client {
	return &http.Client{
		Timeout:   pollTimeout,
		Transport: c.HTTP.Transport,
	}
}

// PollDiscovery long-polls the portal for a queued discovery job
// assigned to this engine. On HTTP 200 it decodes and returns the
// job. On 204 (no work) it returns (nil, nil) so the caller can
// simply poll again. Any other status — or transport error — returns
// a non-nil error.
func (c *Client) PollDiscovery(ctx context.Context) (*srvdisc.Job, error) {
	url := c.PortalURL + "/api/v1/engine/discoveries/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.longPollClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll discovery: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var job srvdisc.Job
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&job); err != nil {
			return nil, fmt.Errorf("decode job: %w", err)
		}
		return &job, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("poll discovery: unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// submitCandidate mirrors the engine-side wire format defined by the
// gateway handler (address as string, not net.IP, so the engine can
// forward rDNS strings or fall back to the raw IP literal).
type submitCandidate struct {
	Address   string `json:"address"`
	Hostname  string `json:"hostname,omitempty"`
	OpenPorts []int  `json:"open_ports"`
}

// submitPayload is the POST body for /engine/discoveries/{id}/submit.
type submitPayload struct {
	Candidates []submitCandidate `json:"candidates"`
	Error      string            `json:"error,omitempty"`
}

// SubmitDiscovery posts the terminal result for a claimed discovery
// job. If errMsg is non-empty the job is flipped to 'failed' and the
// candidate list is ignored by the server. Otherwise the candidates
// are persisted and the job flipped to 'completed'. Expected server
// response is 204.
func (c *Client) SubmitDiscovery(ctx context.Context, jobID uuid.UUID, candidates []srvdisc.Candidate, errMsg string) error {
	body := submitPayload{Error: errMsg}
	body.Candidates = make([]submitCandidate, 0, len(candidates))
	for i := range candidates {
		cand := &candidates[i]
		body.Candidates = append(body.Candidates, submitCandidate{
			Address:   cand.Address.String(),
			Hostname:  cand.Hostname,
			OpenPorts: cand.OpenPorts,
		})
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal submit body: %w", err)
	}

	url := c.PortalURL + "/api/v1/engine/discoveries/" + jobID.String() + "/submit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("submit discovery: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("submit discovery: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// post is the shared round-trip helper. If expectBody is true, a 200
// status is required and the body is logged (via the returned error
// on failure); otherwise 204 is required.
func (c *Client) post(ctx context.Context, path string, expectBody bool) error {
	url := c.PortalURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()

	want := http.StatusNoContent
	if expectBody {
		want = http.StatusOK
	}
	if resp.StatusCode != want {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("post %s: unexpected status %d: %s", path, resp.StatusCode, string(body))
	}
	return nil
}

// SubmitEncryptionPubkey POSTs the engine's static X25519 public key
// to /api/v1/engine/encryption-pubkey. Idempotent: latest submission
// wins. Expected server response is 204.
func (c *Client) SubmitEncryptionPubkey(ctx context.Context, pubkey []byte) error {
	body := map[string]string{"pubkey": base64.StdEncoding.EncodeToString(pubkey)}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal pubkey body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.PortalURL+"/api/v1/engine/encryption-pubkey", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("submit pubkey: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("submit pubkey: unexpected status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// DeliveryPayload is the engine-local wire shape for a pulled
// credential delivery. Mirrors pkg/server/credentials.DeliveryPayload
// but is duplicated here to keep pkg/engine/client free of
// server-package imports.
type DeliveryPayload struct {
	ID         string `json:"id"`
	ProfileID  string `json:"profile_id,omitempty"`
	SecretRef  string `json:"secret_ref"`
	AuthType   string `json:"auth_type"`
	Kind       string `json:"kind"`
	Ciphertext string `json:"ciphertext,omitempty"` // base64; present only for kind=push
}

// PollCredentialDelivery long-polls the portal for a credential
// delivery targeted at this engine. 200 → payload, 204 → (nil, nil).
func (c *Client) PollCredentialDelivery(ctx context.Context) (*DeliveryPayload, error) {
	url := c.PortalURL + "/api/v1/engine/credentials/deliveries/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.longPollClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll credential delivery: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		var d DeliveryPayload
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&d); err != nil {
			return nil, fmt.Errorf("decode delivery: %w", err)
		}
		return &d, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("poll credential delivery: unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

// ackDeliveryBody is the POST body for /engine/credentials/deliveries/{id}/ack.
type ackDeliveryBody struct {
	Error string `json:"error,omitempty"`
}

// AckCredentialDelivery acks a claimed delivery. A non-empty errMsg
// marks the delivery as failed. Expected server response is 204.
func (c *Client) AckCredentialDelivery(ctx context.Context, id, errMsg string) error {
	raw, err := json.Marshal(ackDeliveryBody{Error: errMsg})
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err)
	}
	url := c.PortalURL + "/api/v1/engine/credentials/deliveries/" + id + "/ack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("ack delivery: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("ack delivery: unexpected status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// HostTarget is a single host to probe as part of a credential test job.
type HostTarget struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// TestJobPayload is the engine-local wire shape for a pulled credential
// test job.
type TestJobPayload struct {
	ID        string       `json:"id"`
	ProfileID string       `json:"profile_id"`
	SecretRef string       `json:"secret_ref"`
	AuthType  string       `json:"auth_type"`
	Hosts     []HostTarget `json:"hosts"`
}

// PollCredentialTest long-polls for a credential test job.
func (c *Client) PollCredentialTest(ctx context.Context) (*TestJobPayload, error) {
	url := c.PortalURL + "/api/v1/engine/credentials/tests/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.longPollClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll credential test: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		var j TestJobPayload
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&j); err != nil {
			return nil, fmt.Errorf("decode test job: %w", err)
		}
		return &j, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("poll credential test: unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

// SubmittedTestResult is a single per-host outcome posted back to the
// portal for a credential test job.
type SubmittedTestResult struct {
	HostID    string `json:"host_id"`
	Success   bool   `json:"success"`
	LatencyMs int    `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// submitTestBody is the POST body for /engine/credentials/tests/{id}/submit.
type submitTestBody struct {
	Results []SubmittedTestResult `json:"results"`
	Error   string                `json:"error,omitempty"`
}

// SubmitCredentialTest posts the terminal result for a credential test
// job. Expected server response is 204.
func (c *Client) SubmitCredentialTest(ctx context.Context, testID string, results []SubmittedTestResult, errMsg string) error {
	if results == nil {
		results = []SubmittedTestResult{}
	}
	raw, err := json.Marshal(submitTestBody{Results: results, Error: errMsg})
	if err != nil {
		return fmt.Errorf("marshal submit body: %w", err)
	}
	url := c.PortalURL + "/api/v1/engine/credentials/tests/" + testID + "/submit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("submit credential test: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("submit credential test: unexpected status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// extractTarGz decompresses the gzip+tar stream and returns a map of
// filename → contents. Returns an error if the archive is malformed
// or any single member exceeds 1 MiB (sanity cap).
func extractTarGz(raw []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := make(map[string][]byte)
	const maxMember = 1 << 20
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Size > maxMember {
			return nil, fmt.Errorf("tar member %s too large: %d bytes", hdr.Name, hdr.Size)
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		out[hdr.Name] = buf
	}
	return out, nil
}
