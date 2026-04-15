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
