package manageserver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// handleSetupStatus returns {admin_created, license_activated, setup_required}.
// GET /api/v1/setup/status — always available, regardless of setup mode.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"admin_created":     state.AdminCreated,
		"license_activated": state.LicenseActivated,
		"setup_required":    !state.AdminCreated || !state.LicenseActivated,
	})
}

// handleSetupAdmin creates the first admin user.
// POST /api/v1/setup/admin — body {email, name, password}.
// Only allowed when no admin exists yet (gated by SetupOnly middleware).
// Returns 409 if an admin is already created (defence-in-depth against
// a race between the middleware check and the handler body).
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	if state.AdminCreated {
		writeError(w, http.StatusConflict, "admin already created")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	user := &managestore.ManageUser{
		Email:        req.Email,
		Name:         req.Name,
		Role:         "admin",
		PasswordHash: hash,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		var cf *managestore.ErrConflict
		if errors.As(err, &cf) {
			writeError(w, http.StatusConflict, cf.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "create user failed")
		return
	}
	if err := s.store.MarkAdminCreated(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "mark setup failed")
		return
	}
	s.RefreshSetupMode(r.Context())

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":      true,
		"user_id": user.ID,
	})
}

// handleSetupLicense activates a licence against the configured License Server
// and persists the signed token locally, transitioning Manage out of setup mode.
//
// POST /api/v1/setup/license — body {license_server_url, license_key}.
//
// Atomicity caveat: if Activate succeeds on the Licence Server but the local
// persist fails, the seat is consumed on LS while Manage still thinks it's
// un-activated. Admin retries; LS dedupes on machine fingerprint + licence key.
func (s *Server) handleSetupLicense(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	if !state.AdminCreated {
		writeError(w, http.StatusConflict, "create admin first")
		return
	}
	if state.LicenseActivated {
		writeError(w, http.StatusConflict, "license already activated")
		return
	}

	var req struct {
		LicenseServerURL string `json:"license_server_url"`
		LicenseKey       string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.LicenseServerURL == "" || req.LicenseKey == "" {
		writeError(w, http.StatusBadRequest, "license_server_url and license_key required")
		return
	}

	// Reject plaintext License Server URLs unless dev opts out explicitly.
	// Production must use HTTPS so the license key isn't exposed on the wire.
	if !strings.HasPrefix(req.LicenseServerURL, "https://") {
		if os.Getenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER") != "true" {
			writeError(w, http.StatusBadRequest,
				"license_server_url must use https:// (set TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER=true to override in dev)")
			return
		}
	}

	// Activate against the License Server. The client is v1-shaped: it accepts
	// just the licence ID and computes machine binding internally. The v2
	// response fields (features, limits, product_scope) are populated when
	// the server is v2-capable; Manage enforces product scope client-side.
	client := license.NewServerClient(req.LicenseServerURL)
	resp, err := client.Activate(req.LicenseKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "activation failed: "+err.Error())
		return
	}
	if !resp.Features.Manage {
		writeError(w, http.StatusForbidden, "license does not grant manage product")
		return
	}

	instanceID := uuid.Must(uuid.NewV7()).String()
	if err := s.store.SaveLicenseActivation(r.Context(),
		req.LicenseServerURL, req.LicenseKey, resp.Token, instanceID); err != nil {
		writeError(w, http.StatusInternalServerError, "save activation: "+err.Error())
		return
	}
	s.RefreshSetupMode(r.Context())

	// Kick the licence guard + usage pusher so feature gating comes online
	// without restarting. Failures here are logged but non-fatal: the next
	// server boot will retry via initLicence.
	if lerr := s.startLicence(r.Context()); lerr != nil {
		log.Printf("manageserver: startLicence after setup: %v", lerr)
	}

	// Batch G — auto-enrol with Report. Best-effort: any failure is logged
	// but does NOT fail the setup response. Admins can manually re-trigger
	// via (future) /api/v1/admin/report/enrol when that endpoint lands.
	// Skipped entirely when ReportServer or ReportServiceKey are empty.
	if s.cfg.ReportServer != "" && s.cfg.ReportServiceKey != "" {
		if enrolErr := s.autoEnrolWithReport(r.Context(), instanceID, req.LicenseKey); enrolErr != nil {
			log.Printf("manageserver: Report auto-enrol failed (best-effort, continuing): %v", enrolErr)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"features": resp.Features,
		"limits":   resp.Limits,
	})
}

// autoEnrolWithReport performs the Batch G hand-off with the upstream
// Report server. On success it:
//  1. persists the signed leaf + matching private key + Report's CA in
//     manage_push_creds (scanresults.Store.SavePushCreds); and
//  2. bootstraps Manage's own CA so the :8443 gateway can come up.
//
// Any failure is wrapped and returned; the caller logs it and continues —
// the whole flow is best-effort so a transient Report outage during
// /setup/license doesn't brick the operator's activation.
func (s *Server) autoEnrolWithReport(ctx context.Context, instanceID, licenseKey string) error {
	if s.resultsStore == nil {
		return errors.New("scan-results store not wired")
	}
	if s.caStore == nil {
		return errors.New("manage CA store not wired")
	}

	// 1. Generate a fresh ECDSA-P256 keypair locally. The private key
	//    stays on Manage; Report only ever sees the public key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 2. POST to Report's enrol endpoint. We use a short timeout per call
	//    so a Report outage can't hang the /setup/license handler.
	enrolURL := strings.TrimRight(s.cfg.ReportServer, "/") + "/api/v1/admin/enrol/manage"
	body, err := json.Marshal(map[string]string{
		"manage_instance_id": instanceID,
		"license_key":        licenseKey,
		"public_key_pem":     string(pubPEM),
	})
	if err != nil {
		return fmt.Errorf("marshal enrol body: %w", err)
	}

	// Derive from a non-cancellable parent so the Report hand-off survives
	// an operator's browser closing mid-request. /setup/license is
	// best-effort for the auto-enrol step; losing the signed bundle
	// because a client disconnected would leave Manage half-configured
	// with no easy recovery path.
	enrolCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(enrolCtx, http.MethodPost, enrolURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build enrol request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Triton-Service-Key", s.cfg.ReportServiceKey)

	// No Timeout on the Client — enrolCtx already bounds the whole call,
	// and setting both makes the lifecycle ambiguous (Client.Timeout
	// cancels mid-body-read and surfaces as io.ErrUnexpectedEOF instead of
	// context.DeadlineExceeded).
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("POST %s: %w", enrolURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Cap the excerpt so a misbehaving proxy can't spray megabytes
		// into logs.
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return fmt.Errorf("report /enrol/manage returned %d: %s", resp.StatusCode, string(excerpt))
	}

	// 3. Parse the gzipped tar bundle. Expected entries:
	//      client.crt   PEM-encoded signed leaf
	//      ca.crt       PEM-encoded Report engine CA
	//      config.yaml  manage_instance_id / report_url / tenant_id
	bundleBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	files, err := extractBundleFiles(bundleBytes)
	if err != nil {
		return fmt.Errorf("extract bundle: %w", err)
	}

	clientCertPEM, ok := files["client.crt"]
	if !ok {
		return errors.New("bundle missing client.crt")
	}
	caCertPEM, ok := files["ca.crt"]
	if !ok {
		return errors.New("bundle missing ca.crt")
	}
	configYAML, ok := files["config.yaml"]
	if !ok {
		return errors.New("bundle missing config.yaml")
	}
	reportURL, tenantID := parseBundleConfig(string(configYAML))
	if reportURL == "" {
		// Fall back to the configured ReportServer if config.yaml is
		// malformed. Not fatal — the Manage drain needs *a* URL.
		reportURL = strings.TrimRight(s.cfg.ReportServer, "/")
	}

	// 4. Persist push creds.
	if err := s.resultsStore.SavePushCreds(ctx, scanresults.PushCreds{
		ClientCertPEM: string(clientCertPEM),
		ClientKeyPEM:  string(keyPEM),
		CACertPEM:     string(caCertPEM),
		ReportURL:     reportURL,
		TenantID:      tenantID,
	}); err != nil {
		return fmt.Errorf("save push creds: %w", err)
	}

	// 5. Bootstrap Manage's CA. Idempotent — Run() also calls Bootstrap
	//    later, but doing it here means the :8443 gateway can come up
	//    without waiting for a next-boot cycle.
	if _, err := s.caStore.Bootstrap(ctx, instanceID); err != nil {
		return fmt.Errorf("bootstrap Manage CA: %w", err)
	}
	return nil
}

// extractBundleFiles reads a gzipped tar and returns a map of file name →
// bytes. Rejects tar members whose cumulative decompressed size exceeds
// ~10 MiB as a soft anti-zip-bomb guard.
func extractBundleFiles(raw []byte) (map[string][]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	out := map[string][]byte{}
	const maxTotal = 10 << 20 // 10 MiB
	total := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read header: %w", err)
		}
		if hdr.Size > maxTotal || total+int(hdr.Size) > maxTotal {
			return nil, fmt.Errorf("bundle exceeds size cap")
		}
		// Budget each entry against the remaining total cap (not the full
		// maxTotal) so a crafted tar can't slip past with entries that
		// individually fit the cap but collectively exceed it.
		data, err := io.ReadAll(io.LimitReader(tr, int64(maxTotal-total)))
		if err != nil {
			return nil, fmt.Errorf("tar read %s: %w", hdr.Name, err)
		}
		total += len(data)
		out[hdr.Name] = data
	}
	return out, nil
}

// parseBundleConfig pulls report_url + tenant_id out of the bundle's
// config.yaml. The format is Manage-side hand-rolled ("key: value" per
// line, no nesting) so we parse by hand rather than pulling in
// gopkg.in/yaml.v3 for three fields.
func parseBundleConfig(yamlText string) (reportURL, tenantID string) {
	for _, line := range strings.Split(yamlText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "report_url":
			reportURL = val
		case "tenant_id":
			tenantID = val
		}
	}
	return reportURL, tenantID
}

// validatePassword enforces the minimum password policy for Manage Server
// admin accounts — at least 12 characters and at least one digit. Intended
// to be tightened by B2's invite/temp-password flow.
func validatePassword(p string) error {
	if len(p) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	hasDigit := false
	for _, c := range p {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return errors.New("password must contain a digit")
	}
	return nil
}
