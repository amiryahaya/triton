package licenseserver

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
)

// POST /api/v1/admin/licenses/{id}/install-token
//
// Generates a short-lived HMAC install token for a license. The token
// is embedded in a curl/PowerShell one-liner that the admin copies to
// the target host. The one-liner calls back to the license server to
// download the binary and agent.yaml — no manual file transfer needed.
func (s *Server) handleGenerateInstallToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if s.config.PublicURL == "" {
		writeError(w, http.StatusBadRequest,
			"PublicURL is not configured on this license server; install-token features are disabled")
		return
	}

	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("install-token: get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "cannot generate install token for a revoked license")
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "cannot generate install token for an expired license")
		return
	}

	ttl := 24 * time.Hour
	token, err := GenerateInstallToken(s.config.SigningKey.Seed(), id, ttl)
	if err != nil {
		log.Printf("install-token: generate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	scriptURL := fmt.Sprintf("%s/api/v1/install/%s", s.config.PublicURL, token)

	s.audit(r, "install_token_generate", id, lic.OrgID, "", map[string]any{
		"expires_in": int(ttl.Seconds()),
		"tier":       lic.Tier,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"expires_in":   int(ttl.Seconds()),
		"curl_command": fmt.Sprintf("curl -sSL '%s' | sudo bash", scriptURL),
		"ps1_command":  fmt.Sprintf("irm '%s?shell=ps1' | iex", scriptURL),
	})
}

// installScriptData is the template context for oneliner install scripts.
type installScriptData struct {
	BaseURL   string
	Token     string
	ScriptURL string
}

// Pre-parsed install script templates. Parsed once at package init
// since the template source is a compile-time constant.
var (
	installShTmpl  = template.Must(template.New("sh").Parse(onelinerInstallSh))
	installPs1Tmpl = template.Must(template.New("ps1").Parse(onelinerInstallPs1))
)

// GET /api/v1/install/{token}
//
// Serves the one-liner install script. The token in the URL path
// authenticates the request (HMAC-SHA256, short TTL). By default
// returns a bash script; ?shell=ps1 returns PowerShell.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	tokenStr := chi.URLParam(r, "token")
	_, err := ValidateInstallToken(s.config.SigningKey.Seed(), tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired install token")
		return
	}

	data := installScriptData{
		BaseURL:   s.config.PublicURL,
		Token:     tokenStr,
		ScriptURL: fmt.Sprintf("%s/api/v1/install/%s", s.config.PublicURL, tokenStr),
	}

	shell := r.URL.Query().Get("shell")
	tmpl := installShTmpl
	if shell == "ps1" {
		tmpl = installPs1Tmpl
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("install-script: template execute error: %v", err)
	}
}

// GET /api/v1/install/{token}/binary/{os}/{arch}
//
// Serves the latest binary for the requested platform. The token
// authenticates the request. Returns 404 if no binary is available.
func (s *Server) handleInstallBinary(w http.ResponseWriter, r *http.Request) {
	tokenStr := chi.URLParam(r, "token")
	_, err := ValidateInstallToken(s.config.SigningKey.Seed(), tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired install token")
		return
	}

	reqOS := chi.URLParam(r, "os")
	reqArch := chi.URLParam(r, "arch")

	if !validOS[reqOS] || !validArch[reqArch] {
		writeError(w, http.StatusBadRequest, "invalid os/arch")
		return
	}

	binaries, err := s.listBinaries()
	if err != nil {
		log.Printf("install-binary: list binaries error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// listBinaries returns sorted by version ascending — walk backwards
	// to find the latest binary matching the requested os/arch.
	var match *binaryMeta
	for i := len(binaries) - 1; i >= 0; i-- {
		if binaries[i].OS == reqOS && binaries[i].Arch == reqArch {
			match = &binaries[i]
			break
		}
	}
	if match == nil {
		writeError(w, http.StatusNotFound, "no binary available for "+reqOS+"/"+reqArch)
		return
	}

	safeFilename := filepath.Base(match.Filename)
	binaryPath := filepath.Clean(filepath.Join(s.config.BinariesDir, match.Version, reqOS+"-"+reqArch, safeFilename))

	// Defense-in-depth: ensure the resolved path is within BinariesDir
	// even if meta.json version field was corrupted on disk.
	if !strings.HasPrefix(binaryPath, filepath.Clean(s.config.BinariesDir)+string(os.PathSeparator)) {
		writeError(w, http.StatusBadRequest, "invalid binary path")
		return
	}

	// Integrity check: verify on-disk size matches metadata.
	fi, err := os.Stat(binaryPath)
	if err != nil || fi.Size() != match.Size {
		writeError(w, http.StatusInternalServerError, "binary integrity check failed")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeFilename))
	w.Header().Set("X-Checksum-SHA3-256", match.SHA3)
	http.ServeFile(w, r, binaryPath)
}

// GET /api/v1/install/{token}/agent-yaml
//
// Generates and serves an agent.yaml for the license embedded in the
// install token. Looks up the license, verifies it is not revoked,
// signs a fresh Ed25519 token, and builds the YAML body.
func (s *Server) handleInstallAgentYAML(w http.ResponseWriter, r *http.Request) {
	tokenStr := chi.URLParam(r, "token")
	claims, err := ValidateInstallToken(s.config.SigningKey.Seed(), tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired install token")
		return
	}

	lic, err := s.store.GetLicense(r.Context(), claims.LicenseID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("install-agent-yaml: get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "license has been revoked")
		return
	}

	tok, err := s.signToken(lic, "")
	if err != nil {
		log.Printf("install-agent-yaml: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Determine report server URL for the agent.yaml.
	var reportServer string
	switch {
	case s.config.ReportServerPublicURL != "":
		reportServer = s.config.ReportServerPublicURL
	default:
		reportServer = s.config.ReportServerURL
	}

	body := buildAgentYAML(agentYAMLParams{
		License:      lic,
		Token:        tok,
		ReportServer: reportServer,
		Profile:      "comprehensive",
	})

	s.audit(r, "install_agent_yaml_download", claims.LicenseID, lic.OrgID, "", map[string]any{
		"tier": lic.Tier,
	})

	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="agent.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
