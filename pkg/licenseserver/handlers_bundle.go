package licenseserver

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
)

// bundleRequest is the POST body for the bundle download endpoint.
type bundleRequest struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Profile string `json:"profile"`
}

// POST /api/v1/admin/licenses/{id}/bundle
//
// Packages the latest binary for the requested platform together with a
// freshly-generated agent.yaml and the appropriate install script into a
// single downloadable archive (tar.gz for Linux/macOS, zip for Windows).
func (s *Server) handleDownloadBundle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req bundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate OS.
	if !validOS[req.OS] {
		writeError(w, http.StatusBadRequest, "os must be linux, darwin, or windows")
		return
	}

	// Validate arch.
	if !validArch[req.Arch] {
		writeError(w, http.StatusBadRequest, "arch must be amd64 or arm64")
		return
	}

	// windows/arm64 is not supported.
	if req.OS == "windows" && req.Arch == "arm64" {
		writeError(w, http.StatusBadRequest, "windows/arm64 is not supported")
		return
	}

	// Default profile.
	if req.Profile == "" {
		req.Profile = "comprehensive"
	}
	if req.Profile != "quick" && req.Profile != "standard" && req.Profile != "comprehensive" {
		writeError(w, http.StatusBadRequest, "profile must be quick, standard, or comprehensive")
		return
	}

	// Look up license.
	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("bundle: get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "cannot generate bundle for a revoked license")
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "cannot generate bundle for an expired license")
		return
	}

	// Find the binary — latest version matching the requested os/arch.
	binaries, err := s.listBinaries()
	if err != nil {
		log.Printf("bundle: list binaries error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	var match *binaryMeta
	for i := len(binaries) - 1; i >= 0; i-- {
		if binaries[i].OS == req.OS && binaries[i].Arch == req.Arch {
			match = &binaries[i]
			break
		}
	}
	if match == nil {
		writeError(w, http.StatusNotFound, "no binary available for "+req.OS+"/"+req.Arch)
		return
	}

	safeFilename := filepath.Base(match.Filename)
	binaryPath := filepath.Join(s.config.BinariesDir, match.Version, req.OS+"-"+req.Arch, safeFilename)

	// Generate agent.yaml.
	tok, err := s.signToken(lic, "")
	if err != nil {
		log.Printf("bundle: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	var reportServer string
	switch {
	case s.config.ReportServerPublicURL != "":
		reportServer = s.config.ReportServerPublicURL
	default:
		reportServer = s.config.ReportServerURL
	}

	yamlBody := buildAgentYAML(agentYAMLParams{
		License:      lic,
		Token:        tok,
		ReportServer: reportServer,
		Profile:      req.Profile,
	})

	// Pick install script and binary name.
	var installScript, installFilename, binName string
	if req.OS == "windows" {
		installScript = bundledInstallBat
		installFilename = "install.bat"
		binName = "triton.exe"
	} else {
		installScript = bundledInstallSh
		installFilename = "install.sh"
		binName = "triton"
	}

	archiveName := fmt.Sprintf("triton-%s-%s-%s", match.Version, req.OS, req.Arch)

	// Audit before streaming — if the archive write fails mid-stream
	// we still want the audit record.
	s.audit(r, "license_download_bundle", id, lic.OrgID, "", map[string]any{
		"os":      req.OS,
		"arch":    req.Arch,
		"version": match.Version,
		"profile": req.Profile,
		"tier":    lic.Tier,
	})

	// Package and serve.
	if req.OS == "windows" {
		s.serveZipBundle(w, archiveName, binaryPath, binName, yamlBody, installScript, installFilename)
	} else {
		s.serveTarGzBundle(w, archiveName, binaryPath, binName, yamlBody, installScript, installFilename)
	}
}

// serveTarGzBundle streams a tar.gz archive containing the binary, agent.yaml, and install script.
func (s *Server) serveTarGzBundle(w http.ResponseWriter, archiveName, binaryPath, binName, yamlBody, installScript, installFilename string) {
	binData, err := os.ReadFile(binaryPath)
	if err != nil {
		log.Printf("bundle: read binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", archiveName+".tar.gz"))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	entries := []struct {
		Name string
		Data []byte
		Mode int64
	}{
		{Name: binName, Data: binData, Mode: 0755},
		{Name: "agent.yaml", Data: []byte(yamlBody), Mode: 0600},
		{Name: installFilename, Data: []byte(installScript), Mode: 0755},
	}

	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.Name,
			Size: int64(len(e.Data)),
			Mode: e.Mode,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			log.Printf("bundle: tar write header error: %v", err)
			return
		}
		if _, err := tw.Write(e.Data); err != nil {
			log.Printf("bundle: tar write data error: %v", err)
			return
		}
	}

	_ = tw.Close()
	_ = gw.Close()
}

// serveZipBundle streams a zip archive containing the binary, agent.yaml, and install script.
func (s *Server) serveZipBundle(w http.ResponseWriter, archiveName, binaryPath, binName, yamlBody, installScript, installFilename string) {
	binData, err := os.ReadFile(binaryPath)
	if err != nil {
		log.Printf("bundle: read binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", archiveName+".zip"))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	zw := zip.NewWriter(w)

	entries := []struct {
		Name string
		Data []byte
	}{
		{Name: binName, Data: binData},
		{Name: "agent.yaml", Data: []byte(yamlBody)},
		{Name: installFilename, Data: []byte(installScript)},
	}

	for _, e := range entries {
		fw, err := zw.Create(e.Name)
		if err != nil {
			log.Printf("bundle: zip create entry error: %v", err)
			return
		}
		if _, err := io.Copy(fw, bytes.NewReader(e.Data)); err != nil {
			log.Printf("bundle: zip write data error: %v", err)
			return
		}
	}

	_ = zw.Close()
}
