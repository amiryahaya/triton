package licenseserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/sha3"
)

// versionRE is a whitelist of allowed characters in version strings.
var versionRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,49}$`)

// maxBinaryUpload is the maximum allowed binary upload size (50 MB).
const maxBinaryUpload = 50 << 20

// validOS is the allowlist of accepted operating system values.
var validOS = map[string]bool{"linux": true, "darwin": true, "windows": true}

// validArch is the allowlist of accepted architecture values.
var validArch = map[string]bool{"amd64": true, "arm64": true}

// binaryMeta holds metadata about an uploaded binary, stored as meta.json sidecar.
type binaryMeta struct {
	Version    string    `json:"version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	SHA3       string    `json:"sha3"`
	Size       int64     `json:"size"`
	Filename   string    `json:"filename"`
	UploadedAt time.Time `json:"uploadedAt"`
}

// validPathSegments checks that all path segments are safe (no traversal, not empty).
func validPathSegments(segments ...string) bool {
	for _, v := range segments {
		if v == "" || v == "." || strings.Contains(v, "..") || strings.ContainsAny(v, "/\\") {
			return false
		}
	}
	return true
}

// compareSemver compares two semver-like version strings numerically.
// Returns -1, 0, or 1. Falls back to lexicographic comparison for non-numeric parts.
func compareSemver(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		aStr := "0"
		bStr := "0"
		if i < len(aParts) {
			aStr = aParts[i]
		}
		if i < len(bParts) {
			bStr = bParts[i]
		}

		aNum, aErr := strconv.Atoi(aStr)
		bNum, bErr := strconv.Atoi(bStr)

		if aErr == nil && bErr == nil {
			if aNum < bNum {
				return -1
			}
			if aNum > bNum {
				return 1
			}
			continue
		}

		// Fallback: lexicographic.
		if aStr < bStr {
			return -1
		}
		if aStr > bStr {
			return 1
		}
	}
	return 0
}

// POST /api/v1/admin/binaries — upload a binary.
func (s *Server) handleUploadBinary(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBinaryUpload+1<<20) // extra 1MB for form fields

	if err := r.ParseMultipartForm(maxBinaryUpload); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "file exceeds maximum upload size (50 MB)")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	version := r.FormValue("version")
	goos := r.FormValue("os")
	goarch := r.FormValue("arch")
	if version == "" || goos == "" || goarch == "" {
		writeError(w, http.StatusBadRequest, "version, os, and arch are required")
		return
	}

	if !validPathSegments(version, goos, goarch) {
		writeError(w, http.StatusBadRequest, "invalid characters in version/os/arch")
		return
	}
	if !versionRE.MatchString(version) {
		writeError(w, http.StatusBadRequest, "version must be alphanumeric (max 50 chars)")
		return
	}

	if !validOS[goos] {
		writeError(w, http.StatusBadRequest, "os must be linux, darwin, or windows")
		return
	}
	if !validArch[goarch] {
		writeError(w, http.StatusBadRequest, "arch must be amd64 or arm64")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer func() { _ = file.Close() }()

	// Determine binary filename.
	filename := "triton"
	if goos == "windows" {
		filename = "triton.exe"
	}

	// Create target directory.
	dir := filepath.Join(s.config.BinariesDir, version, goos+"-"+goarch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("create binary dir error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Write to temp file first (atomic).
	tmpFile, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		log.Printf("create temp file error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	tmpPath := tmpFile.Name()
	renamed := false
	defer func() {
		_ = tmpFile.Close()
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	// Hash while copying.
	h := sha3.New256()
	size, err := io.Copy(io.MultiWriter(tmpFile, h), file)
	if err != nil {
		log.Printf("copy binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := tmpFile.Close(); err != nil {
		log.Printf("close temp file error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	checksum := fmt.Sprintf("%x", h.Sum(nil))

	// Set readable permissions before rename.
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		log.Printf("chmod binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Atomic rename binary into place.
	targetPath := filepath.Join(dir, filename)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		log.Printf("rename binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	renamed = true

	// Write meta.json atomically (temp file + rename).
	meta := binaryMeta{
		Version:    version,
		OS:         goos,
		Arch:       goarch,
		SHA3:       checksum,
		Size:       size,
		Filename:   filename,
		UploadedAt: time.Now().UTC(),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		log.Printf("marshal meta.json error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	metaPath := filepath.Join(dir, "meta.json")
	if err := atomicWriteFile(metaPath, metaBytes, 0o644); err != nil {
		log.Printf("write meta.json error: %v", err)
		// Binary is already written; log but don't fail the request.
	}

	s.audit(r, "binary_upload", "", "", "", map[string]any{
		"version": version, "os": goos, "arch": goarch, "sha3": checksum, "size": size,
	})

	writeJSON(w, http.StatusCreated, meta)
}

// GET /api/v1/admin/binaries — list all uploaded binaries.
func (s *Server) handleListBinaries(w http.ResponseWriter, r *http.Request) {
	binaries, err := s.listBinaries()
	if err != nil {
		log.Printf("list binaries error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, binaries)
}

// DELETE /api/v1/admin/binaries/{version}/{os}/{arch} — delete a binary.
func (s *Server) handleDeleteBinary(w http.ResponseWriter, r *http.Request) {
	version := chi.URLParam(r, "version")
	goos := chi.URLParam(r, "os")
	goarch := chi.URLParam(r, "arch")

	if !validPathSegments(version, goos, goarch) {
		writeError(w, http.StatusBadRequest, "invalid path parameters")
		return
	}

	dir := filepath.Join(s.config.BinariesDir, version, goos+"-"+goarch)
	metaPath := filepath.Join(dir, "meta.json")

	// Read meta to get the binary filename before deleting.
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "binary not found")
		return
	}

	var meta binaryMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		log.Printf("parse meta.json error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Delete known files only (no RemoveAll).
	binaryFilename := filepath.Base(meta.Filename) // sanitize
	_ = os.Remove(filepath.Join(dir, binaryFilename))
	_ = os.Remove(metaPath)
	_ = os.Remove(dir) // succeeds only if empty

	// Clean up empty version directory.
	versionDir := filepath.Join(s.config.BinariesDir, version)
	entries, _ := os.ReadDir(versionDir)
	if len(entries) == 0 {
		_ = os.Remove(versionDir)
	}

	s.audit(r, "binary_delete", "", "", "", map[string]any{
		"version": version, "os": goos, "arch": goarch,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// GET /api/v1/license/download/latest-version — returns latest version + platforms.
func (s *Server) handleLatestVersion(w http.ResponseWriter, r *http.Request) {
	binaries, err := s.listBinaries()
	if err != nil {
		log.Printf("list binaries error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if len(binaries) == 0 {
		writeError(w, http.StatusNotFound, "no binaries available")
		return
	}

	// Find the latest version using numeric semver comparison.
	versions := make(map[string][]binaryMeta)
	for _, b := range binaries {
		versions[b.Version] = append(versions[b.Version], b)
	}
	var versionList []string
	for v := range versions {
		versionList = append(versionList, v)
	}
	sort.Slice(versionList, func(i, j int) bool {
		return compareSemver(versionList[i], versionList[j]) < 0
	})
	latest := versionList[len(versionList)-1]

	platforms := make([]map[string]string, 0, len(versions[latest]))
	for _, b := range versions[latest] {
		platforms = append(platforms, map[string]string{"os": b.OS, "arch": b.Arch, "sha3": b.SHA3})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":   latest,
		"platforms": platforms,
	})
}

// GET /api/v1/license/download/{version}/{os}/{arch}?license_id=UUID — serve binary.
func (s *Server) handleDownloadBinary(w http.ResponseWriter, r *http.Request) {
	licenseID := r.URL.Query().Get("license_id")
	if licenseID == "" {
		writeError(w, http.StatusUnauthorized, "license_id query parameter is required")
		return
	}

	// Validate license.
	lic, err := s.store.GetLicense(r.Context(), licenseID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid license")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusForbidden, "license has been revoked")
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		writeError(w, http.StatusForbidden, "license has expired")
		return
	}

	version := chi.URLParam(r, "version")
	goos := chi.URLParam(r, "os")
	goarch := chi.URLParam(r, "arch")

	if !validPathSegments(version, goos, goarch) {
		writeError(w, http.StatusBadRequest, "invalid path parameters")
		return
	}

	dir := filepath.Join(s.config.BinariesDir, version, goos+"-"+goarch)
	metaPath := filepath.Join(dir, "meta.json")

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "binary not found")
		return
	}

	var meta binaryMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		log.Printf("parse meta.json error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Sanitize filename from meta.json to prevent path traversal.
	safeFilename := filepath.Base(meta.Filename)
	binaryPath := filepath.Join(dir, safeFilename)

	f, err := os.Open(binaryPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "binary file missing")
		return
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		log.Printf("stat binary error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.audit(r, "binary_download", licenseID, lic.OrgID, "", map[string]any{
		"version": version, "os": goos, "arch": goarch,
	})

	// Prevent license ID from leaking via Referer header.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeFilename))
	w.Header().Set("X-Checksum-SHA3-256", meta.SHA3)

	// Verify file size matches metadata to detect on-disk tampering.
	if fi.Size() != meta.Size {
		log.Printf("binary size mismatch: meta=%d actual=%d for %s/%s-%s", meta.Size, fi.Size(), version, goos, goarch)
		writeError(w, http.StatusInternalServerError, "binary integrity check failed")
		return
	}

	http.ServeContent(w, r, safeFilename, fi.ModTime(), f)
}

// listBinaries scans the BinariesDir for meta.json sidecars and returns all binaries.
func (s *Server) listBinaries() ([]binaryMeta, error) {
	binaries := make([]binaryMeta, 0)

	if s.config.BinariesDir == "" {
		return binaries, nil
	}

	versionDirs, err := os.ReadDir(s.config.BinariesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return binaries, nil
		}
		return nil, err
	}

	for _, vDir := range versionDirs {
		if !vDir.IsDir() {
			continue
		}
		platformDirs, err := os.ReadDir(filepath.Join(s.config.BinariesDir, vDir.Name()))
		if err != nil {
			continue
		}
		for _, pDir := range platformDirs {
			if !pDir.IsDir() {
				continue
			}
			metaPath := filepath.Join(s.config.BinariesDir, vDir.Name(), pDir.Name(), "meta.json")
			metaBytes, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}
			var meta binaryMeta
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				continue
			}
			binaries = append(binaries, meta)
		}
	}

	sort.Slice(binaries, func(i, j int) bool {
		cmp := compareSemver(binaries[i].Version, binaries[j].Version)
		if cmp != 0 {
			return cmp < 0
		}
		if binaries[i].OS != binaries[j].OS {
			return binaries[i].OS < binaries[j].OS
		}
		return binaries[i].Arch < binaries[j].Arch
	})

	return binaries, nil
}

// atomicWriteFile writes data to a temp file then renames it to the target path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".meta-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // no-op if rename succeeded
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
