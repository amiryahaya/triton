//go:build integration

package licenseserver_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createLicenseForBundle is a helper that creates an org + license and returns
// (tsURL, jwt, licID, binDir). Reuses the setupTestServerWithPublicURL helper from
// handlers_install_test.go which provides PublicURL + BinariesDir.
func createLicenseForBundle(t *testing.T) (tsURL string, jwt string, licID string, binDir string) {
	t.Helper()
	ts, store, bd := setupTestServerWithPublicURL(t)
	jwt = quickAdminJWT(t, ts, store)
	tsURL = ts.URL

	orgResp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/orgs", map[string]string{"name": "BundleOrg"})
	orgResult := decodeJSON(t, orgResp)
	orgID := orgIDOf(orgResult)

	licResp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses", map[string]any{
		"orgID": orgID, "tier": "enterprise", "seats": 5, "days": 365,
	})
	licResult := decodeJSON(t, licResp)
	licID = licResult["id"].(string)
	binDir = bd
	return
}

func TestHandleDownloadBundle_LinuxTarGz(t *testing.T) {
	tsURL, jwt, licID, binDir := createLicenseForBundle(t)

	// Seed a linux/amd64 binary.
	seedBinary(t, binDir, "1.0.0", "linux", "amd64", "fake-triton-linux")

	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "linux", "arch": "amd64", "profile": "comprehensive",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "application/gzip", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Content-Disposition"), ".tar.gz")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	// Read the tar.gz and verify entries.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	gr, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	files := make(map[string]string) // name → content
	modes := make(map[string]int64)  // name → mode
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		files[hdr.Name] = string(data)
		modes[hdr.Name] = hdr.Mode
	}

	// Must contain triton binary, agent.yaml, and install.sh.
	assert.Contains(t, files, "triton")
	assert.Contains(t, files, "agent.yaml")
	assert.Contains(t, files, "install.sh")

	assert.Equal(t, "fake-triton-linux", files["triton"])
	assert.Contains(t, files["agent.yaml"], "license_key:")
	assert.Contains(t, files["agent.yaml"], "profile: \"comprehensive\"")
	assert.Contains(t, files["install.sh"], "#!/usr/bin/env bash")

	// Check permissions.
	assert.Equal(t, int64(0755), modes["triton"])
	assert.Equal(t, int64(0600), modes["agent.yaml"])
	assert.Equal(t, int64(0755), modes["install.sh"])
}

func TestHandleDownloadBundle_WindowsZip(t *testing.T) {
	tsURL, jwt, licID, binDir := createLicenseForBundle(t)

	// Seed a windows/amd64 binary.
	seedBinary(t, binDir, "1.0.0", "windows", "amd64", "fake-triton-windows")

	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "windows", "arch": "amd64",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "application/zip", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Content-Disposition"), ".zip")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	require.NoError(t, err)

	files := make(map[string]string)
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		rc.Close()
		files[f.Name] = string(data)
	}

	assert.Contains(t, files, "triton.exe")
	assert.Contains(t, files, "agent.yaml")
	assert.Contains(t, files, "install.bat")

	assert.Equal(t, "fake-triton-windows", files["triton.exe"])
	assert.Contains(t, files["agent.yaml"], "license_key:")
	// Default profile should be "comprehensive" when empty (spec says default).
	assert.Contains(t, files["agent.yaml"], "profile: \"comprehensive\"")
	assert.Contains(t, files["install.bat"], "@echo off")
}

func TestHandleDownloadBundle_NoBinaryAvailable(t *testing.T) {
	tsURL, jwt, licID, _ := createLicenseForBundle(t)

	// No binaries seeded — request darwin/arm64.
	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "darwin", "arch": "arm64",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Contains(t, result["error"].(string), "no binary available")
}

func TestHandleDownloadBundle_RevokedLicense(t *testing.T) {
	tsURL, jwt, licID, binDir := createLicenseForBundle(t)

	seedBinary(t, binDir, "1.0.0", "linux", "amd64", "fake-triton")

	// Revoke the license.
	revokeResp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/revoke", nil)
	revokeResp.Body.Close()

	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "linux", "arch": "amd64",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleDownloadBundle_InvalidOS(t *testing.T) {
	tsURL, jwt, licID, _ := createLicenseForBundle(t)

	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "freebsd", "arch": "amd64",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleDownloadBundle_WindowsArm64Unsupported(t *testing.T) {
	tsURL, jwt, licID, _ := createLicenseForBundle(t)

	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "windows", "arch": "arm64",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleDownloadBundle_DefaultProfile(t *testing.T) {
	tsURL, jwt, licID, binDir := createLicenseForBundle(t)

	seedBinary(t, binDir, "1.0.0", "linux", "amd64", "fake-triton")

	// Empty profile should default to "comprehensive".
	resp := adminReq(t, jwt, "POST", tsURL+"/api/v1/admin/licenses/"+licID+"/bundle", map[string]any{
		"os": "linux", "arch": "amd64",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	gr, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "agent.yaml" {
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			assert.Contains(t, string(data), `profile: "comprehensive"`)
			return
		}
	}
	t.Fatal("agent.yaml not found in archive")
}
