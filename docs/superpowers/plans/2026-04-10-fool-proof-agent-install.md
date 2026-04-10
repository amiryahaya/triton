# Fool-Proof Agent Installation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A non-technical operator installs the Triton agent on any machine by pasting one command or unzipping one bundle — no terminal expertise, no manual file placement, no "which binary do I download?" confusion.

**Architecture:** The license server gains two new capabilities: (1) a **bundle endpoint** that packages the correct platform binary + agent.yaml + install script into a single archive, and (2) a **one-liner install endpoint** that serves a platform-detecting shell script callable via `curl | sudo bash`. Both are backed by HMAC-signed short-lived install tokens so the URL the admin shares with the operator carries authorization without exposing the admin API key. The admin UI gets a platform picker dropdown and a "Copy install command" button alongside the existing "Download agent.yaml" button.

**Tech Stack:** Go (chi router, crypto/hmac, archive/zip, archive/tar, text/template), vanilla JS (admin UI), bash/PowerShell (install scripts)

**Installation paths (locked in):**
- Linux/macOS: `/opt/triton/` (binary + agent.yaml + reports/)
- Windows: `C:\Program Files\Triton\` (binary + agent.yaml + reports\)

---

## File Structure

### New files
| File | Responsibility |
|------|---------------|
| `pkg/licenseserver/install_token.go` | HMAC-signed install token: generate, validate, encode/decode |
| `pkg/licenseserver/install_token_test.go` | Token generation, validation, expiry, tampering tests |
| `pkg/licenseserver/handlers_install.go` | HTTP handlers: one-liner script, binary download, agent.yaml download (all token-authed) |
| `pkg/licenseserver/handlers_install_test.go` | Handler tests: script rendering, binary serving, agent.yaml serving, error paths |
| `pkg/licenseserver/handlers_bundle.go` | HTTP handler: admin-authed bundle download (zip/tarball) |
| `pkg/licenseserver/handlers_bundle_test.go` | Bundle handler tests: archive contents, platform validation, error paths |
| `pkg/licenseserver/install_scripts.go` | Embedded install script templates (bash + PowerShell) as Go constants |

### Modified files
| File | Change |
|------|--------|
| `pkg/licenseserver/server.go` | Add bundle + install routes |
| `pkg/licenseserver/config.go` | Add `PublicURL string` field (license server's own external URL for install callbacks) |
| `cmd/licenseserver/main.go` | Read `TRITON_LICENSE_SERVER_PUBLIC_URL` env var, pass to config |
| `pkg/licenseserver/ui/dist/admin.js` | Platform picker dropdown, bundle download button, copy install command button on license detail page |

---

## Task 1: Install Token — Generation and Validation

HMAC-signed, stateless, short-lived tokens that authorize an install without exposing the admin API key. The admin generates one from the UI; the operator pastes the resulting URL into their terminal.

**Token format:** `base64url(payload).base64url(HMAC-SHA256(payload, secret))`

Payload is JSON: `{"lid":"<license-id>","exp":<unix-timestamp>}`

The HMAC secret is derived from the Ed25519 signing key's seed (first 32 bytes) — no additional config needed.

**Files:**
- Create: `pkg/licenseserver/install_token.go`
- Create: `pkg/licenseserver/install_token_test.go`

- [ ] **Step 1: Write failing tests for token generation and validation**

```go
// pkg/licenseserver/install_token_test.go
package licenseserver

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return priv
}

func TestInstallToken_RoundTrip(t *testing.T) {
	key := testSigningKey(t)
	licenseID := "019d72f8-166a-7e5c-b132-1d48d2d5d4ec"
	ttl := 24 * time.Hour

	token, err := GenerateInstallToken(key.Seed(), licenseID, ttl)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := ValidateInstallToken(key.Seed(), token)
	require.NoError(t, err)
	assert.Equal(t, licenseID, claims.LicenseID)
}

func TestInstallToken_Expired(t *testing.T) {
	key := testSigningKey(t)
	token, err := GenerateInstallToken(key.Seed(), "some-id", -1*time.Hour)
	require.NoError(t, err)

	_, err = ValidateInstallToken(key.Seed(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestInstallToken_Tampered(t *testing.T) {
	key := testSigningKey(t)
	token, err := GenerateInstallToken(key.Seed(), "some-id", 24*time.Hour)
	require.NoError(t, err)

	// Flip a character in the payload portion
	tampered := []byte(token)
	if tampered[0] == 'a' {
		tampered[0] = 'b'
	} else {
		tampered[0] = 'a'
	}

	_, err = ValidateInstallToken(key.Seed(), string(tampered))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestInstallToken_WrongKey(t *testing.T) {
	key1 := testSigningKey(t)
	key2 := testSigningKey(t)

	token, err := GenerateInstallToken(key1.Seed(), "some-id", 24*time.Hour)
	require.NoError(t, err)

	_, err = ValidateInstallToken(key2.Seed(), token)
	require.Error(t, err)
}

func TestInstallToken_EmptyLicenseID(t *testing.T) {
	key := testSigningKey(t)
	_, err := GenerateInstallToken(key.Seed(), "", 24*time.Hour)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestInstallToken ./pkg/licenseserver/...`
Expected: FAIL — `GenerateInstallToken` and `ValidateInstallToken` undefined

- [ ] **Step 3: Implement install token**

```go
// pkg/licenseserver/install_token.go
package licenseserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// installTokenClaims is the payload embedded in an install token.
type installTokenClaims struct {
	LicenseID string `json:"lid"`
	ExpiresAt int64  `json:"exp"`
}

// GenerateInstallToken creates an HMAC-signed install token that
// authorizes downloading the agent bundle for the given license.
// The token is stateless — no DB storage required — and expires
// after ttl. The hmacSecret should be the Ed25519 signing key's
// 32-byte seed.
func GenerateInstallToken(hmacSecret []byte, licenseID string, ttl time.Duration) (string, error) {
	if licenseID == "" {
		return "", errors.New("license ID is required")
	}
	claims := installTokenClaims{
		LicenseID: licenseID,
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := hmacSign(hmacSecret, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return payloadB64 + "." + sigB64, nil
}

// ValidateInstallToken verifies the HMAC signature and expiry of
// an install token. Returns the decoded claims on success.
func ValidateInstallToken(hmacSecret []byte, token string) (*installTokenClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid install token format")
	}
	payloadB64, sigB64 := parts[0], parts[1]

	// Verify HMAC
	expectedSig := hmacSign(hmacSecret, []byte(payloadB64))
	actualSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("invalid install token signature encoding")
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, errors.New("invalid install token signature")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("invalid install token payload encoding")
	}
	var claims installTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid install token payload: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("install token expired")
	}
	return &claims, nil
}

func hmacSign(secret, message []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestInstallToken ./pkg/licenseserver/...`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/licenseserver/install_token.go pkg/licenseserver/install_token_test.go
git commit -m "feat(licenseserver): HMAC-signed install tokens for agent installation"
```

---

## Task 2: Install Script Templates

Embedded bash and PowerShell scripts rendered as Go templates. Two variants each: **bundled** (runs from inside an extracted archive) and **one-liner** (downloads everything on the fly).

**Files:**
- Create: `pkg/licenseserver/install_scripts.go`

- [ ] **Step 1: Create the install scripts file with all four templates**

```go
// pkg/licenseserver/install_scripts.go
package licenseserver

// bundledInstallSh is the install script included in Linux/macOS
// bundle archives. It assumes triton and agent.yaml are in the
// same directory as the script.
const bundledInstallSh = `#!/bin/bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "  ERROR: This installer must be run as root."
    echo ""
    echo "  Run:  sudo bash install.sh"
    echo ""
    exit 1
fi

INSTALL_DIR="/opt/triton"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  Triton Agent Installer"
echo "  ======================"
echo ""
echo "  Install directory: $INSTALL_DIR"
echo ""

# Verify bundle contents
if [ ! -f "$SCRIPT_DIR/triton" ]; then
    echo "ERROR: 'triton' binary not found in $SCRIPT_DIR"
    echo "       Make sure you extracted the full archive."
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/agent.yaml" ]; then
    echo "ERROR: 'agent.yaml' not found in $SCRIPT_DIR"
    echo "       Make sure you extracted the full archive."
    exit 1
fi

# Create install directory
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/reports"

# Copy files
cp "$SCRIPT_DIR/triton" "$INSTALL_DIR/triton"
cp "$SCRIPT_DIR/agent.yaml" "$INSTALL_DIR/agent.yaml"

# Set permissions — binary is world-executable, config is root-only
chmod 755 "$INSTALL_DIR/triton"
chmod 600 "$INSTALL_DIR/agent.yaml"

# macOS: remove quarantine attribute so Gatekeeper doesn't block
if [ "$(uname)" = "Darwin" ]; then
    xattr -d com.apple.quarantine "$INSTALL_DIR/triton" 2>/dev/null || true
fi

# Verify the installation works
echo "  Verifying installation..."
echo ""
"$INSTALL_DIR/triton" agent --check-config
echo ""
echo "  Installation complete!"
echo ""
echo "  To run a scan:   sudo /opt/triton/triton agent"
echo "  To uninstall:    sudo rm -rf /opt/triton"
echo ""
`

// bundledInstallBat is the install script included in Windows
// bundle archives. Must be run as Administrator.
const bundledInstallBat = `@echo off
setlocal

:: Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   ERROR: This installer must be run as Administrator.
    echo.
    echo   Right-click install.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

set INSTALL_DIR=C:\Program Files\Triton
set SCRIPT_DIR=%~dp0

echo.
echo   Triton Agent Installer
echo   ======================
echo.
echo   Install directory: %INSTALL_DIR%
echo.

:: Verify bundle contents
if not exist "%SCRIPT_DIR%triton.exe" (
    echo ERROR: triton.exe not found in %SCRIPT_DIR%
    echo        Make sure you extracted the full archive.
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%agent.yaml" (
    echo ERROR: agent.yaml not found in %SCRIPT_DIR%
    echo        Make sure you extracted the full archive.
    pause
    exit /b 1
)

:: Create install directory
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\reports" mkdir "%INSTALL_DIR%\reports"

:: Copy files
copy /Y "%SCRIPT_DIR%triton.exe" "%INSTALL_DIR%\triton.exe" >nul
copy /Y "%SCRIPT_DIR%agent.yaml" "%INSTALL_DIR%\agent.yaml" >nul

:: Restrict agent.yaml to Administrators only
icacls "%INSTALL_DIR%\agent.yaml" /inheritance:r /grant:r "BUILTIN\Administrators:(R)" >nul 2>&1

:: Verify
echo   Verifying installation...
echo.
"%INSTALL_DIR%\triton.exe" agent --check-config
echo.
echo   Installation complete!
echo.
echo   To run a scan:   "%INSTALL_DIR%\triton.exe" agent
echo   To uninstall:    rmdir /s /q "%INSTALL_DIR%"
echo.
pause
`

// onelinerInstallSh is the shell script served by the one-liner
// install endpoint. It auto-detects the platform, downloads the
// binary and agent.yaml from the license server, and installs.
// Rendered as a Go text/template with {{.BaseURL}} and {{.Token}}.
const onelinerInstallSh = `#!/bin/bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "  ERROR: This installer must be run as root."
    echo ""
    echo "  Re-run with:  curl -sSL '{{.ScriptURL}}' | sudo bash"
    echo ""
    exit 1
fi

# Detect platform
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

INSTALL_DIR="/opt/triton"
BASE="{{.BaseURL}}"
TOKEN="{{.Token}}"

echo ""
echo "  Triton Agent Installer"
echo "  ======================"
echo ""
echo "  Platform:  ${OS}/${ARCH}"
echo "  Install:   ${INSTALL_DIR}"
echo ""

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Download binary
echo "  Downloading triton binary..."
HTTP_CODE=$(curl -sSL -w "%{http_code}" -o "$TMP/triton" \
    "${BASE}/api/v1/install/${TOKEN}/binary/${OS}/${ARCH}")
if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Binary download failed (HTTP $HTTP_CODE)"
    echo "       The install link may have expired. Ask your admin for a new one."
    exit 1
fi

# Download agent.yaml
echo "  Downloading agent configuration..."
HTTP_CODE=$(curl -sSL -w "%{http_code}" -o "$TMP/agent.yaml" \
    "${BASE}/api/v1/install/${TOKEN}/agent-yaml")
if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Config download failed (HTTP $HTTP_CODE)"
    exit 1
fi

# Install
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/reports"
cp "$TMP/triton" "$INSTALL_DIR/triton"
cp "$TMP/agent.yaml" "$INSTALL_DIR/agent.yaml"
chmod 755 "$INSTALL_DIR/triton"
chmod 600 "$INSTALL_DIR/agent.yaml"

# macOS: remove quarantine
if [ "$OS" = "darwin" ]; then
    xattr -d com.apple.quarantine "$INSTALL_DIR/triton" 2>/dev/null || true
fi

# Verify
echo ""
"$INSTALL_DIR/triton" agent --check-config
echo ""
echo "  Installation complete!"
echo ""
echo "  To run a scan:   sudo /opt/triton/triton agent"
echo "  To uninstall:    sudo rm -rf /opt/triton"
echo ""
`

// onelinerInstallPs1 is the PowerShell script served for Windows
// one-liner installs. Rendered as a Go text/template.
const onelinerInstallPs1 = `#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  ERROR: This installer must be run as Administrator."
    Write-Host ""
    Write-Host "  Right-click PowerShell -> 'Run as Administrator', then paste the command again."
    Write-Host ""
    exit 1
}

$InstallDir = "C:\Program Files\Triton"
$Base = "{{.BaseURL}}"
$Token = "{{.Token}}"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "amd64" }

Write-Host ""
Write-Host "  Triton Agent Installer"
Write-Host "  ======================"
Write-Host ""
Write-Host "  Platform:  windows/$Arch"
Write-Host "  Install:   $InstallDir"
Write-Host ""

$Tmp = Join-Path $env:TEMP "triton-install-$(Get-Random)"
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

try {
    Write-Host "  Downloading triton binary..."
    Invoke-WebRequest -Uri "$Base/api/v1/install/$Token/binary/windows/$Arch" -OutFile "$Tmp\triton.exe" -UseBasicParsing

    Write-Host "  Downloading agent configuration..."
    Invoke-WebRequest -Uri "$Base/api/v1/install/$Token/agent-yaml" -OutFile "$Tmp\agent.yaml" -UseBasicParsing

    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    if (-not (Test-Path "$InstallDir\reports")) { New-Item -ItemType Directory -Path "$InstallDir\reports" -Force | Out-Null }

    Copy-Item "$Tmp\triton.exe" "$InstallDir\triton.exe" -Force
    Copy-Item "$Tmp\agent.yaml" "$InstallDir\agent.yaml" -Force

    # Restrict agent.yaml to Administrators
    $acl = Get-Acl "$InstallDir\agent.yaml"
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "Read", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl "$InstallDir\agent.yaml" $acl

    Write-Host ""
    & "$InstallDir\triton.exe" agent --check-config
    Write-Host ""
    Write-Host "  Installation complete!"
    Write-Host ""
    Write-Host "  To run a scan:   & '$InstallDir\triton.exe' agent"
    Write-Host "  To uninstall:    Remove-Item -Recurse -Force '$InstallDir'"
    Write-Host ""
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
`
```

- [ ] **Step 2: Verify the file compiles**

Run: `go build ./pkg/licenseserver/...`
Expected: PASS (no compilation errors — these are just string constants)

- [ ] **Step 3: Commit**

```bash
git add pkg/licenseserver/install_scripts.go
git commit -m "feat(licenseserver): embedded install script templates for bundled + one-liner flows"
```

---

## Task 3: Config — Add PublicURL for Install Callbacks

The one-liner install script needs to call back to the license server to download the binary and agent.yaml. It needs the license server's own external URL (not the report server's).

**Files:**
- Modify: `pkg/licenseserver/config.go`
- Modify: `cmd/licenseserver/main.go`

- [ ] **Step 1: Add PublicURL to Config**

In `pkg/licenseserver/config.go`, add after `ReportServerPublicURL`:

```go
	// PublicURL is the customer-facing URL of this license server
	// itself. Used by install scripts that call back to download
	// binaries and agent.yaml. When empty, install-token features
	// are disabled (the admin UI hides the "Copy install command"
	// button). Example: "https://license.example.com"
	PublicURL string
```

- [ ] **Step 2: Read the env var in main.go**

In `cmd/licenseserver/main.go`, find where `reportServerPublicURL` is read and add nearby:

```go
	publicURL := envOr("TRITON_LICENSE_SERVER_PUBLIC_URL", "")
```

Then pass it into the config struct:

```go
	PublicURL:              publicURL,
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./cmd/licenseserver/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/licenseserver/config.go cmd/licenseserver/main.go
git commit -m "feat(licenseserver): add PublicURL config for install script callbacks"
```

---

## Task 4: Install Handlers — One-Liner Endpoint

Three sub-endpoints under `/api/v1/install/{token}/`:
- `GET /` — serves the platform-detecting install shell script
- `GET /binary/{os}/{arch}` — serves the binary (token-authed, no admin key)
- `GET /agent-yaml` — serves agent.yaml for the token's license (token-authed)

**Files:**
- Create: `pkg/licenseserver/handlers_install.go`
- Create: `pkg/licenseserver/handlers_install_test.go`
- Modify: `pkg/licenseserver/server.go` (add routes)

- [ ] **Step 1: Write failing tests for the install script endpoint**

```go
// pkg/licenseserver/handlers_install_test.go
package licenseserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleInstallScript_ValidToken(t *testing.T) {
	srv, _ := newTestServerWithBinaries(t) // helper from existing test infra
	token := srv.generateTestInstallToken(t, "test-license-id")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token, nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, rec.Body.String(), "Triton Agent Installer")
	assert.Contains(t, rec.Body.String(), token) // token embedded in script
}

func TestHandleInstallScript_ExpiredToken(t *testing.T) {
	srv, _ := newTestServerWithBinaries(t)
	token, err := GenerateInstallToken(srv.config.SigningKey.Seed(), "test-id", -1*time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token, nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "expired")
}

func TestHandleInstallBinary_ValidToken(t *testing.T) {
	srv, _ := newTestServerWithBinaries(t) // seeds a linux/amd64 binary
	token := srv.generateTestInstallToken(t, "test-license-id")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token+"/binary/linux/amd64", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.NotEmpty(t, rec.Body.Bytes())
}

func TestHandleInstallBinary_UnsupportedPlatform(t *testing.T) {
	srv, _ := newTestServerWithBinaries(t)
	token := srv.generateTestInstallToken(t, "test-license-id")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token+"/binary/freebsd/mips", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleInstallAgentYAML_ValidToken(t *testing.T) {
	srv, _ := newTestServerWithLicense(t) // seeds an org + license
	token := srv.generateTestInstallToken(t, srv.testLicenseID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token+"/agent-yaml", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "license_key:")
	assert.Contains(t, rec.Body.String(), "report_server:")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestHandleInstall ./pkg/licenseserver/...`
Expected: FAIL — handlers not defined

- [ ] **Step 3: Implement the install handlers**

```go
// pkg/licenseserver/handlers_install.go
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

const installTokenTTL = 24 * time.Hour

// handleGenerateInstallToken creates a short-lived install token
// for a license. Admin-authed (called from the UI).
// POST /api/v1/admin/licenses/{id}/install-token
func (s *Server) handleGenerateInstallToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "license ID is required")
		return
	}
	if s.config.PublicURL == "" {
		writeError(w, http.StatusServiceUnavailable,
			"TRITON_LICENSE_SERVER_PUBLIC_URL is not configured — install links cannot be generated")
		return
	}

	// Verify license exists and is active
	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "cannot generate install token for a revoked license")
		return
	}
	if lic.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "cannot generate install token for an expired license")
		return
	}

	token, err := GenerateInstallToken(s.config.SigningKey.Seed(), id, installTokenTTL)
	if err != nil {
		log.Printf("install-token: generate error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate install token")
		return
	}

	baseURL := strings.TrimRight(s.config.PublicURL, "/")
	curlCmd := fmt.Sprintf("curl -sSL '%s/api/v1/install/%s' | sudo bash", baseURL, token)
	ps1Cmd := fmt.Sprintf("irm '%s/api/v1/install/%s?shell=ps1' | iex", baseURL, token)

	s.audit(r, "license_generate_install_token", id, "", "", nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":       token,
		"expires_in":  int(installTokenTTL.Seconds()),
		"curl_command": curlCmd,
		"ps1_command":  ps1Cmd,
	})
}

// handleInstallScript serves the platform-detecting install script.
// Token-authed (no admin key needed — the URL IS the credential).
// GET /api/v1/install/{token}
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	claims, err := ValidateInstallToken(s.config.SigningKey.Seed(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}
	_ = claims // token is valid — we just need it for auth

	baseURL := strings.TrimRight(s.config.PublicURL, "/")
	scriptURL := fmt.Sprintf("%s/api/v1/install/%s", baseURL, token)

	// Serve PowerShell if requested, otherwise bash
	shell := r.URL.Query().Get("shell")
	if shell == "ps1" {
		tmpl, err := template.New("ps1").Parse(onelinerInstallPs1)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "template error")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_ = tmpl.Execute(w, map[string]string{
			"BaseURL":   baseURL,
			"Token":     token,
			"ScriptURL": scriptURL,
		})
		return
	}

	tmpl, err := template.New("sh").Parse(onelinerInstallSh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "template error")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_ = tmpl.Execute(w, map[string]string{
		"BaseURL":   baseURL,
		"Token":     token,
		"ScriptURL": scriptURL,
	})
}

// handleInstallBinary serves the agent binary for the given platform.
// Token-authed.
// GET /api/v1/install/{token}/binary/{os}/{arch}
func (s *Server) handleInstallBinary(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if _, err := ValidateInstallToken(s.config.SigningKey.Seed(), token); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	osName := chi.URLParam(r, "os")
	arch := chi.URLParam(r, "arch")

	binName := "triton"
	if osName == "windows" {
		binName = "triton.exe"
	}

	// Find the latest version available
	binaries, err := listBinaries(s.config.BinariesDir)
	if err != nil || len(binaries) == 0 {
		writeError(w, http.StatusNotFound, "no binaries available")
		return
	}
	// binaries are sorted by version descending, first is latest
	var binaryPath string
	for _, b := range binaries {
		if b.OS == osName && b.Arch == arch {
			binaryPath = filepath.Join(s.config.BinariesDir, b.Version, osName+"-"+arch, binName)
			break
		}
	}
	if binaryPath == "" {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("no binary available for %s/%s", osName, arch))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, binName))
	http.ServeFile(w, r, binaryPath)
}

// handleInstallAgentYAML serves agent.yaml for the token's license.
// Token-authed.
// GET /api/v1/install/{token}/agent-yaml
func (s *Server) handleInstallAgentYAML(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	claims, err := ValidateInstallToken(s.config.SigningKey.Seed(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	lic, err := s.store.GetLicense(r.Context(), claims.LicenseID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusGone, "license has been revoked")
		return
	}

	signedToken, err := s.signToken(lic, "")
	if err != nil {
		log.Printf("install-agent-yaml: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to sign license token")
		return
	}

	var reportServer string
	switch {
	case s.config.ReportServerPublicURL != "":
		reportServer = s.config.ReportServerPublicURL
	case s.config.ReportServerURL != "":
		reportServer = s.config.ReportServerURL
	}

	yamlBody := buildAgentYAML(agentYAMLParams{
		LicenseID:     lic.ID,
		OrgName:       lic.OrgName,
		Tier:          lic.Tier,
		Seats:         lic.Seats,
		ExpiresAt:     lic.ExpiresAt,
		MachineBinding: "",
		Token:         signedToken,
		ReportServer:  reportServer,
		Profile:       "comprehensive",
	})

	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(yamlBody))
}
```

- [ ] **Step 4: Register the routes in server.go**

In `pkg/licenseserver/server.go`, add inside the admin route group (after the existing `agent-yaml` route):

```go
		r.Post("/licenses/{id}/install-token", srv.handleGenerateInstallToken)
```

Add a new public route group (outside admin, no admin key required):

```go
	// Install endpoints — token-authed (the URL is the credential).
	// No admin key or license activation required. The HMAC token
	// in the URL path carries authorization.
	r.Route("/api/v1/install/{token}", func(r chi.Router) {
		r.Get("/", srv.handleInstallScript)
		r.Get("/binary/{os}/{arch}", srv.handleInstallBinary)
		r.Get("/agent-yaml", srv.handleInstallAgentYAML)
	})
```

- [ ] **Step 5: Run tests**

Run: `go test -v -run TestHandleInstall ./pkg/licenseserver/...`
Expected: PASS (adjust test helpers as needed to seed test data)

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/handlers_install.go pkg/licenseserver/handlers_install_test.go pkg/licenseserver/server.go
git commit -m "feat(licenseserver): one-liner install endpoint with token-authed binary + agent.yaml download"
```

---

## Task 5: Bundle Download Handler

Admin endpoint that packages binary + agent.yaml + install script into a single archive. ZIP for Windows, tar.gz for Linux/macOS.

**Files:**
- Create: `pkg/licenseserver/handlers_bundle.go`
- Create: `pkg/licenseserver/handlers_bundle_test.go`
- Modify: `pkg/licenseserver/server.go` (add route)

- [ ] **Step 1: Write failing tests**

```go
// pkg/licenseserver/handlers_bundle_test.go
package licenseserver

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleDownloadBundle_LinuxTarGz(t *testing.T) {
	srv, _ := newTestServerWithLicenseAndBinaries(t, "linux", "amd64")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/licenses/"+srv.testLicenseID+"/bundle",
		strings.NewReader(`{"os":"linux","arch":"amd64"}`))
	req.Header.Set("X-Triton-Admin-Key", srv.adminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), ".tar.gz")

	// Verify archive contents
	gr, err := gzip.NewReader(rec.Body)
	require.NoError(t, err)
	tr := tar.NewReader(gr)
	files := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		files[hdr.Name] = true
	}
	assert.True(t, files["triton"], "archive must contain the binary")
	assert.True(t, files["agent.yaml"], "archive must contain agent.yaml")
	assert.True(t, files["install.sh"], "archive must contain install script")
}

func TestHandleDownloadBundle_WindowsZip(t *testing.T) {
	srv, _ := newTestServerWithLicenseAndBinaries(t, "windows", "amd64")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/licenses/"+srv.testLicenseID+"/bundle",
		strings.NewReader(`{"os":"windows","arch":"amd64"}`))
	req.Header.Set("X-Triton-Admin-Key", srv.adminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Disposition"), ".zip")

	// Verify archive contents
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	require.NoError(t, err)
	files := map[string]bool{}
	for _, f := range zr.File {
		files[f.Name] = true
	}
	assert.True(t, files["triton.exe"], "archive must contain the binary")
	assert.True(t, files["agent.yaml"], "archive must contain agent.yaml")
	assert.True(t, files["install.bat"], "archive must contain install script")
}

func TestHandleDownloadBundle_NoBinaryAvailable(t *testing.T) {
	srv, _ := newTestServerWithLicenseAndBinaries(t, "linux", "amd64")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/licenses/"+srv.testLicenseID+"/bundle",
		strings.NewReader(`{"os":"darwin","arch":"arm64"}`))
	req.Header.Set("X-Triton-Admin-Key", srv.adminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "no binary available")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestHandleDownloadBundle ./pkg/licenseserver/...`
Expected: FAIL

- [ ] **Step 3: Implement the bundle handler**

```go
// pkg/licenseserver/handlers_bundle.go
package licenseserver

import (
	"archive/tar"
	"archive/zip"
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

type bundleRequest struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Profile string `json:"profile,omitempty"`
}

// handleDownloadBundle generates a single archive containing the
// agent binary + agent.yaml + install script for a given platform.
// POST /api/v1/admin/licenses/{id}/bundle
func (s *Server) handleDownloadBundle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "license ID is required")
		return
	}

	var req bundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validOS := map[string]bool{"linux": true, "darwin": true, "windows": true}
	validArch := map[string]bool{"amd64": true, "arm64": true}
	if !validOS[req.OS] {
		writeError(w, http.StatusBadRequest, "os must be linux, darwin, or windows")
		return
	}
	if !validArch[req.Arch] {
		writeError(w, http.StatusBadRequest, "arch must be amd64 or arm64")
		return
	}
	if req.OS == "windows" && req.Arch == "arm64" {
		writeError(w, http.StatusBadRequest, "windows/arm64 is not supported")
		return
	}

	profile := req.Profile
	if profile == "" {
		profile = "comprehensive"
	}

	// Look up the license (same validation as agent-yaml endpoint)
	lic, err := s.store.GetLicense(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("bundle: get license error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if lic.Revoked {
		writeError(w, http.StatusBadRequest, "cannot generate bundle for a revoked license")
		return
	}
	if lic.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "cannot generate bundle for an expired license")
		return
	}

	// Find the binary
	binName := "triton"
	if req.OS == "windows" {
		binName = "triton.exe"
	}
	binaries, err := listBinaries(s.config.BinariesDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list binaries")
		return
	}
	var binaryPath string
	var binaryVersion string
	for _, b := range binaries {
		if b.OS == req.OS && b.Arch == req.Arch {
			binaryPath = filepath.Join(s.config.BinariesDir, b.Version, req.OS+"-"+req.Arch, binName)
			binaryVersion = b.Version
			break
		}
	}
	if binaryPath == "" {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("no binary available for %s/%s — upload one first via POST /api/v1/admin/binaries", req.OS, req.Arch))
		return
	}

	// Generate agent.yaml
	signedToken, err := s.signToken(lic, "")
	if err != nil {
		log.Printf("bundle: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to sign license token")
		return
	}
	var reportServer string
	switch {
	case s.config.ReportServerPublicURL != "":
		reportServer = s.config.ReportServerPublicURL
	case s.config.ReportServerURL != "":
		reportServer = s.config.ReportServerURL
	}
	yamlBody := buildAgentYAML(agentYAMLParams{
		LicenseID:      lic.ID,
		OrgName:        lic.OrgName,
		Tier:           lic.Tier,
		Seats:          lic.Seats,
		ExpiresAt:      lic.ExpiresAt,
		MachineBinding: "",
		Token:          signedToken,
		ReportServer:   reportServer,
		Profile:        profile,
	})

	// Pick the right install script
	var installScript string
	var installFilename string
	if req.OS == "windows" {
		installScript = bundledInstallBat
		installFilename = "install.bat"
	} else {
		installScript = bundledInstallSh
		installFilename = "install.sh"
	}

	// Audit
	s.audit(r, "license_download_bundle", id, "", "", map[string]any{
		"os": req.OS, "arch": req.Arch, "version": binaryVersion, "profile": profile,
	})

	archiveName := fmt.Sprintf("triton-%s-%s-%s", binaryVersion, req.OS, req.Arch)

	if req.OS == "windows" {
		s.serveZipBundle(w, archiveName, binaryPath, binName, yamlBody, installScript, installFilename)
	} else {
		s.serveTarGzBundle(w, archiveName, binaryPath, binName, yamlBody, installScript, installFilename)
	}
}

func (s *Server) serveTarGzBundle(w http.ResponseWriter, archiveName, binaryPath, binName, yamlBody, installScript, installFilename string) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, archiveName+".tar.gz"))
	w.Header().Set("Cache-Control", "no-store")

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add binary
	binFile, err := os.Open(binaryPath)
	if err != nil {
		return
	}
	defer binFile.Close()
	binStat, _ := binFile.Stat()
	_ = tw.WriteHeader(&tar.Header{
		Name: binName, Size: binStat.Size(), Mode: 0755, ModTime: binStat.ModTime(),
	})
	_, _ = io.Copy(tw, binFile)

	// Add agent.yaml
	_ = tw.WriteHeader(&tar.Header{
		Name: "agent.yaml", Size: int64(len(yamlBody)), Mode: 0600, ModTime: time.Now(),
	})
	_, _ = tw.Write([]byte(yamlBody))

	// Add install script
	_ = tw.WriteHeader(&tar.Header{
		Name: installFilename, Size: int64(len(installScript)), Mode: 0755, ModTime: time.Now(),
	})
	_, _ = tw.Write([]byte(installScript))
}

func (s *Server) serveZipBundle(w http.ResponseWriter, archiveName, binaryPath, binName, yamlBody, installScript, installFilename string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, archiveName+".zip"))
	w.Header().Set("Cache-Control", "no-store")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Add binary
	binFile, _ := os.Open(binaryPath)
	defer binFile.Close()
	binStat, _ := binFile.Stat()
	bw, _ := zw.CreateHeader(&zip.FileHeader{
		Name: binName, Method: zip.Store,
		Modified: binStat.ModTime(),
	})
	_, _ = io.Copy(bw, binFile)

	// Add agent.yaml
	yw, _ := zw.Create("agent.yaml")
	_, _ = yw.Write([]byte(yamlBody))

	// Add install script
	iw, _ := zw.Create(installFilename)
	_, _ = iw.Write([]byte(installScript))
}
```

- [ ] **Step 4: Register the route in server.go**

In the admin route group, add after `install-token`:

```go
		r.Post("/licenses/{id}/bundle", srv.handleDownloadBundle)
```

- [ ] **Step 5: Run tests**

Run: `go test -v -run TestHandleDownloadBundle ./pkg/licenseserver/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/licenseserver/handlers_bundle.go pkg/licenseserver/handlers_bundle_test.go pkg/licenseserver/server.go
git commit -m "feat(licenseserver): bundle download endpoint — binary + agent.yaml + install script in one archive"
```

---

## Task 6: Admin UI — Platform Picker, Bundle Download, Copy Install Command

Update the license detail page to replace the single "Download agent.yaml" button with a richer installation section.

**Files:**
- Modify: `pkg/licenseserver/ui/dist/admin.js`

- [ ] **Step 1: Replace the download button section in the license detail page**

Find the existing "Download agent.yaml" button markup in `admin.js` (around line 334) and replace with the new installation section. The new UI has:

1. **Platform dropdown** (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
2. **"Download bundle"** button — triggers `POST /api/v1/admin/licenses/{id}/bundle` with the selected platform
3. **"Download agent.yaml only"** button — keeps the existing behavior for admins who want just the config
4. **"Copy install command"** button — calls `POST /api/v1/admin/licenses/{id}/install-token` and copies the curl one-liner to clipboard. Shows a tooltip/flash "Copied!" on success. Disabled when `PublicURL` is not configured (the endpoint returns 503).

The HTML block to insert (replacing the existing button):

```javascript
// Installation section
'<div class="card" style="margin-top:1.5em">' +
'  <div class="card-header"><strong>Agent Installation</strong></div>' +
'  <div class="card-body">' +
'    <div style="margin-bottom:1em">' +
'      <label for="platform-select" style="font-weight:600">Target platform:</label>' +
'      <select id="platform-select" class="form-control" style="width:auto;display:inline-block;margin-left:0.5em">' +
'        <option value="linux-amd64">Linux (Intel/AMD 64-bit)</option>' +
'        <option value="linux-arm64">Linux (ARM 64-bit)</option>' +
'        <option value="darwin-amd64">macOS (Intel)</option>' +
'        <option value="darwin-arm64" selected>macOS (Apple Silicon)</option>' +
'        <option value="windows-amd64">Windows (64-bit)</option>' +
'      </select>' +
'    </div>' +
'    <div style="display:flex;gap:0.75em;flex-wrap:wrap">' +
'      <button class="btn btn-primary" id="download-bundle-btn">' +
'        Download bundle' +
'      </button>' +
'      <button class="btn btn-outline-secondary" id="download-agent-yaml-btn">' +
'        Download agent.yaml only' +
'      </button>' +
'      <button class="btn btn-outline-secondary" id="copy-install-cmd-btn">' +
'        Copy install command' +
'      </button>' +
'    </div>' +
'    <div id="install-cmd-display" style="display:none;margin-top:1em">' +
'      <label style="font-weight:600">Linux/macOS:</label>' +
'      <pre id="install-cmd-curl" style="background:#1a1a2e;color:#e0e0e0;padding:0.75em;border-radius:4px;cursor:pointer;user-select:all"></pre>' +
'      <label style="font-weight:600">Windows (PowerShell as Admin):</label>' +
'      <pre id="install-cmd-ps1" style="background:#1a1a2e;color:#e0e0e0;padding:0.75em;border-radius:4px;cursor:pointer;user-select:all"></pre>' +
'      <small class="text-muted">This link expires in 24 hours. Generate a new one if needed.</small>' +
'    </div>' +
'  </div>' +
'</div>'
```

Wire the bundle download button:

```javascript
document.getElementById('download-bundle-btn').onclick = async function() {
    var btn = this;
    var sel = document.getElementById('platform-select').value;
    var parts = sel.split('-');
    var os = parts[0], arch = parts[1];
    btn.disabled = true;
    btn.textContent = 'Generating bundle...';
    try {
        var resp = await fetch('/api/v1/admin/licenses/' + encodeURIComponent(id) + '/bundle', {
            method: 'POST',
            headers: {'X-Triton-Admin-Key': adminKey, 'Content-Type': 'application/json'},
            body: JSON.stringify({os: os, arch: arch})
        });
        if (!resp.ok) {
            var err = await resp.json().catch(function() { return {error: 'Download failed'}; });
            alert(err.error || 'Download failed');
            return;
        }
        var blob = await resp.blob();
        var cd = resp.headers.get('Content-Disposition') || '';
        var filename = (cd.match(/filename="?([^"]+)"?/) || [])[1] || 'triton-bundle';
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function() { URL.revokeObjectURL(url); }, 100);
    } catch(e) {
        alert('Bundle download failed: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Download bundle';
    }
};
```

Wire the copy install command button:

```javascript
document.getElementById('copy-install-cmd-btn').onclick = async function() {
    var btn = this;
    btn.disabled = true;
    btn.textContent = 'Generating...';
    try {
        var resp = await fetch('/api/v1/admin/licenses/' + encodeURIComponent(id) + '/install-token', {
            method: 'POST',
            headers: {'X-Triton-Admin-Key': adminKey}
        });
        if (!resp.ok) {
            var err = await resp.json().catch(function() { return {error: 'Failed'}; });
            alert(err.error || 'Failed to generate install link');
            return;
        }
        var data = await resp.json();
        document.getElementById('install-cmd-curl').textContent = data.curl_command;
        document.getElementById('install-cmd-ps1').textContent = data.ps1_command;
        document.getElementById('install-cmd-display').style.display = 'block';
        // Copy the curl command to clipboard
        await navigator.clipboard.writeText(data.curl_command);
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy install command'; }, 2000);
    } catch(e) {
        alert('Failed: ' + e.message);
    } finally {
        btn.disabled = false;
    }
};
```

- [ ] **Step 2: Disable buttons for revoked/expired licenses**

Same pattern as existing code — check `lic.revoked` and `isExpired` and set `disabled` + title on all three buttons.

- [ ] **Step 3: Test manually in browser**

1. Start the license server locally
2. Navigate to a license detail page
3. Verify platform dropdown renders with 5 options
4. Verify "Download bundle" downloads a tar.gz/zip with the correct contents
5. Verify "Copy install command" shows the curl + ps1 commands
6. Verify buttons are disabled for revoked/expired licenses

- [ ] **Step 4: Commit**

```bash
git add pkg/licenseserver/ui/dist/admin.js
git commit -m "feat(licenseserver/ui): platform picker + bundle download + copy install command on license detail"
```

---

## Task 7: Integration Test — Full Install Flow

End-to-end test that exercises the complete install flow: generate install token, fetch install script, download binary, download agent.yaml.

**Files:**
- Create: `pkg/licenseserver/handlers_install_integration_test.go`

- [ ] **Step 1: Write the integration test**

```go
// pkg/licenseserver/handlers_install_integration_test.go
package licenseserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallFlow_EndToEnd(t *testing.T) {
	srv, _ := newTestServerWithLicenseAndBinaries(t, "linux", "amd64")
	srv.config.PublicURL = "http://localhost:18081"

	// Step 1: Admin generates install token
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/licenses/"+srv.testLicenseID+"/install-token", nil)
	req.Header.Set("X-Triton-Admin-Key", srv.adminKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&tokenResp))
	token := tokenResp["token"].(string)
	curlCmd := tokenResp["curl_command"].(string)
	require.NotEmpty(t, token)
	require.Contains(t, curlCmd, "curl")
	require.Contains(t, curlCmd, "sudo bash")

	// Step 2: Operator hits the install script URL
	req = httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token, nil)
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	script := rec.Body.String()
	assert.Contains(t, script, "#!/bin/bash")
	assert.Contains(t, script, "Triton Agent Installer")
	assert.Contains(t, script, token)

	// Step 3: Script downloads binary
	req = httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token+"/binary/linux/amd64", nil)
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Body.Bytes())

	// Step 4: Script downloads agent.yaml
	req = httptest.NewRequest(http.MethodGet, "/api/v1/install/"+token+"/agent-yaml", nil)
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "license_key:")
}
```

- [ ] **Step 2: Run the test**

Run: `go test -v -run TestInstallFlow_EndToEnd ./pkg/licenseserver/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/licenseserver/handlers_install_integration_test.go
git commit -m "test(licenseserver): end-to-end install flow integration test"
```

---

## Task 8: Documentation Update

Update the deployment guide and README with the new installation flow.

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `README.md`

- [ ] **Step 1: Add install flow section to deployment guide**

Add a new section to `docs/DEPLOYMENT_GUIDE.md` documenting:
- The `TRITON_LICENSE_SERVER_PUBLIC_URL` env var
- The bundle download flow (admin UI)
- The one-liner flow (curl | sudo bash / irm | iex)
- Install paths and permissions on each OS
- Troubleshooting: Gatekeeper, SmartScreen, permission denied

- [ ] **Step 2: Update the README's end-to-end flow section**

Replace the manual `curl` steps with:
1. "Download bundle" button in the admin UI
2. OR paste the one-liner install command

- [ ] **Step 3: Commit**

```bash
git add docs/DEPLOYMENT_GUIDE.md README.md
git commit -m "docs: document fool-proof agent installation — bundle + one-liner + install paths"
```

---

## Summary of New Routes

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/v1/admin/licenses/{id}/bundle` | Admin key | Download binary + agent.yaml + install script as one archive |
| `POST` | `/api/v1/admin/licenses/{id}/install-token` | Admin key | Generate a 24h HMAC install token (returns curl + ps1 commands) |
| `GET` | `/api/v1/install/{token}` | Install token | Serve the platform-detecting install shell script |
| `GET` | `/api/v1/install/{token}?shell=ps1` | Install token | Serve the PowerShell install script |
| `GET` | `/api/v1/install/{token}/binary/{os}/{arch}` | Install token | Serve the agent binary for the given platform |
| `GET` | `/api/v1/install/{token}/agent-yaml` | Install token | Serve agent.yaml for the token's license |

## End User Experience After Implementation

**Non-technical operator (one-liner — requires internet on target):**
```
Admin sends:  "Paste this into your terminal"
              curl -sSL 'https://license.example.com/install/eyJsa...' | sudo bash
Operator:     pastes, types sudo password, done
```

**Air-gapped operator (bundle — no internet on target):**
```
Admin:   clicks "Download bundle" → picks "Linux ARM 64-bit" → gets triton-v3.3.0-linux-arm64.tar.gz
         sends the file to the operator via USB/email/whatever
Operator: tar xzf triton-*.tar.gz && cd triton-* && sudo bash install.sh
```

Both paths end with:
```
  Triton Agent Installer
  ======================

  Verifying installation...

  Triton Agent starting...
    config file: /opt/triton/agent.yaml
    license:     enterprise tier (org=acme-corp)
    mode:        submit to report server https://reports.example.com
    profile:     comprehensive

  Config check passed — agent would run successfully with the settings above.

  Installation complete!

  To run a scan:   sudo /opt/triton/triton agent
  To uninstall:    sudo rm -rf /opt/triton
```
