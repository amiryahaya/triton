package licenseserver

// bundledInstallSh is the bash install script embedded in Linux/macOS bundle archives.
// It expects triton binary and agent.yaml to be present alongside the script.
const bundledInstallSh = `#!/usr/bin/env bash
set -euo pipefail

BANNER="========================================"
echo "$BANNER"
echo "  Triton Agent Installer"
echo "$BANNER"
echo ""

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    echo "       Re-run with: sudo bash install.sh" >&2
    exit 1
fi

INSTALL_DIR="/opt/triton"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify required files exist
if [ ! -f "${SCRIPT_DIR}/triton" ]; then
    echo "ERROR: triton binary not found in ${SCRIPT_DIR}" >&2
    echo "       Ensure triton and agent.yaml are in the same directory as this script." >&2
    exit 1
fi

if [ ! -f "${SCRIPT_DIR}/agent.yaml" ]; then
    echo "ERROR: agent.yaml not found in ${SCRIPT_DIR}" >&2
    echo "       Ensure triton and agent.yaml are in the same directory as this script." >&2
    exit 1
fi

echo "Installing Triton agent to ${INSTALL_DIR} ..."

# Create install directories
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/reports"

# Copy binary and config
cp "${SCRIPT_DIR}/triton" "${INSTALL_DIR}/triton"
cp "${SCRIPT_DIR}/agent.yaml" "${INSTALL_DIR}/agent.yaml"

# Set permissions
chmod 755 "${INSTALL_DIR}/triton"
chmod 600 "${INSTALL_DIR}/agent.yaml"

# macOS: bypass Gatekeeper quarantine
if [ "$(uname -s)" = "Darwin" ]; then
    xattr -d com.apple.quarantine "${INSTALL_DIR}/triton" 2>/dev/null || true
fi

echo ""
echo "Verifying configuration ..."
"${INSTALL_DIR}/triton" agent --check-config

echo ""
echo "$BANNER"
echo "  Installation complete!"
echo "$BANNER"
echo ""
echo "  Run agent:   ${INSTALL_DIR}/triton agent"
echo "  Uninstall:   sudo rm -rf ${INSTALL_DIR}"
echo ""
`

// bundledInstallBat is the Windows batch install script embedded in Windows bundle archives.
// It expects triton.exe and agent.yaml to be present alongside the script.
const bundledInstallBat = `@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Triton Agent Installer
echo ========================================
echo.

:: Admin check
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo        Right-click install.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

set "INSTALL_DIR=C:\Program Files\Triton"
set "SCRIPT_DIR=%~dp0"
:: Remove trailing backslash from SCRIPT_DIR
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: Verify required files exist
if not exist "%SCRIPT_DIR%\triton.exe" (
    echo ERROR: triton.exe not found in %SCRIPT_DIR%
    echo        Ensure triton.exe and agent.yaml are in the same directory as this script.
    echo.
    pause
    exit /b 1
)

if not exist "%SCRIPT_DIR%\agent.yaml" (
    echo ERROR: agent.yaml not found in %SCRIPT_DIR%
    echo        Ensure triton.exe and agent.yaml are in the same directory as this script.
    echo.
    pause
    exit /b 1
)

echo Installing Triton agent to "%INSTALL_DIR%" ...
echo.

:: Create install directory
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create %INSTALL_DIR%
        pause
        exit /b 1
    )
)

:: Copy binary and config
copy /y "%SCRIPT_DIR%\triton.exe" "%INSTALL_DIR%\triton.exe" >nul
if %errorlevel% neq 0 (
    echo ERROR: Failed to copy triton.exe to %INSTALL_DIR%
    pause
    exit /b 1
)

copy /y "%SCRIPT_DIR%\agent.yaml" "%INSTALL_DIR%\agent.yaml" >nul
if %errorlevel% neq 0 (
    echo ERROR: Failed to copy agent.yaml to %INSTALL_DIR%
    pause
    exit /b 1
)

:: Restrict agent.yaml to Administrators read-only
icacls "%INSTALL_DIR%\agent.yaml" /inheritance:r /grant:r "BUILTIN\Administrators:(R)" >nul
if %errorlevel% neq 0 (
    echo WARNING: Could not restrict permissions on agent.yaml
)

echo Verifying configuration ...
echo.
"%INSTALL_DIR%\triton.exe" agent --check-config
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Configuration check failed. Review the output above.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Installation complete!
echo ========================================
echo.
echo   Run agent:   "%INSTALL_DIR%\triton.exe" agent
echo   Uninstall:   rmdir /s /q "%INSTALL_DIR%"
echo.
pause
`

// onelinerInstallSh is the bash one-liner install script served by the install endpoint.
// It uses Go text/template variables: {{.BaseURL}}, {{.Token}}, {{.ScriptURL}}.
const onelinerInstallSh = `#!/usr/bin/env bash
set -euo pipefail

BANNER="========================================"
echo "$BANNER"
echo "  Triton Agent Installer"
echo "$BANNER"
echo ""

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    echo "       Re-run with: sudo bash <(curl -fsSL '{{.ScriptURL}}')" >&2
    exit 1
fi

BASE="{{.BaseURL}}"
TOKEN="{{.Token}}"
INSTALL_DIR="/opt/triton"

# Platform detection
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
RAW_ARCH="$(uname -m)"
case "${RAW_ARCH}" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *)
        echo "ERROR: Unsupported architecture: ${RAW_ARCH}" >&2
        exit 1
        ;;
esac

echo "Detected platform: ${OS}/${ARCH}"
echo ""

# Create temp directory, cleaned up on exit
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BINARY_URL="${BASE}/api/v1/install/${TOKEN}/binary/${OS}/${ARCH}"
YAML_URL="${BASE}/api/v1/install/${TOKEN}/agent-yaml"

echo "Downloading Triton binary ..."
HTTP_STATUS="$(curl -fsSL -w "%{http_code}" -o "${TMP}/triton" "${BINARY_URL}")"
if [ "${HTTP_STATUS}" != "200" ]; then
    echo "ERROR: Download failed (HTTP ${HTTP_STATUS})." >&2
    echo "       The install link may have expired. Request a new one from your administrator." >&2
    exit 1
fi

echo "Downloading agent configuration ..."
HTTP_STATUS="$(curl -fsSL -w "%{http_code}" -o "${TMP}/agent.yaml" "${YAML_URL}")"
if [ "${HTTP_STATUS}" != "200" ]; then
    echo "ERROR: Download failed (HTTP ${HTTP_STATUS})." >&2
    echo "       The install link may have expired. Request a new one from your administrator." >&2
    exit 1
fi

echo "Installing to ${INSTALL_DIR} ..."

mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/reports"

cp "${TMP}/triton" "${INSTALL_DIR}/triton"
cp "${TMP}/agent.yaml" "${INSTALL_DIR}/agent.yaml"

chmod 755 "${INSTALL_DIR}/triton"
chmod 600 "${INSTALL_DIR}/agent.yaml"

# macOS: bypass Gatekeeper quarantine
if [ "${OS}" = "darwin" ]; then
    xattr -d com.apple.quarantine "${INSTALL_DIR}/triton" 2>/dev/null || true
fi

echo ""
echo "Verifying configuration ..."
"${INSTALL_DIR}/triton" agent --check-config

echo ""
echo "$BANNER"
echo "  Installation complete!"
echo "$BANNER"
echo ""
echo "  Run agent:   ${INSTALL_DIR}/triton agent"
echo "  Uninstall:   sudo rm -rf ${INSTALL_DIR}"
echo ""
`

// onelinerInstallPs1 is the PowerShell one-liner install script for Windows.
// It uses Go text/template variables: {{.BaseURL}}, {{.Token}}.
//
// Note: PowerShell uses backtick (` ) as its escape character. Go raw string literals
// cannot contain a literal backtick, so error messages that would normally use `n for
// a newline are split across separate Write-Host calls instead.
const onelinerInstallPs1 = `#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "========================================"
Write-Host "  Triton Agent Installer"
Write-Host "========================================"
Write-Host ""

# Admin check
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator."
    Write-Host "       Right-click PowerShell and select 'Run as Administrator', then re-run the install command."
    exit 1
}

$BASE        = "{{.BaseURL}}"
$TOKEN       = "{{.Token}}"
$INSTALL_DIR = "C:\Program Files\Triton"

# Architecture detection
if ([Environment]::Is64BitOperatingSystem) {
    $ARCH = "amd64"
} else {
    $ARCH = "386"
}
Write-Host "Detected architecture: $ARCH"
Write-Host ""

# Create temp directory; cleaned up in finally block
$TMP = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $TMP | Out-Null

try {
    $BINARY_URL = "$BASE/api/v1/install/$TOKEN/binary/windows/$ARCH"
    $YAML_URL   = "$BASE/api/v1/install/$TOKEN/agent-yaml"
    $BINARY_TMP = Join-Path $TMP "triton.exe"
    $YAML_TMP   = Join-Path $TMP "agent.yaml"

    Write-Host "Downloading Triton binary ..."
    try {
        $response = Invoke-WebRequest -Uri $BINARY_URL -OutFile $BINARY_TMP -PassThru -UseBasicParsing
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
    } catch {
        Write-Host "ERROR: Binary download failed ($_)."
        Write-Host "       The install link may have expired. Request a new one from your administrator."
        exit 1
    }

    Write-Host "Downloading agent configuration ..."
    try {
        $response = Invoke-WebRequest -Uri $YAML_URL -OutFile $YAML_TMP -PassThru -UseBasicParsing
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
    } catch {
        Write-Host "ERROR: Configuration download failed ($_)."
        Write-Host "       The install link may have expired. Request a new one from your administrator."
        exit 1
    }

    Write-Host "Installing to $INSTALL_DIR ..."

    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
    }

    Copy-Item -Path $BINARY_TMP -Destination "$INSTALL_DIR\triton.exe" -Force
    Copy-Item -Path $YAML_TMP   -Destination "$INSTALL_DIR\agent.yaml"  -Force

    # Restrict agent.yaml to Administrators read-only
    $acl = Get-Acl "$INSTALL_DIR\agent.yaml"
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "Read", "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path "$INSTALL_DIR\agent.yaml" -AclObject $acl

    Write-Host ""
    Write-Host "Verifying configuration ..."
    & "$INSTALL_DIR\triton.exe" agent --check-config
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Configuration check failed. Review the output above."
        exit 1
    }

    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "  Run agent:   & '$INSTALL_DIR\triton.exe' agent"
    Write-Host "  Uninstall:   Remove-Item -Recurse -Force '$INSTALL_DIR'"
    Write-Host ""
} finally {
    Remove-Item -Recurse -Force $TMP -ErrorAction SilentlyContinue
}
`
