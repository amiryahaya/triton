# Triton User Manual

**Version 2.7** | SBOM/CBOM Scanner for Post-Quantum Cryptography Compliance

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Scan Profiles](#4-scan-profiles)
5. [Scanning Categories](#5-scanning-categories)
6. [Understanding PQC Status](#6-understanding-pqc-status)
7. [Running a Scan](#7-running-a-scan)
8. [Reading Reports](#8-reading-reports)
9. [Using triton doctor](#9-using-triton-doctor)
10. [Configuration](#10-configuration)
11. [Policy Evaluation](#11-policy-evaluation)
12. [Server Mode](#12-server-mode)
13. [Licensing](#13-licensing)
14. [Platform Notes](#14-platform-notes)
15. [Troubleshooting](#15-troubleshooting)
16. [Algorithm Reference](#16-algorithm-reference)
17. [Glossary](#17-glossary)

---

## 1. Introduction

Triton is a command-line tool that scans your systems to produce:

- **SBOM** (Software Bill of Materials) — an inventory of all software components
- **CBOM** (Cryptographic Bill of Materials) — an inventory of all cryptographic assets, algorithms, and protocols in use

The output helps Malaysian government agencies and critical infrastructure operators assess their readiness for the transition to **Post-Quantum Cryptography (PQC)** as mandated by NACSA and aligned with the 2030 timeline set by NIST and CNSA 2.0 guidelines.

### Who is this for?

- IT administrators responsible for system security audits
- Compliance officers preparing PQC migration plans
- Security teams conducting cryptographic inventory assessments
- Anyone who needs to know "what crypto does my system use?"

### What does Triton detect?

Triton uses 19 scanner modules across 9 CBOM categories — from certificates on disk to TLS connections on the network — and classifies every finding as SAFE, TRANSITIONAL, DEPRECATED, or UNSAFE for the post-quantum era.

---

## 2. Installation

### Download from GitHub Releases

1. Go to the [Releases page](https://github.com/amiryahaya/triton/releases)
2. Download the binary for your platform:
   - `triton_darwin_arm64` — macOS (Apple Silicon)
   - `triton_darwin_amd64` — macOS (Intel)
   - `triton_linux_amd64` — Linux (64-bit)
   - `triton_linux_arm64` — Linux (ARM64)
   - `triton_windows_amd64.exe` — Windows (64-bit)
3. Verify the checksum:
   ```bash
   sha256sum triton_darwin_arm64
   # Compare with checksums.txt in the release
   ```
4. Make it executable and move to PATH:

   **macOS / Linux:**
   ```bash
   chmod +x triton_darwin_arm64
   sudo mv triton_darwin_arm64 /usr/local/bin/triton
   ```

   **Windows (PowerShell):**
   ```powershell
   # Move to a directory in your PATH, e.g.:
   Move-Item triton_windows_amd64.exe C:\Users\<you>\bin\triton.exe
   # Add to PATH if needed (persistent, user-level):
   [Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Users\<you>\bin", "User")
   ```
5. Verify installation:
   ```bash
   triton --version
   ```

### Download from License Server

If your organization uses a Triton License Server, you can download the binary directly from it:

1. Open the download page in your browser:
   ```
   https://li/download
   ```
2. Enter your **License ID** (a UUID provided by your administrator) and click **Continue**.
3. The page auto-detects your operating system and architecture. Click **Download Triton** for the recommended platform, or choose another platform from the list.
4. Follow the on-screen installation instructions. The key steps are:

   **macOS / Linux:**
   ```bash
   chmod +x triton
   sudo mv triton /usr/local/bin/triton
   triton license activate --license-server https://<your-license-server> --license-id <your-license-id>
   triton --version
   ```

   **Windows (PowerShell):**
   ```powershell
   Move-Item triton.exe C:\Windows\triton.exe
   triton license activate --license-server https://<your-license-server> --license-id <your-license-id>
   triton --version
   ```

The download page validates your license before serving the binary — revoked or expired licenses are rejected.

### Prerequisites

Building from source requires **Go 1.24 or later**. If you don't have Go installed:

1. Download and install from the official site: [https://go.dev/doc/install](https://go.dev/doc/install)
2. Verify the installation:
   ```bash
   go version
   # Should output: go version go1.24.x ...
   ```

### Post-Installation: Permissions and Trust

After downloading and installing the Triton binary, your operating system may block it from running because it is an unsigned binary downloaded from the internet. Follow the steps below for your platform.

#### macOS

macOS Gatekeeper blocks unsigned binaries downloaded from the internet. You will see a **"triton cannot be opened because it is from an unidentified developer"** dialog.

**Remove the quarantine attribute (required):**
```bash
# Remove the quarantine flag set by the browser
xattr -d com.apple.quarantine /usr/local/bin/triton
```

**Or allow via System Settings:**
1. Try running `triton --version` — it will be blocked
2. Open **System Settings > Privacy & Security**
3. Scroll down to the security section — you'll see **"triton was blocked"**
4. Click **Allow Anyway**
5. Run `triton --version` again and click **Open** in the confirmation dialog

**Grant Full Disk Access (recommended for comprehensive scans):**

Some scan targets (e.g. `/System/Library`, application containers) require Full Disk Access:

1. Open **System Settings > Privacy & Security > Full Disk Access**
2. Click **+** and add your terminal app (Terminal.app, iTerm, etc.)
3. Restart your terminal

**Run with elevated privileges (for process/network scanning):**
```bash
sudo triton --profile comprehensive
```

#### Linux

**Make the binary executable:**
```bash
chmod +x /usr/local/bin/triton
```

**Run with elevated privileges (recommended for full scanning):**

Process scanning, network scanning, and some filesystem paths require root access:

```bash
sudo triton --profile comprehensive
```

Alternatively, grant specific capabilities without full root:
```bash
# Allow network scanning without root
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/triton
```

**SELinux systems (RHEL, CentOS, Fedora):**

If SELinux is enforcing, you may need to set the correct context:
```bash
sudo chcon -t bin_t /usr/local/bin/triton
```

#### Windows

Windows SmartScreen blocks unsigned executables. You will see a **"Windows protected your PC"** dialog.

**Allow through SmartScreen:**
1. When the SmartScreen dialog appears, click **More info**
2. Click **Run anyway**

**Run as Administrator (recommended for full scanning):**

Right-click on your terminal (PowerShell or Command Prompt) and select **Run as administrator**, then run Triton:
```powershell
triton --profile comprehensive
```

Or from a regular terminal, use:
```powershell
Start-Process -Verb RunAs -FilePath "triton.exe" -ArgumentList "--profile comprehensive"
```

**Windows Defender exclusion (if flagged as unknown):**

If Windows Defender quarantines the binary:
1. Open **Windows Security > Virus & threat protection > Protection history**
2. Find the Triton entry and click **Actions > Allow on device**

Or via PowerShell (as Administrator):
```powershell
Add-MpPreference -ExclusionPath "C:\Windows\triton.exe"
```

**Verify the binary checksum** before allowing any security exclusion:
```powershell
Get-FileHash triton.exe -Algorithm SHA256
# Compare with the checksum shown on the download page or in checksums.txt
```

### Build from Source

```bash
git clone https://github.com/amiryahaya/triton.git
cd triton
make build
./bin/triton --version
```

---

## 3. Quick Start

Three commands to go from zero to a complete PQC assessment:

```bash
# Step 1: Check that your system is ready
triton doctor

# Step 2: Run a scan
triton --profile standard --format all

# Step 3: Open the report
open Triton_PQC_Report-*.xlsx    # macOS
xdg-open Triton_PQC_Report-*.xlsx  # Linux
```

The Excel report contains 5 worksheets with your complete SBOM and CBOM in the government-mandated format.

---

## 4. Scan Profiles

Triton offers three scan profiles that control which modules run, how deep the filesystem traversal goes, and how many concurrent workers are used.

### Quick

```bash
triton --profile quick
```

| Setting | Value |
|---------|-------|
| Modules | certificates, keys, packages |
| Depth | 3 directories |
| Workers | 4 |
| Use case | Fast check of critical crypto assets |

Best for: Initial triage or quick validation after a change. Completes in seconds.

### Standard (default)

```bash
triton --profile standard
```

| Setting | Value |
|---------|-------|
| Modules | certificates, keys, packages, libraries, binaries, scripts, webapp |
| Depth | 10 directories |
| Workers | 8 |
| Use case | Balanced system assessment |

Best for: Regular compliance checks. Covers file-based crypto without active network probing.

### Comprehensive

```bash
triton --profile comprehensive
```

| Setting | Value |
|---------|-------|
| Modules | All 19 modules (including processes, network, protocol, hsm, ldap, codesign) |
| Depth | Unlimited |
| Workers | 16 |
| Use case | Full audit including runtime and network |

Best for: Complete PQC readiness audit. Includes active TLS probing and process inspection. Run with `sudo` for best results.

> **Note:** Worker count is capped at the number of CPU cores on your machine.

---

## 5. Scanning Categories

Triton covers all 9 categories defined by the CBOM scanning framework. Each category maps to one or more scanner modules.

### Category 1: Binaries in Use (Active/Runtime)

**Module:** `processes`

Scans running processes for crypto-related binaries. Detects services like OpenSSH, OpenVPN, WireGuard, GnuPG, and HashiCorp Vault by matching process names against known crypto keywords.

**Detection method:** Parses `ps -eo pid,command` output and matches against known crypto process keywords.

**Example findings:** `sshd` (SSH), `openvpn` (TLS), `gpg-agent` (RSA)

### Category 2: Binaries on Disk (Passive/File)

**Module:** `binaries`

Scans executable files for embedded cryptographic patterns. Reads binary content and searches for algorithm strings and crypto library references.

**Detection method:** Pattern matching in binary content for strings like "AES", "RSA", "SHA", and library references.

### Category 3: Cryptographic Libraries (Passive/File)

**Module:** `libraries`

Detects installed cryptographic libraries by scanning filesystem for known library files and patterns.

**Detection method:** Filename pattern matching for libraries like `libcrypto`, `libssl`, `libgnutls`, `libmbedtls`, `libnss`, and `libgcrypt`.

### Category 4: Kernel Modules (Passive/File)

**Module:** `kernel`

Scans kernel modules (`.ko` files on Linux) for cryptographic functionality. On macOS, checks kernel extensions.

**Detection method:** Filename and content pattern matching in kernel module directories.

### Category 5: Certificates and Keys (Passive/File)

**Modules:** `certificates`, `keys`

Scans for X.509 certificates (PEM, DER, PKCS#12) and private keys. Extracts the signature algorithm, key type, key size, validity dates, and issuer/subject information.

**Detection method:**
- Certificates: Parses `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx` files using Go's `crypto/x509` library
- Keys: Detects private keys via file extension (`.key`) and PEM header pattern matching (`BEGIN RSA PRIVATE KEY`, etc.)

**Example findings:** RSA-2048 certificate signed with SHA-256, ECDSA-P256 private key

### Category 6: Executable Scripts (Passive/Code)

**Module:** `scripts`

Scans script files (`.py`, `.sh`, `.rb`, `.pl`) for cryptographic function calls and library imports.

**Detection method:** Regex pattern matching for crypto API calls like `hashlib.sha256()`, `openssl enc`, `Cipher.new()`.

### Category 7: Web Applications (Passive/Code)

**Module:** `webapp`

Scans web application source code (`.php`, `.js`, `.ts`, `.go`, `.java`) for cryptographic usage patterns.

**Detection method:** Pattern matching for web-specific crypto APIs and framework usage.

### Category 8: Network Applications (Active/Network)

**Module:** `network`

Detects listening network services that use cryptographic protocols by checking which ports are open and matching them against known crypto port numbers.

**Detection method:**
- macOS: `lsof -i -P -n -sTCP:LISTEN`
- Linux: `ss -tlnp` (preferred) with `lsof` fallback

**Crypto ports detected:** 22 (SSH), 443 (HTTPS), 993 (IMAPS), 995 (POP3S), 465 (SMTPS), 636 (LDAPS), 8443 (HTTPS alt), 500/4500 (IPsec), 51820 (WireGuard), and more.

### Category 9: Network Protocols (Active/Network)

**Module:** `protocol`

Performs active TLS probing to identify the actual cipher suites and protocol versions in use by listening services.

**Detection method:** Initiates TLS handshakes with discovered services and performs:

- **Cipher enumeration** — tests each TLS 1.2 cipher suite individually (~24 suites) to identify all supported ciphers, not just the negotiated default
- **Cipher preference order** — uses iterative removal to determine server cipher preference ordering
- **TLS version range** — probes TLS 1.0, 1.1, 1.2, and 1.3 individually to map the supported version range
- **Key exchange / PFS analysis** — classifies each cipher finding by key exchange type (ECDHE, DHE, RSA, TLS 1.3) and forward secrecy support
- **Chain validation** — checks for weak signatures (SHA-1, MD5), certificate expiry warnings (30-day window), and Subject Alternative Name (SAN) extraction

---

## 6. Understanding PQC Status

Every cryptographic asset Triton discovers is classified into one of four PQC readiness levels:

### SAFE

**Quantum-resistant.** These algorithms are expected to remain secure even after large-scale quantum computers become available.

| Type | Examples |
|------|----------|
| Symmetric (>=192-bit) | AES-256-GCM, AES-192-CBC, ChaCha20-Poly1305 |
| Hash (>=256-bit output) | SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b |
| KDF/Password | Argon2, scrypt, Bcrypt, PBKDF2, HKDF |
| PQC Standards | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| Protocols | TLS 1.3, WireGuard, QUIC |

**Action:** Monitor for updates; no immediate action needed.

### TRANSITIONAL

**Needs migration plan.** These algorithms are currently secure against classical attacks but will be vulnerable to quantum computers. Begin planning migration.

| Type | Examples | Estimated break year |
|------|----------|---------------------|
| RSA | RSA-2048, RSA-3072, RSA-4096 | 2035-2050 |
| ECC | ECDSA-P256, ECDSA-P384, Ed25519, X25519 | 2030-2040 |
| Symmetric (128-bit) | AES-128-GCM, AES-128-CBC | N/A (reduced margin) |
| Hash (224-256 bit) | SHA-256, SHA-224 | N/A (reduced margin) |
| Protocols | TLS 1.2, SSH, IPsec | Depends on cipher suite |

**Action:** Develop a migration plan to replace with SAFE alternatives by 2030.

### DEPRECATED

**Replace soon.** These algorithms have known weaknesses even without quantum computers and should be replaced on an accelerated timeline.

| Type | Examples |
|------|----------|
| Weak RSA | RSA-1024 |
| Legacy hash | SHA-1, MD5, RIPEMD-160 |
| Block ciphers | 3DES, Blowfish, CAST5, IDEA |
| Signatures | DSA, ECDSA-P192 |
| Protocols | TLS 1.0, TLS 1.1 |

**Action:** Schedule replacement within 6-12 months.

### UNSAFE

**Immediate vulnerability.** These algorithms are broken and provide no meaningful security.

| Type | Examples |
|------|----------|
| Block ciphers | DES (56-bit key), RC2 |
| Stream ciphers | RC4 |
| Hash | MD4 |
| Null | NULL cipher |
| Protocols | SSL 2.0, SSL 3.0 |

**Action:** Replace immediately. These represent active security vulnerabilities.

---

## 7. Running a Scan

### Basic Usage

```bash
# Default scan (standard profile, all formats)
triton

# With explicit profile
triton --profile comprehensive

# Specific output format
triton --format xlsx
triton --format json
triton --format html
triton --format all       # default — generates all three
```

### CLI Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-p` | `standard` | Scan profile: `quick`, `standard`, `comprehensive` |
| `--format` | `-f` | `all` | Output format: `json`, `html`, `xlsx`, `sarif`, `cdx`, `all` |
| `--output` | `-o` | `triton-report.json` | Output file (used with `--format json`) |
| `--output-dir` | `-d` | `.` | Output directory for reports |
| `--modules` | `-m` | (all) | Comma-separated list of specific modules to run |
| `--metrics` | | `false` | Show per-module scan metrics table (pro+) |
| `--incremental` | | `false` | Skip unchanged files since last scan (pro+) |
| `--db` | | | PostgreSQL connection URL for scan storage (pro+) |
| `--policy` | | | Policy file or builtin name (pro+) |
| `--license-key` | | | Licence key token (or set `TRITON_LICENSE_KEY` env / `~/.triton/license.key` file) |
| `--config` | | `~/.triton.yaml` | Path to config file |
| `--version` | | | Show version |

### Examples

```bash
# Scan only certificates and keys
triton --modules certificates,keys

# Save reports to a specific directory
triton --output-dir ./reports

# Comprehensive scan with metrics
triton --profile comprehensive --metrics

# JSON output only, custom filename
triton --format json --output my-report.json
```

### Headless Mode

When Triton detects that stdin is not a terminal (e.g., running in a CI/CD pipeline or via SSH without a TTY), it automatically switches to headless mode with plain text progress output instead of the interactive TUI:

```bash
# Pipe or redirect — triggers headless mode
triton --profile quick 2>&1 | tee scan.log

# CI/CD usage
triton --profile standard --format json --output report.json
```

### Cancellation

Press **Ctrl+C** during a scan to cancel. The scan will stop gracefully and no partial report will be generated.

---

## 8. Reading Reports

### 8.1 Excel Report (Government Format)

The Excel report (`Triton_PQC_Report-*.xlsx`) uses a government-mandated template with 5 worksheets:

#### Sheet 0: Inventory (0_Inventory)

High-level inventory of all systems/components discovered.

| Column | Description |
|--------|-------------|
| # | Row number |
| Asset Type | Application Stack, Cloud Services, Database, etc. |
| Asset Name | System or component name |
| Location / Owner | Vendor or owner |
| Crypto Present? | Always "Yes" for detected assets |
| Algorithms Used | Comma-separated list of algorithms |
| SBOM/CBOM Available? | "CBOM" |
| Migration Readiness Level | High / Medium / Low / Very Low |
| Notes | Additional notes |

#### Sheet 1: SBOM — Jadual 1 (1_SBOM)

Software Bill of Materials in the Jadual 1 format with 17 columns:

| Column | Description |
|--------|-------------|
| # | Row number |
| System / Application | Name of the system |
| Purpose / Usage | What the system does |
| URL | System URL |
| Services Mode | Service delivery mode |
| Target Customer | Target users |
| Software Component | Component list |
| Third-party Modules | External dependencies |
| External APIs | API integrations |
| Critical Level | Criticality: Sangat Tinggi/Tinggi/Sederhana/Rendah |
| Data Category | Type of data handled |
| In Use? | Ya / Tidak |
| Developer | Development team |
| Vendor | Vendor name |
| Has expertise? | Internal PQC expertise |
| Has budget? | Budget for migration |
| Link to CBOM | Reference to CBOM entries |

#### Sheet 2: CBOM — Jadual 2 (2_CBOM)

Cryptographic Bill of Materials with 8 columns. One row per crypto asset:

| Column | Description |
|--------|-------------|
| # (CBOM) | CBOM reference number (e.g., "CBOM #1") |
| System / Application | Parent system |
| Cryptographic Function | What the crypto does (e.g., "Certificate signing") |
| Algorithm Used | Algorithm name (e.g., "RSA-2048") |
| Library / Module | Crypto library (e.g., "OpenSSL 3.0") |
| Key Length | Key size in bits (e.g., "2048-bit") or "N/A" |
| Purpose / Usage | Why this crypto is used |
| Crypto-Agility Support | Ya / Terhad / Tidak dapat dinilai |

#### Sheet 3: Risk Register (3_RiskRegister)

Risk entries per crypto asset with 8 columns:

| Column | Description |
|--------|-------------|
| # | Row number |
| System Name | Parent system |
| Type of Asset | Certificate, Key Exchange, Encryption, etc. |
| Cryptographic Algorithm | Algorithm name |
| Algorithm Usage | Function description |
| Criticality | System criticality level |
| Risk | Risk description in Malay |
| Risk Owner | (To be filled manually) |

#### Sheet 4: Risk Assessment (4_RiskAssessment)

Quantitative risk scoring with 11 columns:

| Column | Description |
|--------|-------------|
| # | Row number |
| Nama Sistem | System name |
| Algoritma Kriptografi | Algorithm name |
| Risiko | Risk description |
| Punca Risiko | Risk source (in Malay) |
| Impak | Impact score (1-5) |
| Kemungkinan | Likelihood score (1-5) |
| Skor Risiko | Risk score (Impact x Likelihood) |
| Risk Level | Very High / High / Medium / Low / Very Low |
| Kawalan Sedia Ada | Existing controls (to be filled) |
| Mitigation Plan | Migration plan (to be filled) |

**Risk scoring:**

| PQC Status | Likelihood Score |
|------------|-----------------|
| UNSAFE | 5 |
| DEPRECATED | 4 |
| TRANSITIONAL | 3 |
| SAFE | 1 |

| Criticality | Impact Score |
|-------------|-------------|
| Sangat Tinggi | 5 |
| Tinggi | 4 |
| Sederhana | 3 |
| Rendah | 2 |

| Risk Score | Level |
|------------|-------|
| >= 20 | Very High Risk |
| 12-19 | High Risk |
| 6-11 | Medium Risk |
| 3-5 | Low Risk |
| < 3 | Very Low Risk |

### 8.2 CycloneDX JSON

The JSON report follows the CycloneDX 1.6 standard for machine-readable SBOM/CBOM data. Use this format for:

- Integration with other security tools
- CI/CD pipeline consumption
- Programmatic analysis
- Compliance automation

```bash
triton --format json --output report.json
```

The output includes:
- `bomFormat`: "CycloneDX"
- `specVersion`: "1.6"
- `components`: Array of all discovered components
- `vulnerabilities`: PQC-related risk entries
- `metadata`: Scan metadata (timestamp, tool version, profile)

### 8.3 HTML Dashboard

The HTML report provides a visual dashboard with:

- PQC status distribution chart
- Summary statistics
- NACSA compliance summary cards and bar chart
- CAMM crypto-agility assessment
- Searchable findings table
- System-level grouping
- **Policy analysis summary** (when `--policy` is used): verdict banner (color-coded PASS/WARN/FAIL), violations-by-rule table, and threshold violations table

```bash
triton --format html
# Open in browser
open triton-report-*.html
```

---

## 9. Using triton doctor

The `triton doctor` command runs pre-flight checks to verify that your system has the tools and permissions needed for a successful scan.

### When to Use

Run `triton doctor` before your first scan on a new system, or whenever a scan produces unexpectedly few results. It identifies missing tools and permission issues that would cause modules to silently skip results.

### Usage

```bash
# Check readiness for the default (standard) profile
triton doctor

# Check readiness for a specific profile
triton doctor --profile comprehensive
triton doctor --profile quick
```

### What It Checks

| Check | Scope | Condition |
|-------|-------|-----------|
| Filesystem access | All file-scanning modules | Can Triton read the default scan target directories? |
| External tools | packages, processes, network | Are `brew`/`dpkg-query`/`rpm`, `ps`, `lsof`/`ss` available? |
| Elevated permissions | processes, network | Is the process running as root? (Unix only) |
| Go TLS | protocol | Are TLS cipher suites available for protocol probing? |

### Understanding the Output

```
Triton Doctor — System Readiness Check
Platform: darwin/arm64
Profile:  comprehensive

Module        Check                 Status  Message
───────────────────────────────────────────────────
certificates  Read /Applications    PASS    Readable
packages      brew available        PASS    /opt/homebrew/bin/brew
processes     ps available          PASS    /bin/ps
processes     Elevated permissions  WARN    Not running as root
network       lsof available        PASS    /usr/sbin/lsof
network       Elevated permissions  WARN    Not running as root
protocol      Go TLS available      PASS    13 cipher suites available
───────────────────────────────────────────────────
Results: 5 passed, 2 warnings, 0 failures

✓ System is ready for scanning (warnings are advisory)
```

- **PASS** — Check passed. No action needed.
- **WARN** — Advisory. The scan will work but some results may be incomplete.
- **FAIL** — A scan target directory does not exist. Findings for that path will be empty.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No failures (PASS and WARN only) |
| 1 | One or more FAIL checks |

### Fixing Common Issues

| Issue | Fix |
|-------|-----|
| "Not running as root" | Run with `sudo triton --profile comprehensive` for complete process/network visibility |
| "brew not found" | Install Homebrew: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` |
| "lsof not found" (Linux) | `sudo apt install lsof` or `sudo yum install lsof` |
| "ss not found" (Linux) | `sudo apt install iproute2` |
| "ps not found" | This is unusual; `ps` is a core Unix utility. Check your PATH. |
| Scan target "not found" | The directory does not exist on this system. This is expected on some platforms. |

---

## 10. Configuration

### Config File

Triton looks for a configuration file at `~/.triton.yaml` (`%USERPROFILE%\.triton.yaml` on Windows). You can override this with `--config`:

```bash
triton --config /path/to/my-config.yaml
```

### Environment Variables

All flags can be set via environment variables prefixed with `TRITON_`:

**macOS / Linux (bash/zsh):**
```bash
export TRITON_PROFILE=comprehensive
export TRITON_OUTPUT=my-report.json
triton  # Uses comprehensive profile
```

**Windows (PowerShell):**
```powershell
$env:TRITON_PROFILE = "comprehensive"
$env:TRITON_OUTPUT = "my-report.json"
triton  # Uses comprehensive profile
```

**Windows (Command Prompt):**
```cmd
set TRITON_PROFILE=comprehensive
set TRITON_OUTPUT=my-report.json
triton
```

To set environment variables permanently on Windows, use System Properties > Environment Variables, or:
```powershell
[Environment]::SetEnvironmentVariable("TRITON_PROFILE", "comprehensive", "User")
```

### Custom Scan Targets

The default scan targets are platform-specific (see [Platform Notes](#14-platform-notes)). Custom targets can be configured through the config file.

---

## 11. Policy Evaluation

Policies enforce compliance rules against scan findings and produce a **PASS**, **WARN**, or **FAIL** verdict. Use policies to validate scans against organizational or regulatory standards.

### 11.1 Built-in Policies

Triton ships with two built-in policies (pro tier and above):

**NACSA 2030** — Malaysian NACSA PQC compliance:

```bash
triton --profile standard --policy nacsa-2030
```

**CNSA 2.0** — NSA Commercial National Security Algorithm Suite:

```bash
triton --profile standard --policy cnsa-2.0
```

### 11.2 Custom Policies

Enterprise tier users can write custom policies in YAML format:

```bash
triton --profile standard --policy /path/to/my-policy.yaml
```

Custom policies use the same YAML schema as the built-in policies. See `pkg/policy/builtin/nacsa-2030.yaml` for an example.

### 11.3 Policy Comparison

| Feature | NACSA 2030 | CNSA 2.0 |
|---------|-----------|----------|
| Minimum RSA key size | 2048 bits | 3072 bits |
| Minimum ECDSA key size | — | P-384 |
| SHA-256 | Allowed | Warning (prefers SHA-384+) |
| MD5 | Error (fail) | — (caught by UNSAFE rule) |
| SHA-1 | Warning | — (caught by DEPRECATED rule) |
| RC4 | Error (fail) | — (caught by UNSAFE rule) |
| DES/3DES | Error (fail) | — (caught by UNSAFE rule) |
| Readiness threshold | 60% NACSA readiness | 50% SAFE |
| Max UNSAFE count | 0 | 0 |

### 11.4 Understanding Verdicts

| Verdict | Meaning | Exit Code |
|---------|---------|-----------|
| **PASS** | All rules satisfied, all thresholds met | 0 |
| **WARN** | Advisory warnings triggered but no failures | 0 |
| **FAIL** | One or more error-severity rules violated, or a threshold breached | 1 |

The verdict is determined by the most severe outcome across all rules and thresholds. A single `fail` action or threshold breach causes a FAIL verdict even if all other rules pass.

### 11.5 Policy in Reports

When `--policy` is used alongside `--format html` (or `--format all`), the HTML report includes a policy analysis summary:

- **Verdict banner** — color-coded card showing PASS (green), WARN (amber), or FAIL (red) with the policy name, rules evaluated, findings checked, and total violations
- **Violations-by-rule table** — aggregated violation counts by rule ID, sorted by count descending
- **Threshold violations table** — expected vs actual values for any breached thresholds

Without `--policy`, the HTML report omits the policy section entirely.

### 11.6 CLI Examples

```bash
# Scan with NACSA 2030 policy and all report formats
triton --profile standard --policy nacsa-2030 --format all

# Scan with CNSA 2.0 policy, JSON output only
triton --profile comprehensive --policy cnsa-2.0 --format json

# Use a custom policy file (enterprise tier)
triton --profile standard --policy ./policies/internal.yaml

# Store results in PostgreSQL with policy evaluation
triton --profile standard --policy nacsa-2030 --db postgres://triton:triton@localhost:5434/triton
```

---

## 12. Server Mode

Triton includes a REST API server with an embedded web dashboard for centralized scan management (enterprise tier).

### Starting the Server

```bash
triton server --db postgres://triton:triton@localhost:5434/triton
```

The server listens on port 8080 by default and provides:

- REST API for submitting, querying, and comparing scans
- Web dashboard with scan history, machine inventory, diff, and trend views
- Policy evaluation via API
- Multi-format report generation

### Agent Mode

Remote machines can submit scans to the server using agent mode:

```bash
triton agent --server http://triton-server:8080 --profile standard
```

The agent runs a local scan and uploads the results to the central server.

### Container Deployment

Triton provides a multi-stage container image (~10MB) for production deployment:

```bash
make container-run   # Starts PostgreSQL + Triton server
make container-stop  # Stops the stack
```

For full setup instructions — including PostgreSQL configuration, TLS, API authentication, systemd services, and production checklist — see [Deployment Guide](DEPLOYMENT_GUIDE.md).

---

## 13. Licensing

Triton uses a 3-tier licence system based on Ed25519-signed tokens. All licence validation is performed offline — no network connection is required.

### Licence Tiers

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Profile: quick | Yes | Yes | Yes |
| Profile: standard / comprehensive | — | Yes | Yes |
| Scanner modules | 3 (certificates, keys, packages) | All 19 | All 19 |
| Format: JSON | Yes | Yes | Yes |
| Format: CDX, HTML, XLSX | — | Yes | Yes |
| Format: SARIF | — | — | Yes |
| Server mode (`triton server`) | — | — | Yes |
| Agent mode (`triton agent`) | — | — | Yes |
| Policy: builtin (NACSA-2030, CNSA-2.0) | — | Yes | Yes |
| Policy: custom YAML | — | — | Yes |
| Metrics, incremental scan | — | Yes | Yes |
| Diff / trend / history | — | Yes | Yes |
| DB persistence | — | Yes | Yes |
| Seats | 1 | Configured | Configured |

### How It Works

Without a licence key, Triton runs in **free tier** — it always works, just with limited features. Invalid or expired licence keys gracefully degrade to free tier rather than blocking the tool.

### Setting a Licence Key

There are three ways to provide a licence key (checked in this order):

**1. CLI flag (highest priority):**
```bash
triton --license-key <token> --profile standard
```

**2. Environment variable:**

macOS / Linux:
```bash
export TRITON_LICENSE_KEY=<token>
triton --profile standard
```

Windows (PowerShell):
```powershell
$env:TRITON_LICENSE_KEY = "<token>"
triton --profile standard
```

Windows (Command Prompt):
```cmd
set TRITON_LICENSE_KEY=<token>
triton --profile standard
```

To persist the environment variable on Windows:
```powershell
[Environment]::SetEnvironmentVariable("TRITON_LICENSE_KEY", "<token>", "User")
```

**3. File (persists across sessions):**

The licence file location is `~/.triton/license.key` — on Windows this resolves to `%USERPROFILE%\.triton\license.key` (e.g. `C:\Users\<you>\.triton\license.key`).

macOS / Linux:
```bash
mkdir -p ~/.triton
echo "<token>" > ~/.triton/license.key
triton --profile standard
```

Windows (PowerShell):
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.triton"
Set-Content -Path "$env:USERPROFILE\.triton\license.key" -Value "<token>"
triton --profile standard
```

### Machine Binding

Licence tokens are bound to a specific machine by default. The machine fingerprint is a SHA-256 hash of `hostname|GOOS|GOARCH` — a deterministic 64-character hex string that requires no elevated privileges to compute.

- **Default behaviour:** `IssueToken()` binds the token to the current machine. Running it on a different machine gracefully degrades to free tier.
- **Portable tokens:** Use `--no-bind` at keygen time to create tokens that work on any machine.
- **Checking fingerprint:** `triton license show` displays your machine's fingerprint alongside the licence details.

If you see unexpected free-tier behaviour, check that the licence token's machine ID matches the current machine (hostname, OS, or architecture may have changed).

### Checking Your Licence

```bash
# Show current licence info (tier, org, seats, expiry, machine fingerprint)
triton license show

# Verify a specific token
triton license verify <token>
```

### Behaviour When Gated

- **Profile gating:** If you run bare `triton` without explicitly setting `--profile`, the tool silently uses the highest profile your tier allows (free tier uses `quick`). If you explicitly request a profile above your tier, you get a clear error message.
- **Format gating:** Same logic — defaults silently adjust, explicit requests produce clear errors.
- **Module gating:** Free tier scans only certificates, keys, and packages. Additional modules are silently excluded.
- **Subcommand gating:** Commands like `triton server`, `triton agent`, `triton diff`, `triton trend`, `triton history`, and `triton policy` require the appropriate tier and produce a clear error with upgrade guidance if unavailable.
- **Expiry:** Licences have a 5-minute grace period after expiry. After that, the tool degrades to free tier.

---

## 14. Platform Notes

### Comparison Table

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| **Default scan targets** | `/Applications`, `/System/Library`, `/usr/local`, `/etc` | `/usr`, `/etc`, `/opt` | `C:\Program Files`, `C:\ProgramData`, `C:\Windows\System32` |
| **Package manager** | `brew` | `dpkg-query` or `rpm` | Not supported |
| **Process scanning** | `ps` | `ps` | Not supported |
| **Network scanning** | `lsof` | `ss` (preferred) + `lsof` (fallback) | Not supported |
| **Root check** | `os.Getuid() == 0` | `os.Getuid() == 0` | Skipped |
| **Kernel modules** | kext detection | `.ko` file scanning | Not supported |

### macOS Notes

- Primary development and testing platform
- Homebrew (`brew`) is used for package inventory
- `lsof` is pre-installed on all macOS versions
- Some directories like `/System/Library` may require Full Disk Access in System Preferences

### Linux Notes

- `ss` (from `iproute2`) is preferred for network scanning; `lsof` is a fallback
- Package scanning supports both Debian (`dpkg-query`) and Red Hat (`rpm`) families
- Run with `sudo` for complete process and network visibility
- Kernel module scanning checks `/lib/modules/$(uname -r)/`

### Windows Notes

- Windows support is limited to passive file scanning (certificates, keys, libraries, binaries)
- Active scanning modules (processes, network, protocol) are not supported
- Package manager scanning is not supported
- Permission checks are skipped
- **Config file:** `%USERPROFILE%\.triton.yaml` (e.g. `C:\Users\<you>\.triton.yaml`)
- **Licence file:** `%USERPROFILE%\.triton\license.key`
- **Environment variables:** Use `$env:TRITON_*` (PowerShell) or `set TRITON_*` (cmd) — see [Configuration](#10-configuration) and [Licensing](#13-licensing) for examples
- **PATH:** Add the directory containing `triton.exe` to your `Path` environment variable via System Properties or PowerShell

---

## 15. Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Scan finds 0 results | Wrong profile or no crypto assets in scan targets | Try `--profile comprehensive` or check `triton doctor` |
| Network module finds nothing | Not running as root, or `lsof`/`ss` missing | Run with `sudo`; install missing tools |
| Process module finds nothing | Not running as root | Run with `sudo triton` |
| "permission denied" errors | Insufficient filesystem access | Run with `sudo` or adjust directory permissions |
| Progress bar doesn't appear | Running in non-interactive terminal | This is normal; headless mode shows text progress |
| Excel report is empty | No findings from the scan | Check scan output for errors; try a broader profile |
| Very slow scan | Comprehensive profile on large filesystem | Use `--profile quick` for initial triage; reduce with `--modules` |
| "command not found: triton" | Binary not in PATH | Add install directory to PATH or use full path `./bin/triton` |
| Report files not appearing | Wrong output directory | Check `--output-dir` flag; default is current directory |
| Policy verdict FAIL but scan succeeded | Policy rules triggered `fail` action | Exit code 1 is expected when policy violations are found; review the violations in the report |
| Licence shows free tier unexpectedly | Machine binding mismatch or expired token | Run `triton license show` to check fingerprint and expiry; re-issue token for current machine or use `--no-bind` |
| Policy section missing from HTML report | `--policy` flag not set | Add `--policy nacsa-2030` (or another policy) to include policy analysis in the HTML report |

### Getting Help

```bash
# Show all available commands and flags
triton --help

# Show doctor subcommand help
triton doctor --help

# Show version
triton --version
```

If you encounter a bug, please report it at: https://github.com/amiryahaya/triton/issues

---

## 16. Algorithm Reference

All algorithms recognized by Triton, grouped by PQC status. The "Break Year" column shows the estimated year a sufficiently powerful quantum computer could break the algorithm (where applicable).

### SAFE — Quantum-Resistant

| Algorithm | Family | Key Size | NIST Standard |
|-----------|--------|----------|---------------|
| AES-256-GCM | AES | 256-bit | Yes |
| AES-256-CBC | AES | 256-bit | Yes |
| AES-256-CTR | AES | 256-bit | Yes |
| AES-256-CCM | AES | 256-bit | Yes |
| AES-192-GCM | AES | 192-bit | Yes |
| AES-192-CBC | AES | 192-bit | Yes |
| AES-192-CTR | AES | 192-bit | Yes |
| ChaCha20-Poly1305 | ChaCha20 | 256-bit | No |
| Camellia-256 | Camellia | 256-bit | No |
| Twofish | Twofish | 256-bit | No |
| Serpent | Serpent | 256-bit | No |
| ARIA-256 | ARIA | 256-bit | No |
| SHA-384 | SHA2 | 384-bit | Yes |
| SHA-512 | SHA2 | 512-bit | Yes |
| SHA3-256 | SHA3 | 256-bit | Yes |
| SHA3-384 | SHA3 | 384-bit | Yes |
| SHA3-512 | SHA3 | 512-bit | Yes |
| BLAKE2b | BLAKE2 | 512-bit | No |
| BLAKE2s | BLAKE2 | 256-bit | No |
| HMAC-SHA256 | HMAC | 256-bit | No |
| HMAC-SHA512 | HMAC | 512-bit | No |
| Poly1305 | MAC | 256-bit | No |
| Bcrypt | Password-Hash | — | No |
| scrypt | KDF | — | No |
| Argon2 | KDF | — | No |
| PBKDF2 | KDF | — | No |
| HKDF | KDF | — | No |
| ML-KEM | Lattice | — | Yes (FIPS 203) |
| ML-DSA | Lattice | — | Yes (FIPS 204) |
| SLH-DSA | Hash-Based | — | Yes (FIPS 205) |
| SPHINCS+ | Hash-Based | — | Yes |
| FALCON | Lattice | — | No |
| FrodoKEM | Lattice | — | No |
| BIKE | Code-Based | — | No |
| HQC | Code-Based | — | No |
| Classic McEliece | Code-Based | — | No |
| NTRU | Lattice | — | No |
| SABER | Lattice | — | No |
| TLS 1.3 | TLS | — | No |
| WireGuard | VPN | — | No |
| QUIC | Transport | — | No |

### TRANSITIONAL — Needs Migration Plan

| Algorithm | Family | Key Size | Break Year |
|-----------|--------|----------|------------|
| AES-128-GCM | AES | 128-bit | — |
| AES-128-CBC | AES | 128-bit | — |
| AES-128-CTR | AES | 128-bit | — |
| AES-128-CCM | AES | 128-bit | — |
| SHA-256 | SHA2 | 256-bit | — |
| SHA-224 | SHA2 | 224-bit | — |
| SHA3-224 | SHA3 | 224-bit | — |
| HMAC-SHA1 | HMAC | 160-bit | — |
| CMAC | MAC | 128-bit | — |
| SipHash | MAC | 128-bit | — |
| RSA-2048 | RSA | 2048-bit | ~2035 |
| RSA-3072 | RSA | 3072-bit | ~2040 |
| RSA-4096 | RSA | 4096-bit | ~2045 |
| RSA-8192 | RSA | 8192-bit | ~2050 |
| ECDSA-P256 | ECDSA | 256-bit | ~2030 |
| ECDSA-P384 | ECDSA | 384-bit | ~2035 |
| ECDSA-P521 | ECDSA | 521-bit | ~2040 |
| Ed25519 | EdDSA | 256-bit | ~2035 |
| Ed448 | EdDSA | 448-bit | ~2040 |
| X25519 | ECDH | 256-bit | ~2035 |
| X448 | ECDH | 448-bit | ~2040 |
| DH | DH | — | ~2035 |
| ElGamal | ElGamal | — | ~2035 |
| Camellia-128 | Camellia | 128-bit | — |
| ARIA-128 | ARIA | 128-bit | — |
| SM4 | SM4 | 128-bit | — |
| SEED | SEED | 128-bit | — |
| Salsa20 | Salsa20 | 256-bit | — |
| SM3 | SM3 | 256-bit | — |
| TLS 1.2 | TLS | — | — |
| SSH | SSH | — | — |
| DTLS | TLS | — | — |
| IPsec | VPN | — | — |

### DEPRECATED — Replace Soon

| Algorithm | Family | Key Size | Break Year |
|-----------|--------|----------|------------|
| RSA-1024 | RSA | 1024-bit | ~2025 |
| DSA | DSA | — | ~2025 |
| ECDSA-P192 | ECDSA | 192-bit | ~2025 |
| SHA-1 | SHA1 | 160-bit | ~2025 |
| MD5 | MD5 | 128-bit | ~2020 |
| 3DES | DES | 168-bit | ~2025 |
| Blowfish | Blowfish | 128-bit | ~2025 |
| CAST5 | CAST5 | 128-bit | ~2025 |
| IDEA | IDEA | 128-bit | ~2025 |
| RIPEMD-160 | RIPEMD | 160-bit | ~2025 |
| Whirlpool | Whirlpool | 512-bit | — |
| Tiger | Tiger | 192-bit | — |
| HMAC-MD5 | HMAC | 128-bit | ~2020 |
| TLS 1.1 | TLS | — | — |
| TLS 1.0 | TLS | — | — |

### UNSAFE — Immediate Action Required

| Algorithm | Family | Key Size | Break Year |
|-----------|--------|----------|------------|
| DES | DES | 56-bit | ~2000 |
| RC4 | RC4 | — | ~2015 |
| RC2 | RC2 | — | ~2010 |
| MD4 | MD4 | 128-bit | ~2005 |
| NULL | NULL | 0-bit | — |
| SSL 2.0 | SSL | — | ~2010 |
| SSL 3.0 | SSL | — | ~2015 |

---

## 17. Glossary

| Term | Definition |
|------|------------|
| **SBOM** | Software Bill of Materials — a complete inventory of software components in a system |
| **CBOM** | Cryptographic Bill of Materials — an inventory of all cryptographic algorithms, protocols, and keys used by a system |
| **PQC** | Post-Quantum Cryptography — cryptographic algorithms designed to be secure against quantum computer attacks |
| **NACSA** | National Cyber Security Agency (Agensi Keselamatan Siber Negara) — Malaysia's cybersecurity authority |
| **NIST** | National Institute of Standards and Technology — US standards body leading PQC standardization |
| **CNSA 2.0** | Commercial National Security Algorithm Suite 2.0 — NSA's guidance on transitioning to quantum-resistant algorithms |
| **CycloneDX** | An OWASP standard for SBOM/CBOM data format (XML/JSON) |
| **Jadual 1** | Table 1 — the SBOM format mandated by Malaysian government for system inventory |
| **Jadual 2** | Table 2 — the CBOM format mandated by Malaysian government for cryptographic inventory |
| **ML-KEM** | Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203) — NIST's primary PQC key exchange standard |
| **ML-DSA** | Module-Lattice-Based Digital Signature Algorithm (FIPS 204) — NIST's primary PQC signature standard |
| **SLH-DSA** | Stateless Hash-Based Digital Signature Algorithm (FIPS 205) — NIST's hash-based PQC signature standard |
| **Shor's algorithm** | A quantum algorithm that can break RSA, ECC, and other public-key cryptosystems |
| **Grover's algorithm** | A quantum algorithm that halves the effective security of symmetric ciphers and hash functions |
| **Crypto-agility** | A system's ability to switch cryptographic algorithms without significant re-engineering |
| **TLS** | Transport Layer Security — the protocol securing HTTPS, email, and other network communications |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm — a public-key signature scheme |
| **RSA** | Rivest-Shamir-Adleman — a widely-used public-key cryptosystem |
| **AES** | Advanced Encryption Standard — a symmetric block cipher |
