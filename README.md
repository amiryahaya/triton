# Triton - SBOM/CBOM Scanner for PQC Compliance

[![CI](https://github.com/amiryahaya/triton/actions/workflows/ci.yml/badge.svg)](https://github.com/amiryahaya/triton/actions/workflows/ci.yml)

An enterprise-grade, cross-platform CLI + server tool for generating Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) to assess Post-Quantum Cryptography (PQC) compliance. Aligned with the NACSA PQC framework and CNSA 2.0 migration timeline.

**Target:** Malaysian government critical infrastructure sectors for 2030 PQC readiness.

## Features

- **29 scanner modules across 9 CBOM categories + enterprise infrastructure** — certificates, keys, libraries, binaries, kernel modules, scripts, web apps, configs, network services, protocol probing, containers, cert stores (incl. Windows Root store + Java cacerts), databases, HSM, LDAP, code signing (incl. Windows Authenticode + JAR + git tags), dependency reachability (Go + Python + Node + Java), web server TLS (nginx/Apache/haproxy/Caddy), VPN (IPsec/WireGuard/OpenVPN), container supply chain (cosign/Notary/K8s SA tokens), service mesh mTLS (Istio/Linkerd/Consul), password hashing posture (/etc/shadow/PAM/pg_hba), auth material (Kerberos keytabs/GPG/Tor/DNSSEC/802.1X), XML DSig/SAML, mail server crypto (Postfix/Sendmail/DKIM)
- **Static + active scanning** — passive file/code analysis plus runtime process inspection and active TLS/network probing
- **Multi-language dependency reachability** — Go, Python, Node.js, and Java crypto library inventory from lockfiles/manifests; Go additionally gets full import graph classification (direct/transitive/unreachable)
- **PQC algorithm detection** — ML-KEM, ML-DSA, SLH-DSA OID recognition in X.509 certificates, including hybrid/composite certs
- **PQC classification** — every cryptographic asset rated SAFE / TRANSITIONAL / DEPRECATED / UNSAFE
- **NACSA PQC framework** — Malaysian compliance labels (Patuh / Dalam Peralihan / Tidak Patuh / Perlu Tindakan Segera)
- **CNSA 2.0 & NIST IR 8547** — deprecation timeline warnings (2027/2030/2035 milestones) per finding
- **CAMM crypto-agility scoring** — Level 0–4 maturity assessment per system
- **Policy engine** — built-in NACSA-2030 and CNSA-2.0 policies, plus custom YAML rules
- **REST API server** — go-chi based HTTP server with embedded web UI dashboard
- **PostgreSQL storage** — scan history, diff/trend analysis, incremental scanning
- **3-tier licensing** — Ed25519-signed licence keys with free/pro/enterprise feature gating
- **License server** — Centralized seat pool management, online validation, admin web UI
- **Government-format Excel reports** — Jadual 1 (SBOM) and Jadual 2 (CBOM) in a single `.xlsx` workbook
- **Multiple output formats** — CycloneDX 1.7 CBOM JSON, HTML dashboard, Excel (`.xlsx`), SARIF
- **Cross-platform** — macOS (primary), Linux, Windows
- **Fast & lightweight** — single binary, concurrent scanning with progress TUI

## Quick Start

```bash
# Clone and build
git clone https://github.com/amiryahaya/triton.git
cd triton
make build

# Check system readiness
./bin/triton doctor

# Run a quick scan
./bin/triton --profile quick

# Check version
./bin/triton --version
```

> **New to Triton?** See the full [User Manual](docs/USER_MANUAL.md) for detailed guidance on scan profiles, report interpretation, and troubleshooting.

## Usage

### Pre-flight Check

```bash
# Check system readiness for the default (standard) profile
./bin/triton doctor

# Check readiness for a specific profile
./bin/triton doctor --profile comprehensive
```

### Scanning

```bash
# Quick scan — certificates, keys, packages (depth 3, 4 workers)
./bin/triton --profile quick

# Standard scan — adds libraries, services (depth 10, 8 workers)
./bin/triton --profile standard

# Comprehensive scan — all categories, unlimited depth (16 workers)
./bin/triton --profile comprehensive

# Specific output format
./bin/triton --format xlsx          # Excel only
./bin/triton --format json          # CycloneDX JSON only
./bin/triton --format html          # HTML dashboard only
./bin/triton --format all           # All formats (default)

# Run specific modules only
./bin/triton --modules certificates,keys

# Custom output directory
./bin/triton --output-dir ./reports
```

### Scanning container images

Triton can scan OCI container images directly without running them. The
image is pulled to a sandboxed tmpfs, layers are flattened, and the
existing filesystem modules (certificates, keys, libraries, binaries,
deps, configs) run against the extracted rootfs.

```bash
# Scan a single public image
triton --image nginx:1.25 --profile standard

# Scan multiple images
triton --image nginx:1.25 --image redis:7 --format json -o scan.json

# Private registry with explicit auth
triton --image myregistry.io/myapp:v1.0 --registry-auth /path/to/docker-config.json
```

OCI image scanning is a **Pro tier** feature. The host filesystem is
**not** scanned when `--image` is set.

## Scanning Categories

Triton covers all 9 CBOM categories plus enterprise infrastructure with **29 scanner modules**:

### CBOM Core (19 modules)

| # | Category | Type | Module(s) | Description |
|---|----------|------|-----------|-------------|
| 1 | Binaries in use | Active/Runtime | `process` | Running processes with crypto libraries |
| 2 | Binaries on disk | Passive/File | `binary` | Executables with crypto patterns |
| 3 | Cryptographic libraries | Passive/File | `library` | libcrypto, libssl, mbedtls, etc. |
| 4 | Kernel modules | Passive/File | `kernel` | Crypto in `.ko` files (Linux) |
| 5 | Certificates & keys | Passive/File | `certificates`, `keys`, `certstore` | PEM/DER/PKCS certs, private keys, SSH host keys, OS cert stores (Linux / macOS / **Windows Root store** / **Java cacerts**) |
| 6 | Executable scripts | Passive/Code | `scripts` | Crypto calls in `.py`, `.sh`, `.rb`, etc. |
| 7 | Web applications | Passive/Code | `webapp` | Crypto patterns in `.php`, `.js`, `.go`, `.java` |
| 8 | Configuration files | Passive/File | `configs` | sshd_config, crypto-policies, java.security |
| 9 | Network applications | Active/Network | `network` | TLS/SSH/IPsec service detection on listening ports |
| 10 | Network protocols | Active/Network | `protocol` | Active TLS probing, cipher suite enumeration |
| — | Packages | Passive/System | `packages` | OS package manager crypto inventory |
| — | Containers | Passive/File | `container` | Dockerfile, compose, Kubernetes config scanning |
| — | Databases | Passive/File | `database` | Database crypto configuration scanning |
| — | HSM/PKCS#11 | Active | `hsm` | Hardware security module detection |
| — | LDAP | Active/Network | `ldap` | LDAP/AD crypto configuration scanning |
| — | Code signing | Passive/File | `codesign` | macOS codesign, Linux RPM/deb, **Windows Authenticode** (osslsigncode), **JAR/WAR/EAR** (jarsigner), **git tag signatures** |
| — | Go dependencies | Passive/Code | `deps` | Go module import graph analysis (direct/transitive/unreachable classification) |

### Enterprise Infrastructure (9 modules)

| Module | Type | Description |
|--------|------|-------------|
| `web_server` | Passive/File | **nginx, Apache, haproxy, Caddy** TLS configs — `ssl_protocols`, `ssl_ciphers`, ECDH curves, HSTS |
| `vpn` | Passive/File | **strongSwan IPsec, WireGuard, OpenVPN** — IKE proposals, DH groups, PFS, cipher lists, TLS min version, `tls-groups` ECDH curves |
| `container_signatures` | Passive/File | **cosign / Sigstore** keys + metadata, **Docker Notary** v1 trust store, **Kubernetes service account JWTs** (header inspection, payload never serialized), **K8s encryption-at-rest provider config** (with identity-first PLAINTEXT warning) |
| `service_mesh` | Passive/File | **Istio, Linkerd, Consul Connect** workload identity certs — vendor-tagged so reports aggregate per mesh |
| `password_hash` | Passive/File | **/etc/shadow** per-user hash algorithm (MD5-crypt / SHA-256 / SHA-512 / bcrypt / yescrypt / Argon2 / DES-crypt), **PAM** stack policy, **pg_hba.conf** PostgreSQL auth methods |
| `auth_material` | Passive/File | **Kerberos keytabs** (RFC 3961 enctype decoder, detects legacy DES / RC4), **GPG keyrings** (RFC 4880 pubkey algos), **802.1X** wpa_supplicant / NetworkManager, **Tor v3** hidden service Ed25519 keys, **DNSSEC** BIND zone-signing keys, **systemd** encrypted credentials |
| `deps_ecosystems` | Passive/File | **Python** (requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock), **Node** (package.json, package-lock.json, yarn.lock), **Java** (pom.xml, build.gradle, build.gradle.kts, gradle.lockfile) crypto library inventory |
| `xml_dsig` | Passive/File | **SAML IdP/SP metadata** and signed XML — extracts `<SignatureMethod>` + `<DigestMethod>` algorithm URIs from the xmldsig-core namespace |
| `mail_server` | Passive/File | **Postfix** (main.cf smtpd_tls_* with multi-line continuations), **Sendmail**, **Exim**, **OpenDKIM** KeyTable + SignatureAlgorithm, **DKIM** private key file presence |

> **Security note:** sensitive key material is NEVER serialized into findings. WireGuard PrivateKey, K8s SA token bodies, /etc/shadow hash values, DKIM key bytes, and Kerberos keyblock contents are all redacted at the parser layer — only metadata (algorithm, principal name, file path, owner) reaches the report.

## Scan Profiles

| Profile | Modules | Depth | Workers | Use Case |
|---------|---------|-------|---------|----------|
| `quick` | certificates, keys, packages (3 modules) | 3 | 4 | Fast check of critical crypto assets |
| `standard` | certificates, keys, packages, libraries, binaries, scripts, webapp, configs, containers, certstore, database, deps, web_server, vpn, password_hash, deps_ecosystems, mail_server (17 modules) | 10 | 8 | Balanced system + infrastructure + multi-language dependency assessment |
| `comprehensive` | All 28 modules (+ kernel, processes, network, protocol, hsm, ldap, codesign, container_signatures, auth_material, service_mesh, xml_dsig) | Unlimited | 16 | Full audit including network probing, supply chain, service mesh, SAML, Kerberos, etc. |

## Output Formats

| Format | File | Description |
|--------|------|-------------|
| Excel | `Triton_PQC_Report.xlsx` | Government template with Jadual 1 (SBOM) + Jadual 2 (CBOM) sheets |
| JSON | `triton-report.json` | CycloneDX 1.7 CBOM for toolchain integration |
| HTML | `triton-report.html` | Visual dashboard with PQC status charts |
| SARIF | `triton-report.sarif` | Static Analysis Results Interchange Format (enterprise tier) |

The default (`--format all`) generates all available formats for your licence tier.

## PQC Classification

| Status | Description | Action Required |
|--------|-------------|-----------------|
| **SAFE** | Quantum-resistant (AES-256, SHA-384, SHA3, ML-KEM, ML-DSA) | Monitor |
| **TRANSITIONAL** | Needs migration plan (RSA-2048, ECDSA-P256, AES-128) | Plan replacement |
| **DEPRECATED** | Replace soon (RSA-1024, SHA-1, 3DES, MD5) | Schedule update |
| **UNSAFE** | Immediate vulnerability (DES, RC4, MD4, NULL) | Emergency fix |

## Policy Engine

Triton includes two built-in compliance policies. Without `--policy`, Triton scans and classifies findings but does not produce a PASS/FAIL verdict. Adding `--policy` enforces rules against every finding.

```bash
# Scan without policy (classification only, no verdict)
./bin/triton --profile comprehensive

# Scan with NACSA-2030 policy (Malaysian government compliance)
./bin/triton --profile comprehensive --policy nacsa-2030

# Scan with CNSA 2.0 policy (US national security compliance)
./bin/triton --profile comprehensive --policy cnsa-2.0

# Scan with custom policy (enterprise tier)
./bin/triton --profile comprehensive --policy ./my-policy.yaml
```

### Built-in Policy Comparison

| Rule | NACSA-2030 | CNSA 2.0 |
|------|-----------|----------|
| UNSAFE algorithms (DES, RC4, SSL, NULL) | FAIL | FAIL |
| DEPRECATED algorithms | warn | warn |
| RSA minimum key size | **2048** bits | **3072** bits |
| ECDSA minimum curve | _(not checked)_ | **P-384** required |
| SHA-256 | allowed | **warn** (prefers SHA-384+) |
| MD5 | FAIL | caught by DEPRECATED |
| SHA-1 | warn | caught by DEPRECATED |
| DES/3DES | FAIL | caught by UNSAFE |
| RC4 | FAIL | caught by UNSAFE |

| Threshold | NACSA-2030 | CNSA 2.0 |
|-----------|-----------|----------|
| Max UNSAFE count | 0 | 0 |
| Min readiness | 60% NACSA-ready | 50% SAFE |

**NACSA-2030** targets Malaysian government PQC readiness with granular rules for specific weak algorithms and NACSA compliance labels (Patuh / Dalam Peralihan / Tidak Patuh / Perlu Tindakan Segera).

**CNSA 2.0** targets US national security with stricter key size minimums (RSA ≥ 3072, ECDSA ≥ P-384) and preference for SHA-384+ over SHA-256.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Triton CLI (Cobra + BubbleTea TUI)         Licence Guard        │
│  ├─ triton scan (default)                   ├─ Ed25519 signed    │
│  ├─ triton server (report server, ent.)     ├─ 3-tier gating     │
│  ├─ triton agent (enterprise)               └─ graceful degrade  │
│  ├─ triton diff/trend/history (pro+)                             │
│  ├─ triton policy (pro+)                                         │
│  └─ triton license show/verify                                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Scanner Engine (concurrent, semaphore-based) — 28 modules │  │
│  │                                                            │  │
│  │  Passive/File       Passive/Code  Active       Specialized │  │
│  │  ├─ certificates    ├─ scripts    ├─ process   ├─ database │  │
│  │  ├─ keys            ├─ webapp     ├─ network   ├─ hsm      │  │
│  │  ├─ library         └─ deps       └─ protocol  ├─ ldap     │  │
│  │  ├─ binary                                     └─ codesign │  │
│  │  ├─ kernel          System                                 │  │
│  │  ├─ configs         ├─ packages                            │  │
│  │  ├─ certstore       └─ container                           │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────────┐ │
│  │ PQC Classifier  │ │ Report Gen      │ │ Policy Engine      │ │
│  │ ├─ Algo registry│ │ ├─ Excel (gov)  │ │ ├─ NACSA-2030      │ │
│  │ ├─ NACSA        │ │ ├─ CycloneDX    │ │ ├─ CNSA-2.0        │ │
│  │ ├─ CNSA 2.0     │ │ ├─ HTML         │ │ └─ Custom YAML     │ │
│  │ ├─ CAMM scoring │ │ └─ SARIF        │ │                    │ │
│  │ └─ OID detection│ │                 │ │                    │ │
│  └─────────────────┘ └─────────────────┘ └────────────────────┘ │
│                                                                  │
│  ┌──────────────────────┐  ┌──────────────────────────────────┐ │
│  │ REST API Server      │  │ PostgreSQL Storage               │ │
│  │ ├─ go-chi/chi/v5     │  │ ├─ Scan history + JSONB results │ │
│  │ ├─ Embedded Web UI   │  │ ├─ Diff/trend analysis          │ │
│  │ └─ Chart.js dashboard│  │ └─ Incremental scan support     │ │
│  └──────────────────────┘  └──────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Development

### Project Structure

```
triton/
├── cmd/                    # Cobra CLI commands (scan, server, agent, diff, trend, policy, license)
├── internal/
│   ├── config/             # Profile-based configuration
│   ├── license/            # Ed25519 licence system (token, guard, tier, keygen)
│   └── version/            # Version (set via ldflags at build time)
├── pkg/
│   ├── scanner/            # Engine + 29 scanner modules
│   ├── crypto/             # PQC registry, OID detection, NACSA, CNSA 2.0, CAMM
│   ├── model/              # Data model (ScanResult, System, Finding, CryptoAsset)
│   ├── report/             # Excel, CycloneDX 1.7 CBOM, HTML, SARIF generators
│   ├── server/             # REST API server (go-chi) + embedded web UI
│   ├── store/              # PostgreSQL storage (pgx/v5)
│   ├── policy/             # YAML policy engine + built-in policies
│   ├── diff/               # Scan comparison and trend analysis
│   └── agent/              # HTTP agent for remote scan submission
├── test/fixtures/          # Test certificates, keys, scripts, configs
└── docs/                   # Development plan, architecture, user manual
```

### Build & Test Commands

```bash
make build          # Build for current platform → bin/triton
make build-all      # Cross-compile (macOS/Linux/Windows, amd64/arm64)
make test           # Run all tests
make bench          # Run benchmarks
make vet            # Run go vet
make fmt            # Format code
make lint           # Lint (golangci-lint)
make clean          # Remove bin/
```

### Running Tests

```bash
# All tests with coverage
go test -cover ./...

# Single test
go test -v -run TestCertificateParsing ./pkg/scanner

# Benchmarks
go test -bench=. -benchmem ./pkg/scanner/ ./pkg/crypto/
```

## Roadmap

### MVP v0.1 (Released)

- [x] Phase 1: Foundation — data model, engine, config, test fixtures
- [x] Phase 2: File scanners — certificates, keys, libraries, binaries, kernel modules
- [x] Phase 3: Runtime & code scanners — processes, scripts, web apps, network, protocols
- [x] Phase 4: PQC assessment & reports — agility scoring, system grouping, Excel/JSON/HTML output
- [x] Phase 5: Polish — version management, benchmarks, cross-platform builds, documentation
- [x] CI/CD pipeline — GitHub Actions (lint + test + build) + GoReleaser releases

### NACSA-Ready v1.0 (Released)

- [x] CycloneDX CBOM v1.7 — proper crypto asset object modeling
- [x] CNSA 2.0 / NIST IR 8547 timeline mapping — deprecation warnings per finding
- [x] NACSA PQC framework alignment — urgent adopter classification, compliance columns
- [x] PQC algorithm detection — ML-KEM, ML-DSA, SLH-DSA OIDs in certificates
- [x] Hybrid certificate detection — RSA + ML-DSA composite certs
- [x] CAMM-aligned crypto-agility scoring — Level 0–4 maturity framework
- [x] Config scanner, algorithm normalization, reverse OID lookup, `triton doctor`

### Enterprise v2.0 (Released)

- [x] REST API server — go-chi/chi/v5 with embedded web UI (Chart.js dashboard)
- [x] PostgreSQL storage — scan history, JSONB results, incremental scanning
- [x] Policy engine — built-in NACSA-2030 and CNSA-2.0 policies, custom YAML rules
- [x] Diff/trend analysis — scan comparison with composite-key matching
- [x] Agent mode — HTTP client for remote scan submission to central server
- [x] Container scanner — Dockerfile, compose, Kubernetes config scanning
- [x] OS cert store scanner — system certificate store scanning
- [x] Database, HSM, LDAP, code signing scanners

### v2.1 SARIF + Additional Scanners (Released)

- [x] SARIF output format for IDE/CI integration
- [x] Expanded scanner coverage to 18 modules

### v2.2 Dependency Reachability (Released)

- [x] Go module dependency crypto reachability analysis (19th module)
- [x] Import graph BFS with direct/transitive/unreachable classification
- [x] Migration priority adjustment for unreachable findings

### v2.3 Licensing (Released)

- [x] Ed25519-signed licence tokens (offline validation, no phone-home)
- [x] 3-tier feature gating: free, pro, enterprise
- [x] Graceful degradation — invalid/expired licence = free tier
- [x] `triton license show/verify` subcommands
- [x] Guard-based enforcement on profiles, formats, modules, and subcommands

### v2.4 Enhanced TLS Probing (Released)

- [x] TLS version range probing (individual version testing)
- [x] Cipher suite enumeration (all TLS 1.2 suites individually tested)
- [x] Cipher preference order detection (iterative removal)
- [x] Key exchange / forward secrecy analysis (ECDHE, DHE, RSA, TLS13)
- [x] Enhanced certificate chain validation (weak signatures, expiry warnings, SANs)

### v3.0 License Server (Released)

- [x] Centralized license server with org-based seat pool management
- [x] Online validation with 7-day offline fallback grace period
- [x] Admin web UI (dashboard, org/license/activation management, audit log)

### v3.1 Coverage + Supply Chain (Released)

- [x] **Web server TLS configs** — nginx, Apache, haproxy, Caddy `ssl_protocols`, `ssl_ciphers`, ECDH curves, HSTS
- [x] **VPN scanner** — strongSwan IPsec, WireGuard, OpenVPN cipher/protocol/PFS inventory (incl. OpenVPN `tls-groups` ECDH curve classification)
- [x] **Container supply chain** — cosign/Sigstore keys + TUF root, Docker Notary v1 trust store, Kubernetes service account JWT header inspection, K8s encryption-at-rest provider walker with identity-first PLAINTEXT warning
- [x] **Authenticode** — cross-platform PE (.exe/.dll/.msi/.sys/.cab) signature verification via `osslsigncode`
- [x] **JAR signing** — .jar/.war/.ear signature verification via `jarsigner`
- [x] **SSH server host keys** — `/etc/ssh/ssh_host_*_key` matcher extension

### v3.2 Fast Wins + Enterprise Coverage (This Release)

- [x] **Windows Root cert store** — via PowerShell `Get-ChildItem Cert:\LocalMachine\Root` with bounded subprocess stdout
- [x] **Java cacerts keystore** — auto-discovery across JAVA_HOME/JDK_HOME/OS-specific roots + `keytool -list -rfc`
- [x] **Password hash posture** — /etc/shadow per-user algorithm detection, PAM stack policy, pg_hba.conf PostgreSQL auth methods
- [x] **Kerberos keytabs** — binary parser (RFC 3961 enctypes; detects legacy DES/RC4-arcfour)
- [x] **GPG keyrings** — `gpg --list-keys --with-colons` parser covering RFC 4880 pubkey algorithms
- [x] **802.1X / Wi-Fi auth** — wpa_supplicant.conf + NetworkManager .nmconnection (EAP-TLS/TTLS/PEAP classification)
- [x] **Tor v3 hidden service keys** — Ed25519 signing key detection
- [x] **DNSSEC zone-signing keys** — BIND `K*.private` filename → algorithm mapping
- [x] **systemd encrypted credentials** — `LoadCredentialEncrypted=` / `SetCredentialEncrypted=` detection
- [x] **Git tag + commit signatures** — `git tag -v` GPG/SSH output parser
- [x] **Multi-language dep reachability** — Python (requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock), Node (package.json, package-lock.json, yarn.lock), Java (pom.xml with `<dependencyManagement>` stripping, build.gradle, build.gradle.kts)
- [x] **Service mesh mTLS** — Istio, Linkerd, Consul Connect workload identity cert detection
- [x] **XML DSig / SAML** — xmldsig-core SignatureMethod + DigestMethod algorithm extraction from SAML IdP/SP metadata
- [x] **Mail server crypto** — Postfix (multi-line continuations supported), Sendmail, Exim TLS configs + OpenDKIM KeyTable + DKIM private key files
- [x] **Memory-safe subprocess handling** — bounded stdout (32 MB Java cacerts, 16 MB Windows Root store) via `io.LimitReader`
- [x] **Adversarial-input hardening** — keytab parser uint32 arithmetic with bounds checks; all regex non-backtracking (Go RE2)
- [x] `triton license activate/deactivate` CLI commands
- [x] SHA-3-256 machine fingerprinting (upgraded from SHA-256)
- [x] PostgreSQL-backed license store with serializable seat enforcement
- [x] Containerized deployment with Docker Compose

## Licensing

Triton uses a 3-tier licence system. Without a licence key, Triton runs in **free tier** — fully functional but limited to quick profile, JSON output, and 3 scanner modules (certificates, keys, packages).

### Tiers

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Profile: quick | Yes | Yes | Yes |
| Profile: standard/comprehensive | — | Yes | Yes |
| Scanner modules | 3 | All 28 | All 28 |
| Format: JSON | Yes | Yes | Yes |
| Format: CDX, HTML, XLSX | — | Yes | Yes |
| Format: SARIF | — | — | Yes |
| Server mode | — | — | Yes |
| Agent mode | — | — | Yes |
| Policy engine (builtin) | — | Yes | Yes |
| Policy engine (custom YAML) | — | — | Yes |
| Metrics, incremental, diff/trend | — | Yes | Yes |
| DB persistence | — | Yes | Yes |

### Setting a Licence Key

```bash
# Via CLI flag
triton --license-key <token> --profile standard

# Via environment variable
export TRITON_LICENSE_KEY=<token>
triton --profile standard

# Via file (persists across sessions)
echo "<token>" > ~/.triton/license.key
triton --profile standard
```

Precedence: CLI flag > environment variable > file.

### License Server (Centralized Management)

For organizations managing multiple machines, the license server provides centralized seat pool management:

```bash
# Activate this machine (one-time setup)
triton license activate \
  --license-server http://license-server:8081 \
  --license-id <license-uuid>

# Deactivate when decommissioning
triton license deactivate
```

#### Agent installation — bundle and one-liner

The license server admin UI (`/ui/#/licenses/<id>`) supports two zero-touch agent installation flows for distributing the binary + config to end-users:

**Bundle download** — pick a platform (Linux amd64/arm64, macOS arm64, Windows amd64), click **Download bundle**, and receive a `.tar.gz` or `.zip` containing the binary, a pre-baked `agent.yaml`, and an install script. The install script handles directory creation, file permissions, and (on macOS) Gatekeeper quarantine removal automatically.

- Linux/macOS install path: `/opt/triton/` (binary + agent.yaml + reports/)
- Windows install path: `C:\Program Files\Triton\` (binary + agent.yaml + reports\)

**One-liner install** — click **Copy install command** and share the command with your operator:

```bash
curl -sSL 'https://license.example.com/api/v1/install/<TOKEN>' | sudo bash
```

The token is valid for 24 hours. The install script auto-detects the host OS/arch, downloads the correct binary and agent.yaml, and installs everything to `/opt/triton/` with correct permissions. Set `TRITON_LICENSE_SERVER_PUBLIC_URL` on the license server to enable this flow.

See [§7f of the Deployment Guide](docs/DEPLOYMENT_GUIDE.md#7f-fool-proof-agent-installation-bundle--one-liner) for full details, install paths, and troubleshooting (macOS Gatekeeper, Windows SmartScreen, permission errors).

See the [License Server Guide](docs/LICENSE_SERVER_GUIDE.md) for full setup instructions.

### Verifying a Licence

```bash
# Show current licence info
triton license show

# Verify a specific token
triton license verify <token>
```

## CI/CD

The project uses GitHub Actions for continuous integration:

- **CI** — runs on every push to `main` and PRs: lint (golangci-lint), test (with race detector, 75% coverage gate), build verification
- **Release** — triggered by `v*` tags: runs tests, then GoReleaser cross-compiles 5 binaries and creates a GitHub Release with checksums

## Requirements

- Go 1.21+ (1.25 recommended)
- macOS, Linux, or Windows
- PostgreSQL 18 (optional, for server mode and scan history)

## License

MIT License - See LICENSE file

## Acknowledgments

- CycloneDX CBOM standard by OWASP
- PQC guidance from NIST IR 8413 and CNSA 2.0
- NACSA (National Cyber Security Agency of Malaysia) PQC framework
