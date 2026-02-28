# Triton - SBOM/CBOM Scanner for PQC Compliance

[![CI](https://github.com/amiryahaya/triton/actions/workflows/ci.yml/badge.svg)](https://github.com/amiryahaya/triton/actions/workflows/ci.yml)

An enterprise-grade, cross-platform CLI + server tool for generating Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) to assess Post-Quantum Cryptography (PQC) compliance. Aligned with the NACSA PQC framework and CNSA 2.0 migration timeline.

**Target:** Malaysian government critical infrastructure sectors for 2030 PQC readiness.

## Features

- **19 scanner modules across 9 CBOM categories** — certificates, keys, libraries, binaries, kernel modules, scripts, web apps, configs, network services, protocol probing, containers, cert stores, databases, HSM, LDAP, code signing, dependency reachability
- **Static + active scanning** — passive file/code analysis plus runtime process inspection and active TLS/network probing
- **Dependency crypto reachability** — Go module import graph analysis classifying crypto as direct, transitive, or unreachable
- **PQC algorithm detection** — ML-KEM, ML-DSA, SLH-DSA OID recognition in X.509 certificates, including hybrid/composite certs
- **PQC classification** — every cryptographic asset rated SAFE / TRANSITIONAL / DEPRECATED / UNSAFE
- **NACSA PQC framework** — Malaysian compliance labels (Patuh / Dalam Peralihan / Tidak Patuh / Perlu Tindakan Segera)
- **CNSA 2.0 & NIST IR 8547** — deprecation timeline warnings (2027/2030/2035 milestones) per finding
- **CAMM crypto-agility scoring** — Level 0–4 maturity assessment per system
- **Policy engine** — built-in NACSA-2030 and CNSA-2.0 policies, plus custom YAML rules
- **REST API server** — go-chi based HTTP server with embedded web UI dashboard
- **PostgreSQL storage** — scan history, diff/trend analysis, incremental scanning
- **3-tier licensing** — Ed25519-signed licence keys with free/pro/enterprise feature gating
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

## Scanning Categories

Triton covers all 9 CBOM categories with 19 scanner modules:

| # | Category | Type | Module(s) | Description |
|---|----------|------|-----------|-------------|
| 1 | Binaries in use | Active/Runtime | `process` | Running processes with crypto libraries |
| 2 | Binaries on disk | Passive/File | `binary` | Executables with crypto patterns |
| 3 | Cryptographic libraries | Passive/File | `library` | libcrypto, libssl, mbedtls, etc. |
| 4 | Kernel modules | Passive/File | `kernel` | Crypto in `.ko` files (Linux) |
| 5 | Certificates & keys | Passive/File | `certificates`, `keys`, `certstore` | PEM/DER/PKCS certs, private keys, OS cert stores |
| 6 | Executable scripts | Passive/Code | `scripts` | Crypto calls in `.py`, `.sh`, `.rb`, etc. |
| 7 | Web applications | Passive/Code | `webapp` | Crypto patterns in `.php`, `.js`, `.go`, `.java` |
| 8 | Configuration files | Passive/File | `configs` | sshd_config, crypto-policies, java.security |
| 9 | Network applications | Active/Network | `network` | TLS/SSH/IPsec service detection on listening ports |
| 10 | Network protocols | Active/Network | `protocol` | Active TLS probing, cipher suite enumeration |
| — | Packages | Passive/System | `packages` | OS package manager crypto inventory |
| — | Containers | Passive/File | `container` | Dockerfile, compose, Kubernetes config scanning |
| — | Databases | Passive/File | `database` | Database crypto configuration scanning |
| — | HSM/PKCS#11 | Passive/File | `hsm` | Hardware security module detection |
| — | LDAP | Active/Network | `ldap` | LDAP/AD crypto configuration scanning |
| — | Code signing | Passive/File | `codesign` | Code signing certificate detection |
| — | Dependencies | Passive/Code | `deps` | Go module crypto reachability analysis |

## Scan Profiles

| Profile | Modules | Depth | Workers | Use Case |
|---------|---------|-------|---------|----------|
| `quick` | certificates, keys, packages (3 modules) | 3 | 4 | Fast check of critical crypto assets |
| `standard` | + libraries, binaries, scripts, webapp, configs, containers, certstore, database, deps (12 modules) | 10 | 8 | Balanced system assessment |
| `comprehensive` | All 19 modules (+ kernel, processes, network, protocol, hsm, ldap, codesign) | Unlimited | 16 | Full audit including network probing |

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

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Triton CLI (Cobra + BubbleTea TUI)         Licence Guard        │
│  ├─ triton scan (default)                   ├─ Ed25519 signed    │
│  ├─ triton server (enterprise)              ├─ 3-tier gating     │
│  ├─ triton agent (enterprise)               └─ graceful degrade  │
│  ├─ triton diff/trend/history (pro+)                             │
│  ├─ triton policy (pro+)                                         │
│  └─ triton license show/verify                                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Scanner Engine (concurrent, semaphore-based) — 19 modules │  │
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
│   ├── scanner/            # Engine + 19 scanner modules
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

### Future

_(none planned)_

## Licensing

Triton uses a 3-tier licence system. Without a licence key, Triton runs in **free tier** — fully functional but limited to quick profile, JSON output, and 3 scanner modules (certificates, keys, packages).

### Tiers

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Profile: quick | Yes | Yes | Yes |
| Profile: standard/comprehensive | — | Yes | Yes |
| Scanner modules | 3 | All 19 | All 19 |
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
