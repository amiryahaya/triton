# Triton - SBOM/CBOM Scanner for PQC Compliance

[![CI](https://github.com/amiryahaya/triton/actions/workflows/ci.yml/badge.svg)](https://github.com/amiryahaya/triton/actions/workflows/ci.yml)

A lightweight, cross-platform CLI tool for generating Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) to assess Post-Quantum Cryptography (PQC) compliance.

**Target:** Malaysian government critical infrastructure sectors for 2030 PQC readiness.

## Features

- **All 9 CBOM scanning categories** — certificates, keys, libraries, binaries, kernel modules, scripts, web apps, network services, protocol probing
- **PQC classification** — every cryptographic asset rated SAFE / TRANSITIONAL / DEPRECATED / UNSAFE
- **Crypto-agility assessment** — evaluates each system's ability to migrate to PQC algorithms
- **Government-format Excel reports** — Jadual 1 (SBOM) and Jadual 2 (CBOM) in a single `.xlsx` workbook
- **Multiple output formats** — CycloneDX JSON, HTML dashboard, Excel (`.xlsx`)
- **Cross-platform** — macOS (primary), Linux, Windows
- **Fast & lightweight** — single binary (~17 MB), concurrent scanning with progress TUI

## Quick Start

```bash
# Clone and build
git clone https://github.com/amiryahaya/triton.git
cd triton
make build

# Run a quick scan
./bin/triton --profile quick

# Check version
./bin/triton --version
```

## Usage

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

Triton covers all 9 categories defined by the CBOM scanning framework:

| # | Category | Type | Module | Description |
|---|----------|------|--------|-------------|
| 1 | Binaries in use | Active/Runtime | `process` | Running processes with crypto libraries |
| 2 | Binaries on disk | Passive/File | `binary` | Executables with crypto patterns |
| 3 | Cryptographic libraries | Passive/File | `library` | libcrypto, libssl, mbedtls, etc. |
| 4 | Kernel modules | Passive/File | `kernel` | Crypto in `.ko` files (Linux) |
| 5 | Certificates & keys | Passive/File | `certificates`, `keys` | PEM/DER/PKCS certificates and private keys |
| 6 | Executable scripts | Passive/Code | `scripts` | Crypto calls in `.py`, `.sh`, `.rb`, etc. |
| 7 | Web applications | Passive/Code | `webapp` | Crypto patterns in `.php`, `.js`, `.go`, `.java` |
| 8 | Network applications | Active/Network | `network` | TLS/SSH/IPsec service detection on listening ports |
| 9 | Network protocols | Active/Network | `protocol` | Active TLS probing, cipher suite enumeration |

## Scan Profiles

| Profile | Categories | Depth | Workers | Use Case |
|---------|-----------|-------|---------|----------|
| `quick` | 2, 3, 5 | 3 | 4 | Fast check of critical crypto assets |
| `standard` | 1-7 | 10 | 8 | Balanced system assessment |
| `comprehensive` | 1-9 | Unlimited | 16 | Full audit including network probing |

## Output Formats

| Format | File | Description |
|--------|------|-------------|
| Excel | `Triton_PQC_Report.xlsx` | Government template with Jadual 1 (SBOM) + Jadual 2 (CBOM) sheets |
| JSON | `triton-report.json` | CycloneDX 1.6 format for toolchain integration |
| HTML | `triton-report.html` | Visual dashboard with PQC status charts |

The default (`--format all`) generates all three formats.

## PQC Classification

| Status | Description | Action Required |
|--------|-------------|-----------------|
| **SAFE** | Quantum-resistant (AES-256, SHA-384, SHA3, ML-KEM, ML-DSA) | Monitor |
| **TRANSITIONAL** | Needs migration plan (RSA-2048, ECDSA-P256, AES-128) | Plan replacement |
| **DEPRECATED** | Replace soon (RSA-1024, SHA-1, 3DES, MD5) | Schedule update |
| **UNSAFE** | Immediate vulnerability (DES, RC4, MD4, NULL) | Emergency fix |

## Architecture

```
┌────────────────────────────────────────────────────────┐
│  Triton CLI (Cobra + BubbleTea TUI)                    │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Scanner Engine (concurrent, semaphore-based)    │  │
│  │                                                  │  │
│  │  Passive/File        Passive/Code   Active       │  │
│  │  ├─ certificates     ├─ scripts     ├─ process   │  │
│  │  ├─ keys             └─ webapp      ├─ network   │  │
│  │  ├─ library                         └─ protocol  │  │
│  │  ├─ binary                                       │  │
│  │  ├─ kernel                                       │  │
│  │  └─ packages                                     │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌─────────────────┐  ┌────────────────────────────┐  │
│  │ PQC Classifier  │  │ Report Generator           │  │
│  │ + Agility Score │  │ ├─ Excel (.xlsx, gov fmt)  │  │
│  │                 │  │ ├─ CycloneDX JSON          │  │
│  │                 │  │ └─ HTML dashboard           │  │
│  └─────────────────┘  └────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

## Development

### Project Structure

```
triton/
├── cmd/                    # Cobra CLI + BubbleTea TUI
├── internal/
│   ├── config/             # Profile-based configuration (Viper)
│   └── version/            # Version (set via ldflags at build time)
├── pkg/
│   ├── scanner/            # Engine + 11 scanner modules
│   ├── crypto/             # PQC registry, classification, agility scoring
│   ├── model/              # Data model (ScanResult, System, Finding, CryptoAsset)
│   └── report/             # Excel, CycloneDX JSON, HTML generators
├── test/fixtures/          # Test certificates, keys, scripts, configs
└── docs/                   # Development plan, architecture, code review checklist
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

### MVP v0.1.0 (Released)

- [x] Phase 1: Foundation — data model, engine, config, test fixtures
- [x] Phase 2: File scanners — certificates, keys, libraries, binaries, kernel modules
- [x] Phase 3: Runtime & code scanners — processes, scripts, web apps, network, protocols
- [x] Phase 4: PQC assessment & reports — agility scoring, system grouping, Excel/JSON/HTML output
- [x] Phase 5: Polish — version management, benchmarks, cross-platform builds, documentation
- [x] CI/CD pipeline — GitHub Actions (lint + test + build) + GoReleaser releases

### NACSA-Ready v1.0 _(Priority: Critical)_

- [ ] CycloneDX CBOM v1.7 — proper crypto asset object modeling (algorithm, key, protocol, certificate)
- [ ] CNSA 2.0 / NIST IR 8547 timeline mapping — deprecation warnings per finding
- [ ] NACSA PQC framework alignment — urgent adopter classification, compliance columns
- [ ] PQC algorithm detection — ML-KEM, ML-DSA, SLH-DSA, FN-DSA OIDs in certificates
- [ ] Hybrid certificate detection — RSA + ML-DSA composite certs
- [ ] CAMM-aligned crypto-agility scoring — Level 0-4 maturity framework
- [ ] Config scanner expansion — sshd_config, crypto-policies
- [ ] `triton doctor` — pre-scan environment check (permissions, tool availability, system access)

### Enterprise v2.0 _(Priority: Low)_

- [ ] Enhanced TLS probing — cipher preference order, chain validation, TLS 1.0/1.1 warnings
- [ ] Incremental scanning — skip unchanged files using modification time + hash cache
- [ ] Container image scanning — crypto-specific Docker/OCI layer analysis
- [ ] Enterprise licensing — license key validation, feature gating, seat management
- [ ] Client-server mode — agent reports to central server
- [ ] Cloud KMS scanning — AWS KMS, Azure Key Vault, GCP KMS
- [ ] Dependency crypto reachability — call graph analysis for transitive Go dependencies
- [ ] Web UI dashboard
- [ ] PKCS#11 / HSM scanning

## CI/CD

The project uses GitHub Actions for continuous integration:

- **CI** — runs on every push to `main` and PRs: lint (golangci-lint), test (with race detector, 75% coverage gate), build verification
- **Release** — triggered by `v*` tags: runs tests, then GoReleaser cross-compiles 5 binaries and creates a GitHub Release with checksums

## Requirements

- Go 1.24+
- macOS, Linux, or Windows

## License

MIT License - See LICENSE file

## Acknowledgments

- CycloneDX standard by OWASP
- PQC guidance from NIST IR 8413
