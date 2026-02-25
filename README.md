# Triton - SBOM/CBOM Scanner for PQC Compliance

A lightweight, cross-platform scanner for generating Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) to support Post-Quantum Cryptography (PQC) compliance.

**Target:** Malaysian government critical sectors for 2030 PQC readiness.

## Features

- 🔍 **Multi-module scanning:** Certificates, keys, packages, libraries, services
- ⚡ **Fast & lightweight:** Written in Go, single binary, low memory footprint
- 🖥️ **Cross-platform:** Windows, macOS, Linux
- 📊 **Multiple output formats:** CycloneDX JSON, CSV, HTML
- 🛡️ **PQC classification:** SAFE, TRANSITIONAL, DEPRECATED, UNSAFE
- 📈 **Progress tracking:** Real-time scan progress with beautiful TUI

## Installation

```bash
# Clone the repository
git clone https://github.com/amiryahaya/triton.git
cd triton

# Build
go build -o triton main.go

# Or install directly
go install
```

## Usage

```bash
# Quick scan (certificates, keys, packages only)
./triton --profile quick

# Standard scan (recommended)
./triton --profile standard

# Comprehensive scan (everything)
./triton --profile comprehensive

# Custom output file
./triton -o my-report.json

# Run specific modules only
./triton --modules certificates,keys
```

## Scan Profiles

| Profile | Description | Modules | Duration |
|---------|-------------|---------|----------|
| `quick` | Fast scan of critical areas | certificates, keys, packages | ~2-5 min |
| `standard` | Balanced system scan | + libraries, services | ~10-30 min |
| `comprehensive` | Deep scan of entire system | + processes, configs | ~1-4 hours |

## Output Formats

The scanner generates:
- `triton-report.json` - CycloneDX 1.6 format (machine-readable)
- `triton-report.csv` - Government format (spreadsheet)
- `triton-report.html` - Visual report (presentation)

## PQC Classification

| Status | Description | Action Required |
|--------|-------------|-----------------|
| **SAFE** | Quantum-resistant algorithms | Monitor |
| **TRANSITIONAL** | Needs migration plan | Plan replacement |
| **DEPRECATED** | Replace soon | Schedule update |
| **UNSAFE** | Immediate vulnerability | Emergency fix |

## Architecture

```
┌─────────────────────────────────────────┐
│  Triton Scanner (Go binary)             │
│  ┌─────────────┐  ┌─────────────────┐   │
│  │ File Scanner│  │ Crypto Scanner  │   │
│  │ - Packages  │  │ - Certificates  │   │
│  │ - Libraries │  │ - Keys          │   │
│  │ - Binaries  │  │ - TLS configs   │   │
│  └─────────────┘  └─────────────────┘   │
│  ┌─────────────────────────────────┐    │
│  │ Report Generator                │    │
│  │ - CycloneDX 1.6 JSON            │    │
│  │ - CSV (gov format)              │    │
│  │ - HTML (visual)                 │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

## Development

### Project Structure

```
triton/
├── cmd/              # CLI commands
├── internal/         # Internal packages
│   ├── config/       # Configuration
│   └── utils/        # Utilities
├── pkg/              # Public packages
│   ├── scanner/      # Scanning engine
│   ├── crypto/       # PQC classification
│   ├── model/        # Data models
│   └── report/       # Report generation
├── test/             # Test fixtures
└── docs/             # Documentation
```

### Running Tests

```bash
go test ./...
```

### Building for All Platforms

```bash
# macOS
go build -o triton-darwin main.go

# Linux
go build -o triton-linux main.go

# Windows
go build -o triton.exe main.go
```

## Roadmap

- [x] Project scaffold
- [x] Certificate scanner
- [x] Key scanner
- [x] Package scanner
- [ ] Service scanner (TLS configs)
- [ ] Process scanner
- [ ] Windows certificate store support
- [ ] Air-gapped mode
- [ ] Centralized reporting server

## License

MIT License - See LICENSE file

## Acknowledgments

- Inspired by [CipherIQ CBOM Generator](https://github.com/CipherIQ/cbom-generator)
- CycloneDX standard by OWASP
- PQC guidance from NIST IR 8413
