# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Triton is an enterprise-grade Go CLI + server tool that scans systems for cryptographic assets and generates SBOM/CBOM reports for Malaysian government PQC (Post-Quantum Cryptography) compliance assessment. It has 19 scanner modules across 6 target types, REST API server with PostgreSQL storage, policy engine, web UI dashboard, and multi-format report generation.

## Build & Development Commands

```bash
make build                  # Build for current platform → bin/triton
make build-all              # Cross-compile (macOS/Linux/Windows, amd64/arm64)
make test                   # Run unit tests only (go test -v -p 1 ./...)
make test-integration       # Run integration tests (requires PostgreSQL)
make test-all               # Run unit + integration tests
make test-integration-race  # Integration tests with race detector
make run                    # Run with quick profile
make fmt                    # Format code (go fmt ./...)
make lint                   # Lint (golangci-lint run)
make deps                   # Download and tidy dependencies
make clean                  # Remove bin/
```

Run a single test:
```bash
go test -v -run TestName ./pkg/scanner
go test -v -tags integration -run TestWorkflow_FullChain ./test/integration/...
```

Coverage:
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

## Architecture

**Entry point:** `main.go` → `cmd/root.go` (Cobra CLI with BubbleTea TUI)

**Core scanning pipeline:**
```
CLI Command → Config Loading → Scanner Engine → [Modules] → PQC Classification → Report Generator
```

### Key packages

- **`cmd/`** — Cobra root command with BubbleTea progress UI
- **`pkg/scanner/`** — Core scanning engine and 19 modules
  - `engine.go` — Orchestrator: manages concurrent module execution using goroutines with semaphore pattern, collects findings via channels
  - `certificate.go`, `key.go` — Certificates and keys (Category 5)
  - `library.go`, `binary.go`, `kernel.go` — Libraries, binaries, kernel modules (Categories 2-4)
  - `package.go`, `config.go` — Package manager and config file scanning
  - `script.go`, `webapp.go` — Source code scanning (Categories 6-7)
  - `process.go`, `network.go`, `protocol.go` — Runtime and network scanning (Categories 1, 8-9); protocol.go includes enhanced TLS probing (cipher enumeration, version range, preference order, KX/PFS, chain validation)
  - `container.go`, `certstore.go` — Container and OS cert store scanning
  - `database.go`, `hsm.go`, `ldap.go`, `codesign.go` — Specialized scanners
  - `deps.go` — Go dependency crypto reachability analysis (direct/transitive/unreachable classification)
- **`pkg/crypto/`** — PQC algorithm registry and classification (SAFE/TRANSITIONAL/DEPRECATED/UNSAFE)
- **`pkg/model/`** — Data structures for SBOM, CBOM, findings, components
- **`pkg/report/`** — Report generation in CycloneDX JSON, CSV (with Malay headers for government format), HTML, SARIF, JSON
- **`pkg/store/`** — PostgreSQL storage via pgx/v5
- **`pkg/server/`** — REST API server (go-chi/chi/v5) with embedded web UI
- **`pkg/policy/`** — YAML policy engine with builtins (nacsa-2030, cnsa-2.0)
- **`internal/config/`** — Profile-based configuration (quick/standard/comprehensive)
- **`internal/license/`** — Ed25519-signed licence keys, 3-tier feature gating (free/pro/enterprise)

### Module interface

Scanner modules implement `Module` interface in `pkg/scanner/engine.go`:
```go
type Module interface {
    Name() string
    Category() ModuleCategory
    ScanTargetType() ScanTargetType
    Scan(ctx context.Context, target ScanTarget, findings chan<- *Finding) error
}
```

### Scan profiles

- **quick** — certificates, keys, packages; depth 3; 4 workers
- **standard** — certificates, keys, packages, libraries, binaries, scripts, webapp, configs, containers, certstore, database, deps; depth 10; 8 workers
- **comprehensive** — all 19 modules; unlimited depth; 16 workers

Worker count is capped by CPU count.

## Development Methodology

The project follows TDD (Red → Green → Refactor). Coverage target is >80%. See `docs/DEVELOPMENT_PLAN.md` for the full development plan (Phases 1-14, 9.1) and `docs/CODE_REVIEW_CHECKLIST.md` for review guidelines.

### Integration tests

Build-tagged with `//go:build integration` — 48 tests in `test/integration/` covering CLI pipelines, server workflows, agent-server communication, cross-package interactions, concurrent stress, and error paths. Unit tests (`make test`) exclude integration tests; use `make test-integration` or `make test-all` to include them.

## Go Version

Requires Go 1.21+ (`go.mod`).
