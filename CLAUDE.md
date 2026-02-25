# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Triton is a Go CLI tool for generating Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) to assess Post-Quantum Cryptography (PQC) compliance. It targets Malaysian government critical infrastructure sectors. Currently in MVP phase.

## Build & Development Commands

```bash
make build          # Build for current platform → bin/triton
make build-all      # Cross-compile (macOS/Linux/Windows, amd64/arm64)
make test           # Run all tests (go test -v ./...)
make run            # Run with quick profile
make fmt            # Format code (go fmt ./...)
make lint           # Lint (golangci-lint run)
make deps           # Download and tidy dependencies
make clean          # Remove bin/
```

Run a single test:
```bash
go test -v -run TestName ./pkg/scanner
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
- **`pkg/scanner/`** — Core scanning engine and modules
  - `engine.go` — Orchestrator: manages concurrent module execution using goroutines with semaphore pattern, collects findings via channels
  - `certificate.go` — Scans for X.509 certificates (.pem, .crt, .cer, .der)
  - `key.go` — Detects private keys via file extension and PEM header pattern matching
  - `package.go` — Queries OS package managers (brew/dpkg/rpm)
- **`pkg/crypto/`** — PQC algorithm registry and classification (SAFE/TRANSITIONAL/DEPRECATED/UNSAFE)
- **`pkg/model/`** — Data structures for SBOM, CBOM, findings, components
- **`pkg/report/`** — Report generation in CycloneDX JSON, CSV (with Malay headers for government format), and HTML
- **`internal/config/`** — Profile-based configuration (quick/standard/comprehensive) with Viper

### Module interface

Scanner modules implement `Module` interface in `pkg/scanner/engine.go`:
```go
type Module interface {
    Name() string
    Scan(ctx context.Context, target string, findings chan<- *model.Finding) error
}
```

### Scan profiles

- **quick** — certificates, keys, packages; depth 3; 4 workers
- **standard** — adds libraries, services; depth 10; 8 workers
- **comprehensive** — adds processes, configs; unlimited depth; 16 workers

Worker count is capped by CPU count.

## Development Methodology

The project follows TDD (Red → Green → Refactor). Coverage target is >80%. See `docs/DEVELOPMENT_PLAN.md` for the full 4-week MVP plan and `docs/CODE_REVIEW_CHECKLIST.md` for review guidelines.

## Go Version

Requires Go 1.21+ (`go.mod`).
