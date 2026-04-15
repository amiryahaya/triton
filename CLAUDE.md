# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Triton is an enterprise-grade Go CLI + server tool that scans systems for cryptographic assets and generates SBOM/CBOM reports for Malaysian government PQC (Post-Quantum Cryptography) compliance assessment. It has 30 scanner modules across 6 target types, REST API server with PostgreSQL storage, policy engine, web UI dashboard, and multi-format report generation.

## Build & Development Commands

```bash
make build                  # Build for current platform → bin/triton
make build-all              # Cross-compile (macOS/Linux/Windows, amd64/arm64)
make test                   # Run unit tests only (go test -v ./...)
make test-integration       # Run integration tests (requires PostgreSQL)
make test-all               # Run unit + integration tests
make test-integration-race  # Integration tests with race detector
make test-e2e               # Playwright E2E browser tests (requires PostgreSQL + Chromium)
make test-e2e-license       # Playwright E2E tests for license server admin UI
make run                    # Run with quick profile
make fmt                    # Format code (go fmt ./...)
make lint                   # Lint (golangci-lint run)
make deps                   # Download and tidy dependencies
make clean                  # Remove bin/
make build-licenseserver    # Build license server → bin/triton-license-server
make container-build        # Build container image (triton:local)
make container-run          # Build + start full stack (postgres + triton server)
make container-stop         # Stop full stack
make container-build-licenseserver  # Build license server container
make container-run-licenseserver    # Start license server + postgres
make container-stop-licenseserver   # Stop license server
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
- **`pkg/scanner/`** — Core scanning engine and 30 modules
  - `engine.go` — Orchestrator: manages concurrent module execution using goroutines with semaphore pattern, collects findings via channels
  - `certificate.go`, `key.go` — Certificates and keys (Category 5)
  - `library.go`, `binary.go`, `kernel.go` — Libraries, binaries, kernel modules (Categories 2-4)
  - `package.go`, `config.go` — Package manager and config file scanning
  - `script.go`, `webapp.go` — Source code scanning (Categories 6-7)
  - `process.go`, `network.go`, `protocol.go` — Runtime and network scanning (Categories 1, 8-9); protocol.go includes enhanced TLS probing (cipher enumeration, version range, preference order, KX/PFS, chain validation) and hybrid PQC named-group classification (X25519MLKEM768, SecP256r1MLKEM768, draft Kyber hybrids) via post-handshake `tls.ConnectionState.CurveID` lookup
  - `container.go`, `certstore.go` — Container and OS cert store scanning
  - `database.go`, `hsm.go`, `ldap.go`, `codesign.go` — Specialized scanners
  - `deps.go` — Go dependency crypto reachability analysis (direct/transitive/unreachable classification)
  - `asn1_oid.go` — ASN.1 OID byte scanner: walks ELF/Mach-O/PE read-only sections for DER-encoded OIDs, classifies via `pkg/crypto/oid.go` registry (comprehensive profile + Pro+ tier only)
  - `java_bytecode.go` — Java class/JAR/WAR/EAR scanner: parses constant pool for crypto literals (JCA standard names, BouncyCastle, PQC), classifies via `pkg/crypto/java_algorithms.go` (comprehensive profile + Pro+ tier only)
  - `dotnet_il.go` — .NET assembly scanner: parses CLI metadata (TypeRef table + #US heap) for crypto type-references and string literals, classifies via `pkg/crypto/dotnet_algorithms.go` registry; supports classic and single-file bundles (comprehensive profile + Pro+ tier only)
  - `ebpf_trace.go` — eBPF runtime crypto tracer: uprobes on libcrypto/gnutls/nss + kprobes on kernel crypto API, observation-window scan; Linux-only (emits skipped-finding on other OS); comprehensive profile + Pro+ tier; requires root/CAP_BPF + kernel ≥ 5.8 + BTF
- **`pkg/crypto/`** — PQC algorithm registry and classification (SAFE/TRANSITIONAL/DEPRECATED/UNSAFE)
  - `tls_groups.go` — IANA TLS named group registry with hybrid PQC classification (composite ML-KEM + classical ECDHE groups, draft Kyber hybrids, pure PQ KEMs)
  - `java_algorithms.go` — Java crypto literal registry (~80 entries)
  - `dotnet_algorithms.go` — .NET crypto registry: BCL types, CAPI/CNG constants, BouncyCastle.NET PQC (~80 entries)
- **`pkg/model/`** — Data structures for SBOM, CBOM, findings, components
- **`pkg/report/`** — Report generation in CycloneDX JSON, CSV (with Malay headers for government format), HTML, SARIF, JSON. HTML report includes policy analysis summary (verdict banner, violations-by-rule table, threshold violations) when `--policy` is used.
- **`pkg/store/`** — PostgreSQL storage via pgx/v5
- **`pkg/server/`** — REST API server (go-chi/chi/v5) with embedded web UI
- **`pkg/policy/`** — YAML policy engine with builtins (nacsa-2030, cnsa-2.0). `ToModelResult()` converts aggregate violations, threshold violations, and stats for report rendering.
- **`internal/config/`** — Profile-based configuration (quick/standard/comprehensive)
- **`internal/license/`** — Ed25519-signed licence keys, 3-tier feature gating (free/pro/enterprise), machine fingerprint binding

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
- **comprehensive** — all 30 modules (including `asn1_oid` ASN.1 OID byte scanner and `java_bytecode` Java JAR/class scanner); unlimited depth; 16 workers

Worker count is capped by CPU count.

### Licence enforcement

3-tier system (free/pro/enterprise) with Ed25519-signed tokens in `internal/license/`:

- **Machine binding**: Tokens include `MachineID` (SHA-3-256 of `hostname|GOOS|GOARCH`). Mismatch → graceful degradation to free tier. Legacy tokens without `mid` are backward compatible.
- **Guard**: `guard.go` — Primary enforcement point. `FilterConfig()` restricts profile, modules, and DB URL. `EnforceFormat("all")` succeeds for all tiers; `AllowedFormats()` determines which formats to generate.
- **Keygen**: `IssueToken()` binds to current machine by default; `IssueTokenWithOptions(..., bind)` for opt-out. CLI: `--no-bind` flag.
- **Server middleware**: `pkg/server/license.go` — `LicenceGate` middleware gates `/diff` and `/trend` routes by tier. Handler-level enforcement in report generation (format gating) and policy evaluation (builtin vs custom). Nil guard = no enforcement (used by E2E testserver).
- **Fingerprint**: `fingerprint.go` — `MachineFingerprint()` returns deterministic 64-char hex string (SHA-3-256), no elevated privileges required.
- **License Server**: Standalone service (`cmd/licenseserver/`) for centralized license management with org-based seat pools, online validation with 7-day offline fallback. See below.

### License server

Standalone binary (`cmd/licenseserver/main.go`) with separate PostgreSQL schema (`pkg/licensestore/`), Chi REST API (`pkg/licenseserver/`), and embedded admin web UI.

- **Store**: `pkg/licensestore/` — 4 tables (organizations, licenses, activations, audit_log), separate `license_schema_version` table, pgx/v5
- **Server**: `pkg/licenseserver/` — Admin API (X-Triton-Admin-Key auth) + Client API (no auth, secured by license UUID + fingerprint)
- **Client**: `internal/license/client.go` — `ServerClient` with Activate/Deactivate/Validate/Health
- **Cache**: `internal/license/cache.go` — `CacheMeta` at `~/.triton/license.meta`, 7-day grace period
- **Guard integration**: `NewGuardWithServer()` validates online, falls back to cached tier if server unreachable
- **CLI commands**: `triton license activate`, `triton license deactivate` (flags: `--license-server`, `--license-id`)
- **Binary**: `cmd/licenseserver/main.go` — env config (`TRITON_LICENSE_SERVER_*`), signal handling
- **Container**: `Containerfile.licenseserver`, compose profile `license-server` on port 8081
- **Admin UI**: Embedded vanilla JS SPA at `/ui/` with hash routing (dashboard, orgs, licenses, activations, audit)

## Development Methodology

The project follows TDD (Red → Green → Refactor). Coverage target is >80%. See `docs/DEVELOPMENT_PLAN.md` for the full development plan (Phases 1-14, 9.1), `docs/CODE_REVIEW_CHECKLIST.md` for review guidelines, and `docs/DEPLOYMENT_GUIDE.md` for client-server deployment (server, agent, PostgreSQL, TLS, API auth, systemd, production checklist).

### Integration tests

Build-tagged with `//go:build integration` — 111 tests in `test/integration/` across 10 files covering CLI pipelines, server workflows, agent-server communication, cross-package interactions, concurrent stress, error paths, licence tier enforcement, license server workflows, and license flow lifecycle. Unit tests (`make test`) exclude integration tests; use `make test-integration` or `make test-all` to include them.

- **`license_tier_test.go`** (19 tests) — Keygen→inject→validate→enforce flow for free/pro/enterprise tiers, expired/tampered/wrong-key degradation, real scan pipelines with report generation gated by licence tier, Pro tier allowed-formats validation, server middleware route blocking (diff/trend/report format), FilterConfig DB URL clearing, and machine-bound token degradation through full pipeline
- **`license_server_test.go`** (33 tests) — Full lifecycle (activate→validate→deactivate), seat limits, revocation, reactivation, concurrent activation (race), admin CRUD, audit trail, Guard online validation, offline fallback (fresh/stale cache), backward compat (offline token), expired license, health check
- **`license_flow_test.go`** (11 tests) — End-to-end license activation flows, server-client integration, token lifecycle management

### E2E browser tests

25 Playwright tests in `test/e2e/` validate the embedded web UI (`pkg/server/ui/dist/`) end-to-end in a real Chromium browser against a live PostgreSQL-backed server.

- **Test server:** `test/e2e/cmd/testserver/main.go` — Lightweight Go server that imports `pkg/server` + `pkg/store` directly, bypassing the CLI licence gate. Truncates DB on startup for isolation. Uses `run()` pattern to satisfy gocritic `exitAfterDefer`.
- **Global setup:** `test/e2e/global-setup.js` — Seeds 4 scans (2 machines) with deterministic timestamps via `POST /api/v1/scans`
- **`dashboard.spec.js`** (4 tests) — Stat cards, machines table, Chart.js charts, aggregate counts
- **`navigation.spec.js`** (5 tests) — Sidebar nav links, hash routing, active class, error page, root redirect
- **`scans.spec.js`** (8 tests) — Scans list/detail, back navigation, machines list/detail, trend chart
- **`diff-trend.spec.js`** (8 tests) — Diff form/result/error paths, trend form/chart/all-hosts

Run with `make test-e2e` (requires PostgreSQL running + Chromium installed via Playwright).

#### License server admin UI E2E tests

22 Playwright tests in `test/e2e/license-admin.spec.js` validate the license server admin web UI (`pkg/licenseserver/ui/dist/`) against a live PostgreSQL-backed license server.

- **Test server:** `test/e2e/cmd/testlicenseserver/main.go` — Lightweight license server with ephemeral Ed25519 keypair, admin key `e2e-test-key`
- **Global setup:** `test/e2e/license-global-setup.js` — Seeds 2 orgs, 2 licenses, 1 activation
- **Config:** `test/e2e/playwright.license.config.js` — Separate Playwright config (baseURL `:8081`)
- **`license-admin.spec.js`** (22 tests) — Auth prompt, dashboard stats, org CRUD, license listing, license detail, activations, audit log, navigation

Run with `make test-e2e-license` (requires PostgreSQL running + Chromium installed via Playwright).

## Container Infrastructure

- **Containerfile** — Multi-stage build (`golang:1.25` → `scratch`), ~10MB production image with CA certs and timezone data
- **compose.yaml** — PostgreSQL 18 (port 5434) + triton server behind `profiles: [server]`; `make db-up` only starts postgres, full stack requires `--profile server`
- **.containerignore** — Excludes `.git`, `docs/`, `test/`, `bin/` from build context

### CI/CD (`.github/workflows/`)

- **ci.yml** — 4 jobs: Lint → Unit Test → Integration Test → Build. Integration tests run with PostgreSQL 18 service container, `-tags integration -race`
- **release.yml** — Triggered on `v*` tags. 3 jobs: Test (unit + integration with PostgreSQL) → Release (GoReleaser) + Container Image (multi-arch push to `ghcr.io/amiryahaya/triton`)

## Code Quality Principles

- Law of Demeter: avoid chaining method calls through intermediaries
- Separation of Concerns: each package/file should have a single responsibility
- Single Source of Truth: no duplicated business logic across packages
- SOLID: prefer interfaces, dependency injection, single responsibility

## Go Version

Requires Go 1.25+ (`go.mod`).
