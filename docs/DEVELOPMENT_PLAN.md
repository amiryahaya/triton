# Triton Development Plan

## SBOM/CBOM Scanner for PQC Compliance

**Version:** 4.0
**Methodology:** Test-Driven Development (TDD) + Code Review + QA Gates
**Language:** Go 1.25+
**Go Quick Reference:** See `docs/GO_QUICK_REFERENCE.md`

### Release Milestones

| Milestone | Phases | Version | Status | Purpose |
|-----------|--------|---------|--------|---------|
| **MVP** | 1-5 | v0.1.0 | **Released** | Technical demo, partner buy-in — all 9 scan categories, Jadual 1 & 2, CI/CD |
| **NACSA-Ready** | 6-7 | v1.0 | **Released** | Official NACSA assessments — CycloneDX CBOM, CNSA 2.0, PQC detection, doctor |
| **Enterprise** | 8-10 | v2.0 | **Released** | Client-server, PostgreSQL, policy engine, web UI, 19 scanner modules |
| **Standards** | 11 | v2.1 | **Released** | FN-DSA (FIPS 206), CAMM Level 3, per-system policy evaluation |
| **Reachability** | 12 | v2.2 | **Released** | Dependency crypto reachability scanner, false positive reduction |
| **Licensing** | 9.1 | v2.3 | **Released** | Ed25519-signed licence keys, 3-tier feature gating (free/pro/enterprise) |
| **TLS Probing** | 13 | v2.4 | **Released** | Enhanced TLS probing — cipher enumeration, preference order, version range, PFS, chain validation |
| **Integration Tests** | 14 | v2.5 | **Released** | Build-tagged integration/e2e tests — 48 tests across 7 files covering CLI, server, agent, cross-package, concurrent, error paths |
| **Container Infra** | 15 | v2.6 | **Released** | Containerfile, compose server profile, CI integration tests, ghcr.io image push |

---

## 1. Project Overview

### 1.1 Goals

- Scan systems for all cryptographic assets across 9 categories (see §3)
- Classify each asset for Post-Quantum Cryptography (PQC) readiness
- Assess crypto-agility — can the system migrate to PQC algorithms?
- Generate reports in **Malaysian government format** (Jadual 1 SBOM & Jadual 2 CBOM)
- Support macOS (primary) and Linux (secondary), Windows best-effort
- Outperform PCert (Java) in speed and memory efficiency

### 1.2 Scope Decisions

| Decision | Status | Notes |
|----------|--------|-------|
| Standalone CLI | **MVP** | Single binary, no server |
| Client-server mode | **Done** | REST API server + agent mode (v2.0) |
| CI/CD pipeline | **Done** | GitHub Actions CI (lint + unit + integration + build) + GoReleaser + ghcr.io container push |
| Government format (Jadual 1 & 2) | **Primary output** | Exact column match required |
| CycloneDX CBOM v1.7 | **Done** | Full crypto object modeling |
| HTML dashboard | **Done** | PQC dashboard with CAMM scoring |
| Policy engine | **Done** | YAML rules + builtins (nacsa-2030, cnsa-2.0) |
| Web UI | **Done** | Embedded vanilla JS + Chart.js |

### 1.3 Success Criteria

| Metric | Target |
|--------|--------|
| Scan 1TB disk | < 2 hours |
| Memory usage | < 200MB |
| Binary size | < 50MB |
| False positive rate | < 5% |
| Test coverage | > 80% |
| Scanning categories | 9 of 9 (19 scanner modules) |
| Government format compliance | Jadual 1 + Jadual 2 exact match |

---

## 2. The 9 Scanning Categories

All categories from the CBOM-scanning reference must be implemented. Each is assigned to a phase below.

| # | Category | Type | Phase | Description |
|---|----------|------|-------|-------------|
| 1 | Binaries in use | Active/Runtime | 3 | Running processes with crypto (lsof, /proc) |
| 2 | Binaries on disk | Passive/File | 2 | Executables with crypto patterns (strings, symbols) |
| 3 | Cryptographic libraries | Passive/File | 2 | libcrypto, libssl, mbedtls, wolfssl, etc. |
| 4 | Kernel modules | Passive/File | 2 | Crypto in .ko files (Linux only, skip macOS) |
| 5 | Certificates & keys | Passive/File | 2 | PEM/DER/PKCS file-based certificates and keys |
| 6 | Executable scripts | Passive/Code | 3 | Crypto calls in .py, .sh, .rb, .pl, etc. |
| 7 | Web applications | Passive/Code | 3 | Crypto patterns in .php, .js, .go, .java, etc. |
| 8 | Network applications | Active/Network | 3 | TLS/SSH/IPsec service detection on listening ports |
| 9 | Network protocols | Active/Network | 3 | Active TLS probing, cipher suite enumeration |

**Type classifications:**
- **Passive/File** — Read files on disk, no system interaction
- **Passive/Code** — Pattern-match source code files
- **Active/Runtime** — Inspect running processes
- **Active/Network** — Probe network services

---

## 3. Development Methodology

### 3.1 TDD Cycle (Daily)

```
Red    → Write failing test (define desired behavior)
Green  → Write minimal code to pass (make it work)
Refactor → Clean up, optimize (make it right)
```

### 3.2 Development Cycle (Per Phase)

```
┌─────────────────────────────────────────────────────────┐
│  WEEKLY CYCLE                                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │   TDD   │→│  Review  │→│   QA    │→│  Merge  │   │
│  │Red-Green│  │ Checklist│  │  Gate   │  │         │   │
│  │Refactor │  │          │  │         │  │         │   │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Code Review Checklist (End of Each Phase)

**Before requesting review:**
- [ ] All tests pass (`go test ./...`)
- [ ] Coverage > 80% (`go test -cover`)
- [ ] No linting errors (`golangci-lint run`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] Documentation updated

**Reviewer checks:**
- [ ] Code follows Go conventions
- [ ] Error handling is complete
- [ ] No obvious bugs or edge cases missed
- [ ] Security considerations addressed

See `docs/CODE_REVIEW_CHECKLIST.md` for full checklist.

### 3.4 QA Gate (End of Each Phase)

**Functional:** Feature works, edge cases handled, error messages helpful
**Performance:** Memory acceptable, speed acceptable, no resource leaks
**Integration:** Works with other modules, no regressions

See `docs/QA_GATE_CHECKLIST.md` for full checklist.

---

## 4. Phase Breakdown

### Phase 1: Foundation & Data Model (Week 1)

**Goal:** Redesigned data model, new module interface, engine scaffold, test fixtures

#### Key Changes from Current Code

The current data model (`pkg/model/types.go`) is file-level — each Finding points to a file path. Government reports (Jadual 1 & 2) are **system/application-level** — findings must be grouped by the system they belong to. Phase 1 redesigns the data model to support both.

#### Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 1 | Redesign data model: ScanResult → System → Finding → CryptoAsset | Unit tests for all types, JSON serialization round-trip | New `pkg/model/` types |
| 2 | New Module interface with Category enum (passive/active/code) and scan target types (filesystem/network/process) | Interface compliance tests with mock modules | Updated `pkg/scanner/engine.go` |
| 3 | Config system: add scan targets, network ranges, system grouping hints | Config loading, validation, profile tests | Updated `internal/config/` |
| 4 | Engine scaffold: concurrent module execution, category-based scheduling | Engine lifecycle tests, concurrency tests | Working engine with mock modules |
| 5 | Test fixtures: sample certs, keys, binaries, scripts. Integration test. | Fixture validation tests | `test/fixtures/` directory |

#### Data Model (New)

```
ScanResult
├── Metadata (timestamp, tool info, scan config)
├── Systems []System           ← NEW: for Jadual 1
│   ├── Name, Purpose, URL
│   ├── ServiceMode, TargetCustomer
│   ├── Components []string
│   ├── ThirdPartyModules []string
│   ├── CriticalityLevel
│   └── CBOMRefs []string      ← links to CBOM entries
├── Findings []Finding         ← raw scan results
│   ├── Category (1-9)
│   ├── Source (file path / process / network endpoint)
│   ├── CryptoAsset
│   │   ├── Algorithm, KeySize, Function
│   │   ├── Library, PQCStatus, CryptoAgility
│   │   └── MigrationPriority
│   └── Confidence, Timestamp
└── Summary
    ├── PQC stats (safe/transitional/deprecated/unsafe)
    └── Crypto-agility score
```

#### Phase 1 QA Gate

```bash
make build && make test
# All tests pass, coverage > 80%
# Engine runs with mock modules, collects findings, groups into systems
```

---

### Phase 2: File-Based Scanners (Week 2)

**Goal:** Implement categories 2, 3, 4, 5 — all passive filesystem scanning

Covers: binaries on disk, cryptographic libraries, kernel modules, certificates & keys, packages

#### Tasks

| Day | Task | Category | Tests | Deliverable |
|-----|------|----------|-------|-------------|
| 6 | Certificate & key scanner — improve existing: parse X.509 fully (key sizes, algorithms, expiry, issuer/subject), support PKCS#8/12 | 5 | Parse real certs from fixtures, verify extracted fields | `pkg/scanner/certificate.go`, `key.go` |
| 7 | Library scanner — find crypto shared libraries (libcrypto, libssl, mbedtls, wolfssl, etc.) via filesystem search + `ldd`/`otool` for dependency chains | 3 | Mock filesystem tests, library detection accuracy | `pkg/scanner/library.go` |
| 8 | Binary-on-disk scanner — `strings` + symbol table analysis for crypto patterns in ELF/Mach-O executables | 2 | Detect known patterns in test binaries | `pkg/scanner/binary.go` |
| 9 | Kernel module scanner — strings on .ko files for crypto references (Linux only, graceful skip on macOS) | 4 | Linux fixture tests, macOS skip test | `pkg/scanner/kernel.go` |
| 10 | Package scanner — improve existing brew/dpkg/rpm; integration test for all file-based scanners | — | End-to-end scan of test directory, result aggregation | `pkg/scanner/package.go` |

#### Detection Patterns

Each file-based scanner uses a crypto pattern registry (see `docs/SYSTEM_ARCHITECTURE.md` §9):

- **Certificates:** File extensions (.pem, .crt, .cer, .der, .p12, .pfx, .jks) + PEM headers
- **Keys:** PEM headers (`BEGIN.*PRIVATE KEY`), SSH key formats
- **Libraries:** Known filenames (libcrypto.so, libssl.so, libmbedcrypto.so, etc.)
- **Binaries:** String patterns (AES, RSA, SHA, ECDSA, etc.) + symbol exports
- **Kernel modules:** `/lib/modules/*/kernel/crypto/*.ko` + strings analysis

#### Phase 2 QA Gate

```bash
# Run on your Mac
./bin/triton --profile standard
# Should find: certificates, keys, libraries on the system
# Verify findings have proper key sizes, algorithms, PQC status
```

---

### Phase 3: Runtime & Active Scanners (Week 3)

**Goal:** Implement categories 1, 6, 7, 8, 9 — runtime inspection, code analysis, network probing

#### Tasks

| Day | Task | Category | Tests | Deliverable |
|-----|------|----------|-------|-------------|
| 11 | Binaries-in-use scanner — enumerate processes (`ps`/`/proc`), detect crypto in running binary memory maps, link to libraries | 1 | Mock process list tests, library linkage detection | `pkg/scanner/process.go` |
| 12 | Script scanner — pattern-match crypto calls in source files (.py, .sh, .rb, .pl) | 6 | Detect hashlib, openssl, crypto imports in fixture scripts | `pkg/scanner/script.go` |
| 13 | Web application scanner — crypto patterns in web source (.php, .js, .go, .java, .ts) | 7 | Detect crypto API usage in fixture web files | `pkg/scanner/webapp.go` |
| 14 | Network application scanner — enumerate listening ports (`ss`/`lsof`/`netstat`), classify protocols (TLS/SSH/IPsec), map to processes | 8 | Mock port list, protocol classification tests | `pkg/scanner/network.go` |
| 15 | Network protocol scanner — active TLS handshake probing (extract cipher suites, certificate chains), SSH algorithm enumeration | 9 | TLS probe against test server, cipher parsing | `pkg/scanner/protocol.go` |

#### Safety Notes

- **Network scanning requires explicit opt-in** — not included in `quick` or `standard` profiles
- Active probes only target explicitly specified hosts/ranges
- Process inspection may require elevated privileges — degrade gracefully
- All network operations have configurable timeouts

#### Phase 3 QA Gate

```bash
# Full scan including active categories (needs --profile comprehensive + targets)
./bin/triton --profile comprehensive --targets 192.168.1.0/24
# Should find: running crypto processes, scripts with crypto, network services
# Verify network probing returns cipher suites and certificate info
```

---

### Phase 4: PQC Assessment & Reports (Week 4)

**Goal:** Crypto-agility assessment, system grouping, government-format reports

#### Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 16 | Crypto-agility assessment — analyze each system for migration capability: hybrid PQC support, algorithm diversity, library update paths | Agility scoring tests with known scenarios | `pkg/crypto/agility.go` |
| 17 | PQC migration priority scoring — enhanced from current basic system: factor in criticality, exposure, agility, algorithm break timeline | Priority calculation tests | Enhanced `pkg/crypto/pqc.go` |
| 18 | System grouper — map raw findings to System/Application entities for Jadual 1; heuristics for grouping by process, path, network endpoint | Grouping tests with mixed findings | `pkg/report/grouper.go` |
| 19 | Jadual 1 & Jadual 2 in Excel (.xlsx) workbook — exact government column match using template | Excel output tests against sample format | `pkg/report/excel.go` |
| 20 | JSON export (CycloneDX) + HTML summary report with PQC dashboard | Output format tests, HTML rendering | `pkg/report/generator.go` |

#### Jadual 1 — SBOM Format (System-Level)

Exact columns from government sample:

| Column | Source |
|--------|--------|
| No. | Auto-increment |
| Sistem / Aplikasi | System.Name |
| Tujuan/Penggunaan | System.Purpose |
| URL | System.URL |
| Mod Perkhidmatan | System.ServiceMode |
| Sasaran Pelanggan | System.TargetCustomer |
| Komponen Perisian | System.Components (joined) |
| Modul Third-party | System.ThirdPartyModules (joined) |
| External APIs / Perkhidmatan | System.ExternalAPIs (joined) |
| Aras Kritikal | System.CriticalityLevel |
| Kategori Data | System.DataCategory |
| Adakah sistem/Aplikasi sedang digunakan | System.InUse (Ya/Tidak) |
| Pembangun Sistem/Aplikasi | System.Developer |
| Nama vendor | System.Vendor |
| Adakah Agensi mempunyai kepakaran | Manual field (default placeholder) |
| Adakah agensi mempunyai peruntukan khas? | Manual field (default placeholder) |
| Pautan ke CBOM | CBOM reference IDs |

#### Jadual 2 — CBOM Format (Crypto-Asset-Level)

Exact columns from government sample:

| Column | Source |
|--------|--------|
| No. | Auto-increment |
| # (CBOM) | CBOM reference ID (e.g., "CBOM #1") |
| Sistem/Aplikasi | Parent System.Name |
| Fungsi Cryptographic | CryptoAsset.Function |
| Algoritma yang digunakan | CryptoAsset.Algorithm |
| Library/Modul | CryptoAsset.Library |
| Panjang Kunci | CryptoAsset.KeySize |
| Tujuan/Penggunaan | CryptoAsset.Purpose |
| Sokongan Crypto-Agility | CryptoAsset.CryptoAgility assessment text |

#### Phase 4 QA Gate

```bash
# Generate all report formats
./bin/triton --profile comprehensive --format all

# Verify Excel output contains Jadual 1 & Jadual 2 sheets
# Verify JSON output is valid CycloneDX 1.6
# Verify HTML report renders PQC dashboard
```

---

### Phase 5: Polish & Demo (Week 5) ✅

**Goal:** Version management, benchmarks, cross-platform builds, documentation

#### Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 21 | Version constant + `--version` flag — single source of truth in `internal/version/` | Build verification | `internal/version/version.go`, wired into CLI |
| 22 | Benchmark tests — scanner and crypto performance baselines | `go test -bench=.` | `pkg/scanner/bench_test.go`, `pkg/crypto/bench_test.go` |
| 23 | Cross-platform build verification — all 5 binaries compile, `make bench` + `make vet` targets | `make build-all` | Updated `Makefile` |
| 24 | README rewrite — all 9 categories, xlsx output, correct architecture, updated roadmap | Doc review | `README.md` |
| 25 | Development plan update + final QA gate | Full test suite, vet, benchmarks | Final documentation |

#### Phase 5 QA Gate (Final)

```bash
make build-all                                    # All 5 binaries compile
go test -cover ./...                              # Coverage >80% everywhere
go vet ./...                                      # No issues
go test -bench=. ./pkg/scanner/ ./pkg/crypto/     # Benchmarks run
./bin/triton --version                            # Prints version
./bin/triton --help                               # Help text correct
```

**Final QA Checklist:**
- [x] All binaries build successfully (macOS arm64/amd64, Linux amd64/arm64, Windows amd64)
- [x] All 9 scanning categories implemented and tested
- [x] Government-format Excel report with Jadual 1 & Jadual 2 sheets
- [x] HTML report renders correctly
- [x] `--version` flag works
- [x] Test coverage > 80% across all packages
- [x] Benchmarks established for scanner and crypto packages
- [x] `go vet` clean
- [x] No known critical bugs
- [x] Documentation complete (README, development plan, architecture)

---

## 5. Testing Strategy

### 5.1 Test Fixtures

```
test/
├── fixtures/
│   ├── certificates/
│   │   ├── rsa-2048.pem          # TRANSITIONAL
│   │   ├── rsa-4096.pem          # SAFE
│   │   ├── ecdsa-p256.pem        # TRANSITIONAL
│   │   ├── ed25519.pem           # TRANSITIONAL
│   │   ├── expired.pem           # Edge case
│   │   └── selfsigned-ca.pem     # CA cert
│   ├── keys/
│   │   ├── rsa-private.pem
│   │   ├── ec-private.pem
│   │   ├── pkcs8-private.pem     # PKCS#8 format
│   │   └── openssh-ed25519
│   ├── binaries/
│   │   └── crypto-test           # Small binary with crypto strings
│   ├── scripts/
│   │   ├── crypto-python.py      # hashlib, cryptography imports
│   │   ├── crypto-shell.sh       # openssl commands
│   │   └── crypto-node.js        # crypto module usage
│   ├── webapp/
│   │   ├── crypto-php.php        # openssl_* function calls
│   │   └── crypto-java.java      # javax.crypto usage
│   └── configs/
│       ├── apache-ssl.conf
│       └── nginx-ssl.conf
```

### 5.2 Test Commands

```bash
# Run all tests
go test -v ./...

# Run a single test
go test -v -run TestCertificateParsing ./pkg/scanner

# Run tests for a package
go test -v ./pkg/scanner/...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Benchmarks
go test -bench=. ./pkg/scanner/...
```

### 5.3 Test Conventions

- Test files: `*_test.go` in the same package
- Test functions: `TestXxx(t *testing.T)` for unit tests
- Benchmark functions: `BenchmarkXxx(b *testing.B)` for performance
- Table-driven tests for multiple input/output scenarios
- Use `testify/assert` for assertions
- Mock external dependencies (filesystem, network, processes)

---

## 6. Post-MVP Roadmap (v1.0 → v2.0 → v2.1)

MVP v0.1.0 (Phases 1-5) is released. Phases 6-12 are complete, delivering v1.0 NACSA-Ready, v2.0 Enterprise, v2.1 Standards Completion, and v2.2 Reachability. Gap analysis informed by industry leaders (IBM Quantum Safe, SandboxAQ, Keyfactor, Fortanix, AppViewX, ReversingLabs, CryptoNext).

### Competitive Position

Triton's strengths vs the industry:
- **9-category coverage in a single binary** — no commercial tool covers all 9; industry practice requires 2-4 tools
- **Kernel crypto module scanning** — zero commercial tools scan `/proc/crypto` or `.ko` files
- **Malaysian government format (Jadual 1 & 2)** — no other tool outputs this
- **Single binary, zero dependencies** — enterprise tools require agents, appliances, or SaaS subscriptions

Key gaps to close: standards compliance (CycloneDX CBOM, CNSA 2.0 mapping), PQC-specific depth (hybrid cert detection, timeline-based risk), and operational tooling (doctor, incremental scans).

---

### v1.0 Scope

v1.0 NACSA-Ready includes **all of Phase 6** plus selected Phase 7 tasks critical for government assessments:

- Phase 6: all tasks (6.1-6.7)
- Phase 7.2: Config scanner expansion (sshd_config, crypto-policies)
- Phase 7.5: `triton doctor` command

**v1.0 release criteria:** CycloneDX CBOM validates against v1.7 schema, CNSA 2.0 status on every finding, NACSA compliance column in Jadual 2, PQC algorithm OIDs detected, `triton doctor` outputs pass/fail per category.

---

### Phase 6: NACSA Alignment & Standards Compliance _(v1.0 — COMPLETED)_

**Goal:** Align Triton output with Malaysia's National PQC Readiness Roadmap (2025-2030) and international CBOM standards. This is the highest priority — without it, Triton cannot be used in official NACSA assessments.

**Context:** Malaysia's NACSA PQC Migration Framework classifies critical infrastructure organizations as "urgent adopters." CyberSecurity Malaysia published phase-by-phase recommendations for PQC adoption. NIST IR 8547 sets deprecation deadlines (RSA/ECDSA deprecated by 2030, disallowed by 2035). CycloneDX 1.6+ is the only standard with native CBOM crypto object modeling.

| # | Task | Priority | Description | Deliverable |
|---|------|----------|-------------|-------------|
| 6.1 | CycloneDX CBOM v1.7 output | **P0** | Implement proper CBOM crypto asset types: algorithm, key, protocol, certificate, related-crypto-material objects per CycloneDX 1.6/1.7 spec. Current JSON output lacks crypto-specific object modeling. Without this, Triton is not interoperable with the CBOM ecosystem. | Enhanced `pkg/report/cyclonedx.go` |
| 6.2 | NIST IR 8547 / CNSA 2.0 timeline mapping | **P0** | Add deprecation timeline to every finding: "RSA-2048: NIST deprecated 2030, disallowed 2035" / "AES-256: CNSA 2.0 approved". Map each algorithm to CNSA 2.0 approval status. Add `--compliance cnsa2` and `--compliance nist` flags. | Enhanced `pkg/crypto/pqc.go`, new `pkg/crypto/compliance.go` |
| 6.3 | NACSA PQC framework alignment | **P0** | Map Triton output to NACSA's "urgent adopter" classification. Add NACSA-specific compliance column in Jadual 2. Align PQC status labels with CyberSecurity Malaysia's recommended terminology. | Enhanced `pkg/report/excel.go` |
| 6.4 | PQC algorithm detection (ML-KEM, ML-DSA, SLH-DSA) | **P0** | Detect NIST PQC algorithm OIDs in X.509 certificates and keys: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), FN-DSA (FIPS 206). Classify as SAFE. | Enhanced `pkg/crypto/registry.go`, `pkg/scanner/certificate.go` |
| 6.5 | Hybrid certificate detection | **P1** | Detect X.509 hybrid certificates (RSA + ML-DSA composite). BSI and ANSSI mandate hybrid approach during transition. Flag hybrid certs as SAFE with note. | Enhanced `pkg/scanner/certificate.go` |
| 6.6 | CAMM-aligned crypto-agility scoring | **P1** | Replace basic agility scoring with CAMM Level 0-4 framework (Knowledge, Process, System Property dimensions). Output CAMM level per system in reports. | Enhanced `pkg/crypto/agility.go` |
| 6.7 | Compliance summary report | **P1** | New "Compliance Summary" sheet in Excel: overall NACSA readiness score, CNSA 2.0 gap count, NIST IR 8547 timeline risk, CAMM agility level, recommended migration priority order. | Enhanced `pkg/report/excel.go` |

**Phase 6 Delivery Summary:** CycloneDX CBOM v1.7 with full crypto object modeling, CNSA 2.0 timeline mapping on every finding, NACSA framework alignment with Malay-language compliance labels, ML-KEM/ML-DSA/SLH-DSA OID detection, hybrid certificate detection, CAMM Level 0-2 auto-assessment, compliance summary in Excel report. ~80+ classified algorithms in registry.

---

### Phase 7: Scan Depth Improvements _(v1.0 partial + v2.0 — COMPLETED)_

**Goal:** Bring scan depth to parity with enterprise tools where it matters most for NACSA assessments.

| # | Task | Priority | Release | Description | Deliverable |
|---|------|----------|---------|-------------|-------------|
| 7.1 | Enhanced TLS probing | **P1** | v2.0 | Capture cipher suite preference order (not just list), warn on TLS 1.0/1.1, validate certificate chains (root CA trust, intermediate expiry), detect session resumption mechanisms. | Enhanced `pkg/scanner/protocol.go` |
| 7.2 | Config scanner expansion | **P1** | **v1.0** | Scan `sshd_config` (SSH algorithms, key exchange), system crypto policies (`/etc/crypto-policies/`), database TLS configs (MySQL, PostgreSQL), Java security properties (`java.security`). | New `pkg/scanner/config.go` |
| 7.3 | Improved binary analysis | **P2** | v2.0 | ELF/Mach-O symbol table extraction for crypto function exports. Detect embedded crypto library versions (OpenSSL version strings). Go beyond string matching. | Enhanced `pkg/scanner/binary.go` |
| 7.4 | OS certificate store scanning | **P2** | v2.0 | Scan macOS Keychain (`security find-certificate`), Linux ca-certificates (`/etc/ssl/certs/`), Windows certificate store. Currently only scans files on disk. | New logic in `pkg/scanner/certificate.go` |
| 7.5 | `triton doctor` command | **P1** | **v1.0** | Pre-scan environment check: verify permissions (root/sudo for process inspection), tool availability (`openssl`, `lsof`, `ss`), directory access, OS compatibility. Output pass/fail checklist per scan category. Aligns with QRAMM pre-assessment concept. | New `cmd/doctor.go` |

**Phase 7 Delivery Summary:** Enhanced TLS probing with cipher preference ordering, config scanner for sshd_config/crypto-policies/java.security, improved binary analysis with ELF/Mach-O symbol extraction, OS certificate store scanning (macOS Keychain, Linux ca-certificates), `triton doctor` command with per-category pass/fail.

---

### Phase 8: Performance & Operational _(v2.0 — COMPLETED)_

**Goal:** Production-ready performance for enterprise-scale deployments.

**Context:** IBM benchmark: 47M LoC / 6,000 repos in hours. Triton already meets its <2hr/1TB target for filesystem scans. These improvements target re-scan speed and large infrastructure.

| # | Task | Priority | Description | Deliverable |
|---|------|----------|-------------|-------------|
| 8.1 | Incremental scanning | **P2** | Skip unchanged files on re-scan using file modification time + hash cache. Store scan state in `.triton-cache`. Reduces re-scan time by 80%+ for large estates. | New `pkg/scanner/cache.go` |
| 8.2 | SARIF output format | **P2** | Static Analysis Results Interchange Format for CI/CD integration (GitHub Code Scanning, Azure DevOps). Enables automated PR annotations for crypto findings. | New `pkg/report/sarif.go` |
| 8.3 | Container image scanning | **P2** | Scan Docker/OCI image layers for embedded crypto libraries, certificates, keys. Extract and inspect each layer. First mover in crypto-specific container analysis (industry gap). | New `pkg/scanner/container.go` |
| 8.4 | Scan metrics dashboard | **P3** | Enhanced `--metrics` output: scan duration per module, findings per category, coverage heatmap, trend comparison vs previous scan. | Enhanced `cmd/root.go` |

**Phase 8 Delivery Summary:** Incremental scanning with file hash cache, SARIF output for CI/CD integration, container image scanning (Dockerfile/compose/k8s), scan metrics with per-module performance tracking. Added container and certstore scanner modules (14 total at this point).

---

### Phase 9: Enterprise & Ecosystem _(v2.0 — COMPLETED)_

**Goal:** Features for enterprise deployment and paid tiers.

| # | Task | Priority | Description | Deliverable |
|---|------|----------|-------------|-------------|
| 9.1 | Enterprise licensing | **P3** | License key validation, feature gating (free tier: quick profile only; pro: all profiles + compliance reports; enterprise: API + multi-node). Seat management for paid tiers. | New `internal/license/` |
| 9.2 | Client-server mode | **P3** | Agent deployed on target systems reports findings to central server. Server aggregates CBOMs across infrastructure. REST API for integration. | New `cmd/agent.go`, `cmd/server.go` |
| 9.3 | ~~Cloud KMS scanning~~ | **Removed** | Removed from roadmap — out of scope for on-premises audit tool. | — |
| 9.4 | Dependency crypto reachability | **Done** | Trace transitive dependency crypto usage via import graph analysis for Go modules. Distinguish "crypto present in library" vs "crypto actually called by your code." Implemented in Phase 12. | New `pkg/scanner/deps.go` |
| 9.5 | Web UI dashboard | **P3** | Browser-based dashboard for viewing scan results, comparing scans over time, exporting reports. Replaces HTML report with interactive SPA. | New `web/` directory |
| 9.6 | PKCS#11 / HSM scanning | **P3** | Enumerate cryptographic objects in hardware security modules via PKCS#11 interface. Specialized hardware, low priority. | New `pkg/scanner/hsm.go` |
| 9.7 | Database encryption auditing | **P3** | Detect TDE (Transparent Data Encryption) configs in MySQL, PostgreSQL, Oracle, SQL Server. Check algorithm strength and key management. | New `pkg/scanner/database.go` |

**Phase 9 Delivery Summary:** Client-server mode with REST API (go-chi/chi/v5), PostgreSQL 18 storage via pgx/v5, agent mode for remote scan submission, embedded web UI (vanilla JS + Chart.js), HSM scanning via PKCS#11 interface, database encryption auditing (MySQL/PostgreSQL/Oracle/SQL Server). 16 scanner modules at this point.

---

### Phase 10: P-Cert Integration _(v2.0 — COMPLETED)_

**Goal:** Advanced certificate analysis inspired by P-Cert, plus additional scanner modules.

**Delivery Summary:** TLS chain extraction with leaf/intermediate/root analysis, OCSP/CRL revocation checking, LDAP directory scanning for certificates, code signing verification (macOS/Linux), policy engine with YAML rules and builtins (nacsa-2030, cnsa-2.0), scan diff/trend analysis. Added LDAP and codesign scanner modules (18 total).

---

### Phase 11: Standards Completion _(v2.1 — COMPLETED)_

**Goal:** Close standards gaps with FN-DSA (FIPS 206) support, CAMM Level 3 partial automation, and per-system policy evaluation.

| # | Task | Description | Deliverable |
|---|------|-------------|-------------|
| 11.1 | FN-DSA (FIPS 206) detection | Add FN-DSA OIDs (2.16.840.1.101.3.4.3.32/33), registry entries (FN-DSA-512/1024), binary scanner patterns, NIST quantum security levels, FALCON→FN-DSA normalization | Enhanced `pkg/crypto/oid.go`, `pqc.go`, `pkg/scanner/binary.go`, `pkg/report/cyclonedx.go` |
| 11.2 | CAMM Level 3 partial automation | Detect rotation automation tools (certbot/ACME, Vault PKI, cert-manager) in scan findings, enable auto-assessment for indicator 3.1 "Automated Rotation" | Enhanced `pkg/crypto/camm.go`, `pkg/scanner/config.go` |
| 11.3 | Per-system policy evaluation | SystemPattern in policy conditions, per-system thresholds (max_unsafe, min_safe_percent), EvaluateSystem() with glob matching, worst-verdict escalation | Enhanced `pkg/policy/engine.go`, `policy.go`, `pkg/report/generator.go` |

**Phase 11 Delivery Summary:** All 4 NIST PQC standards now covered (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205, FN-DSA FIPS 206). CAMM auto-assessment covers Levels 0-3 (Level 3 via rotation tool detection). Policy engine supports per-system evaluation with SystemPattern glob matching and per-system thresholds.

---

### Phase 12: Dependency Crypto Reachability _(v2.2 — COMPLETED)_

**Goal:** Reduce false positives by distinguishing reachable vs unreachable crypto in Go module dependencies.

| # | Task | Description | Deliverable |
|---|------|-------------|-------------|
| 12.1 | CryptoAsset reachability fields | Add `Reachability` (direct/transitive/unreachable) and `DependencyPath` (import chain) to CryptoAsset model | Enhanced `pkg/model/types.go` |
| 12.2 | DepsModule scanner | go.mod/go.sum parsing, import graph via `go/parser`, BFS import chain finder, crypto import registry (30+ entries covering stdlib, x/crypto, PQC libs) | New `pkg/scanner/deps.go` |
| 12.3 | Reachability classification | Direct imports → 0.95 confidence, transitive → 0.75, unreachable (go.sum only) → 0.50 with halved migration priority | `pkg/scanner/deps.go` |

**Phase 12 Delivery Summary:** New `deps` scanner module (19 total) analyzes Go module dependencies at two levels: (1) go.mod/go.sum text parsing for module-level crypto detection, (2) import graph via `go/parser` stdlib for package-level reachability. BFS finds shortest import chains. Unreachable findings get reduced confidence (0.50) and halved migration priority, reducing false positives from transitive dependencies. 20 test cases with mock analyzer injection. Added to standard and comprehensive scan profiles.

---

### Phase 9.1: Enterprise Feature Gating / Licensing _(v2.3 — COMPLETED)_

Ed25519-signed licence key system with 3-tier feature gating (free/pro/enterprise) for commercial distribution. Offline-first — all validation is local signature verification, no phone-home. Graceful degradation — invalid/expired/missing licence = free tier.

| Task | Description | Files |
|------|-------------|-------|
| 9.1.1 | Tier/Feature definitions | `internal/license/tier.go` — 17 feature constants, 3-tier matrix |
| 9.1.2 | Licence parser | `internal/license/license.go` — Ed25519 signed JSON token (base64url claims + signature) |
| 9.1.3 | Embedded public key | `internal/license/pubkey.go` — overridable via ldflags |
| 9.1.4 | Guard enforcement | `internal/license/guard.go` — token resolution (flag→env→file), EnforceProfile/Format/Feature, FilterConfig |
| 9.1.5 | Keygen tool | `internal/license/keygen.go` + `internal/license/cmd/keygen/main.go` (build-tagged ignore) |
| 9.1.6 | Licence subcommand | `cmd/license.go` — `triton license show/verify` |
| 9.1.7 | CLI integration | `cmd/root.go` — `--license-key` flag, PersistentPreRun guard init, default downgrade for free tier |
| 9.1.8 | Subcommand gates | `cmd/server.go`, `cmd/agent.go` (enterprise), `cmd/diff.go`, `cmd/trend.go`, `cmd/history.go` (pro), `cmd/policy.go` (tiered) |

**Phase 9.1 Delivery Summary:** 38 test cases across 4 test files. Three-layer enforcement: (1) config filter strips disallowed settings, (2) subcommand PreRunE hooks, (3) explicit enforcement in runScan. Free tier: quick profile, JSON only, 3 modules. Pro tier: all profiles/modules, most formats, analytics. Enterprise: everything including server, agent, SARIF, custom policies.

---

### Phase 13: Enhanced TLS Probing _(v2.4 — COMPLETED)_

Enterprise-grade TLS probing bringing the protocol scanner to audit quality. Augments the existing single-handshake probe with comprehensive cipher enumeration, version range testing, and enhanced certificate chain analysis.

| Task | Description | Files |
|------|-------------|-------|
| 13.1 | Helper functions | `cipherSuiteKeyExchange`, `isWeakSignatureAlgorithm`, `sigAlgoToPQCAlgorithm`, `allTLS12CipherSuiteIDs` — `pkg/scanner/protocol.go` |
| 13.2 | Model fields | `KeyExchange`, `ForwardSecrecy`, `SANs` added to `CryptoAsset` — `pkg/model/types.go` |
| 13.3 | KX/PFS augmentation | Existing cipher suite finding augmented with key exchange type and forward secrecy flag |
| 13.4 | Enhanced chain validation | Weak signature detection (SHA-1/MD5), certificate expiry warnings (30-day window), SAN extraction |
| 13.5 | TLS version range probing | Individual TLS 1.0/1.1/1.2/1.3 connection testing, summary finding |
| 13.6 | Cipher suite enumeration | Per-cipher TLS 1.2 probing (~24 suites), supported cipher findings with KX/PFS |
| 13.7 | Cipher preference order | Iterative removal algorithm to determine server cipher preference ranking |

**Phase 13 Delivery Summary:** 20 test cases (3 unit + 17 integration). 8 new functions/methods added to protocol scanner. 3 new model fields. 7 new finding types. Initial probe now offers all cipher suites (secure + insecure) for audit discovery. Coverage 80.4%.

---

### Regulatory Timeline Reference

Key deadlines driving implementation priority:

| Date | Milestone | Impact on Triton |
|------|-----------|------------------|
| **2025-2026** | Malaysia NACSA PQC Readiness Roadmap active | Phase 6 must be complete for NACSA assessments |
| **2026 Dec** | EU NIS Cooperation Group: initial national PQC roadmaps due | CycloneDX CBOM compliance needed for EU market |
| **2027 Jan 1** | CNSA 2.0: all new NSS acquisitions must be compliant | CNSA 2.0 mapping (Task 6.2) critical |
| **2028** | NCSC UK Phase 1 deadline: all crypto assets identified | Triton must be able to produce complete inventory |
| **2030** | NIST: RSA, ECDSA, EdDSA, DH, ECDH deprecated | Timeline warnings in reports (Task 6.2) |
| **2035** | NIST: all classical algorithms disallowed | Full PQC migration must be trackable |

---

### Priority Legend

| Label | Meaning | Timeline |
|-------|---------|----------|
| **P0** | Must-have for NACSA adoption | Next release |
| **P1** | High value for government assessments | Near-term |
| **P2** | Competitive parity with enterprise tools | Medium-term |
| **P3** | Enterprise/ecosystem features | Post-adoption |

---

## 7. Definition of Done

### For Each Task:
- [ ] Tests written first (Red)
- [ ] Code implemented (Green)
- [ ] Refactored and clean
- [ ] All tests pass
- [ ] Coverage > 80%
- [ ] Linter passes
- [ ] Self-review completed
- [ ] Committed with clear message

### For Each Phase:
- [ ] All phase tasks complete
- [ ] Phase code review passed
- [ ] Phase QA gate passed
- [ ] Ready for next phase

### For MVP (v0.1.0):
- [x] All 9 scanning categories implemented
- [x] Jadual 1 & 2 Excel output matches government format
- [x] Crypto-agility assessment produces meaningful results
- [x] Cross-platform builds (macOS, Linux, Windows)
- [x] Documentation complete
- [x] CI/CD pipeline (lint + test + build + release)

### For NACSA-Ready (v1.0):
- [x] CycloneDX CBOM validates against v1.7 schema
- [x] Every finding includes CNSA 2.0 status + NIST deprecation timeline
- [x] NACSA compliance column in Jadual 2
- [x] PQC algorithm OIDs detected (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
- [x] Hybrid certificate detection working
- [x] CAMM-aligned crypto-agility scoring (Level 0-3 auto, Level 4 manual)
- [x] Compliance Summary sheet in Excel report
- [x] Config scanner covers sshd_config, crypto-policies
- [x] `triton doctor` outputs pass/fail per scan category
- [x] All tests pass with >80% coverage

### For Enterprise (v2.0):
- [x] Client-server mode with REST API
- [x] PostgreSQL storage with pgx/v5
- [x] Policy engine with YAML rules and builtin policies
- [x] Web UI dashboard with Chart.js
- [x] 19 scanner modules across 6 target types
- [x] HSM scanning, database encryption auditing
- [x] LDAP scanning, code signing verification
- [x] Scan diff/trend analysis

### For Standards Completion (v2.1):
- [x] All 4 NIST PQC standards: ML-KEM, ML-DSA, SLH-DSA, FN-DSA
- [x] CAMM Level 3 auto-assessment (rotation tool detection)
- [x] Per-system policy evaluation with SystemPattern matching
- [x] Per-system thresholds (max_unsafe, max_deprecated, min_safe_percent)

---

## 8. Emergency Procedures

### If Falling Behind:
1. **Cut scope, not quality** — Remove categories 4 (kernel) and 9 (protocol probing) first, they are lowest priority
2. **Simplify** — Hardcode system grouping instead of auto-detection
3. **Ask for help** — Don't struggle alone for > 2 hours

### If Tests Are Hard to Write:
1. **The code might be poorly designed** — Refactor first
2. **Start with a smaller test** — Test one function, not whole module
3. **Use mocks** — Isolate the code under test

### Priority Order (if time constrained):
1. Certificates & keys (category 5) — already partially done
2. Libraries (category 3) — high value for PQC assessment
3. Network protocols (category 9) — TLS cipher visibility
4. Scripts & web apps (categories 6, 7) — code-level crypto discovery
5. Binaries on disk (category 2) — broad coverage
6. Network applications (category 8) — service mapping
7. Binaries in use (category 1) — runtime view
8. Package scanner — supporting data
9. Kernel modules (category 4) — Linux-specific, lowest priority

---

### Phase 14: Integration & E2E Testing (v2.5)

**Goal:** Add build-tagged integration/e2e tests that validate cross-package interactions, full pipelines, and concurrent behavior without slowing down `make test`.

**Build tag strategy:** `//go:build integration` — unit tests run normally without the tag, integration tests require `-tags integration`.

**Test structure:** `test/integration/` — 7 files, 48 tests total:

| File | Tests | Coverage |
|------|-------|----------|
| `helpers_test.go` | Shared helpers (requireDB, requireServer, scanFixtures, makeScanResult, etc.) | Test infrastructure |
| `cli_pipeline_test.go` | 11 tests | Config → engine → report → policy full pipeline |
| `server_workflow_test.go` | 9 tests | Multi-step API workflows (submit→diff→trend→policy→report) |
| `agent_server_test.go` | 7 tests | Real agent client → real test server |
| `cross_package_test.go` | 6 tests | Engine + store + report + diff + policy interactions |
| `concurrent_test.go` | 5 tests | Multi-module, multi-agent, race detector stress |
| `error_paths_test.go` | 10 tests | Bad config, DB down, oversized payloads, 404s |

**Infrastructure changes:**
- `pkg/scanner/integration_test.go` — retrofitted with `//go:build integration` tag
- `Makefile` — added `test-integration`, `test-all`, `test-integration-race` targets
- `make test` now uses `-p 1` to prevent cross-package DB contention

**Verification commands:**
```bash
make test                    # Unit tests only (~40s)
make test-integration        # Integration only (~3s)
make test-all                # Unit + integration (~45s)
make test-integration-race   # Integration + race detector (~5s)
```

---

### Phase 15: Container Infrastructure _(v2.6 — COMPLETED)_

**Goal:** Full local + CI container infrastructure for deployment and testing. Enables reproducible builds, full-stack local development, CI integration tests, and automated container image publishing.

| Task | Description | Files |
|------|-------------|-------|
| 15.1 | Containerfile | Multi-stage build (`golang:1.25` → `scratch`), `CGO_ENABLED=0` static binary, ldflags version injection via `ARG VERSION=dev`, CA certs + timezone data, `EXPOSE 8080`, ~10MB production image | `Containerfile` |
| 15.2 | Build context exclusions | Excludes `.git`, `.github`, `.claude`, `bin/`, `docs/`, `test/`, `*.md` from build context | `.containerignore` |
| 15.3 | Compose server service | Triton server service with `profiles: [server]`, depends on postgres healthy, internal network (`postgres:5432`), `make db-up` unchanged | `compose.yaml` |
| 15.4 | Makefile container targets | `container-build` (podman build), `container-run` (build + compose --profile server up), `container-stop` (compose down) | `Makefile` |
| 15.5 | CI integration tests | Renamed test→"Unit Test", added `integration-test` job with PostgreSQL 18 service, `-tags integration -race -count=1 -p 1` | `.github/workflows/ci.yml` |
| 15.6 | Release pipeline | Split into 3 jobs: Test (unit + integration with PostgreSQL) → Release (GoReleaser) + Container Image (multi-arch `linux/amd64,linux/arm64` push to `ghcr.io/amiryahaya/triton`), OCI labels | `.github/workflows/release.yml` |

**CI pipeline (4 jobs):**
```
Lint ──→ Unit Test ──→ Integration Test
              │
              └──→ Build
```

**Release pipeline (3 jobs):**
```
Test (unit + integration) ──→ Release (GoReleaser)
                           ──→ Container Image (ghcr.io push)
```

**Verification commands:**
```bash
podman build -t triton:local -f Containerfile .   # Build image
podman run --rm triton:local --version             # Verify binary
make container-run                                 # Full stack (postgres + triton)
curl http://localhost:8080/api/v1/health           # Health check
make container-stop                                # Tear down
```

---

**Remember:** Red → Green → Refactor → Review → QA → Merge

**Quality over speed. Working code over perfect code. Government format compliance is non-negotiable.**
