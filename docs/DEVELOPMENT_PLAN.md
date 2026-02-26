# Triton Development Plan

## SBOM/CBOM Scanner for PQC Compliance

**Version:** 2.0
**Target:** MVP in 5 weeks — standalone CLI for partner buy-in
**Methodology:** Test-Driven Development (TDD) + Code Review + QA Gates
**Language:** Go 1.21+
**Go Quick Reference:** See `docs/GO_QUICK_REFERENCE.md`

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
| Client-server mode | **Deferred** | Future: agent reports to central server |
| CI/CD pipeline | **Deferred** | Set up after code stabilizes |
| Government format (Jadual 1 & 2) | **Primary output** | Exact column match required |
| CycloneDX JSON | Secondary | For interoperability |
| HTML dashboard | Secondary | For presentations |

### 1.3 Success Criteria

| Metric | Target |
|--------|--------|
| Scan 1TB disk | < 2 hours |
| Memory usage | < 200MB |
| Binary size | < 50MB |
| False positive rate | < 5% |
| Test coverage | > 80% |
| Scanning categories | 9 of 9 |
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

## 6. Deferred Items

These are explicitly **not** in the MVP scope:

| Item | Reason | When |
|------|--------|------|
| CI/CD pipeline | Code still evolving rapidly | After Phase 3 stabilizes |
| Client-server mode | MVP is standalone assessment | Post-MVP (v2) |
| Web UI | CLI + reports sufficient for partner demo | Post-MVP |
| Database storage | File-based output sufficient for MVP | Post-MVP |
| Auto-update | Manual distribution for MVP | Post-MVP |
| PKCS#11/HSM scanning | Specialized hardware, low priority | Post-MVP |

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

### For MVP:
- [x] All 9 scanning categories implemented
- [x] Jadual 1 & 2 Excel output matches government format
- [x] Crypto-agility assessment produces meaningful results
- [x] Cross-platform builds (macOS, Linux, Windows)
- [x] Documentation complete

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

**Remember:** Red → Green → Refactor → Review → QA → Merge

**Quality over speed. Working code over perfect code. Government format compliance is non-negotiable.**
