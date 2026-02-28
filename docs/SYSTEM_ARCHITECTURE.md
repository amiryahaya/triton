# Triton System Architecture

**Version:** 4.0
**Status:** Enterprise — CLI + Server + Web UI + Dependency Reachability
**Last Updated:** 2026-03-01

---

## 1. System Overview

Triton is an enterprise-grade CLI + server tool that scans systems for cryptographic assets and generates reports for Malaysian government PQC (Post-Quantum Cryptography) compliance assessment.

**Current scope:** 19 scanner modules across 6 target types (filesystem, network, process, database, HSM, LDAP), REST API server with PostgreSQL storage, policy engine with per-system evaluation, web UI dashboard, dependency crypto reachability analysis, and multi-format report generation (Jadual 1/2 CSV, CycloneDX CBOM v1.7, HTML, SARIF, JSON).

```
┌─────────────────────────────────────────────────────────────────┐
│                        Triton CLI / Server                      │
│                                                                 │
│  triton --profile comprehensive --targets 192.168.1.0/24        │
│  triton server --port 8080                                      │
│                                                                 │
│  Inputs:                        Outputs:                        │
│  • Filesystem paths             • Jadual 1 CSV (SBOM)           │
│  • Network ranges               • Jadual 2 CSV (CBOM)           │
│  • Process scope                • CycloneDX CBOM v1.7 JSON      │
│  • Database endpoints           • HTML dashboard                 │
│  • HSM interfaces               • SARIF (CI/CD integration)     │
│  • LDAP directories             • Web UI dashboard               │
│  • Scan profile                 • Policy evaluation results      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Architecture Diagram

```
                           ┌──────────────┐
                           │   CLI (cmd/)  │
                           │  Cobra + TUI  │
                           └──────┬───────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │              │
             ┌──────▼───────┐ ┌──▼───────┐ ┌───▼──────────┐
             │ Config Loader│ │  Server  │ │  Agent Mode  │
             │  (internal/  │ │ (pkg/    │ │ (pkg/agent/) │
             │   config/)   │ │ server/) │ │              │
             └──────┬───────┘ └──┬───────┘ └───┬──────────┘
                    │            │              │
                    └────────────┼──────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │       Scanner Engine         │
                    │    (pkg/scanner/engine.go)    │
                    │                              │
                    │  • 19 scanner modules         │
                    │  • 6 target types             │
                    │  • Concurrent execution       │
                    │  • Finding collection         │
                    └──┬──────┬──────┬──────┬──────┘
                       │      │      │      │
          ┌────────────┘      │      │      └─────────────┐
          │            ┌──────┘      └──────┐             │
 ┌────────▼────────┐ ┌─▼──────────────┐ ┌──▼───────────┐ ┌▼────────────────┐
 │  Passive/File   │ │ Active/Runtime  │ │ Passive/Code │ │ Specialized      │
 │  Modules        │ │ Modules         │ │ Modules      │ │ Modules          │
 │                 │ │                 │ │              │ │                  │
 │ • certificate(5)│ │ • process (1)   │ │ • script (6) │ │ • database       │
 │ • key         (5)│ │ • network (8)   │ │ • webapp (7) │ │ • hsm            │
 │ • library     (3)│ │ • protocol (9)  │ │ • deps       │ │ • ldap           │
 │ • binary      (2)│ │                 │ │              │ │ • codesign       │
 │ • kernel      (4)│ │                 │ │              │ │ • certstore      │
 │ • package       │ │                 │ │              │ │ • container      │
 │ • config        │ │                 │ │              │ │                  │
 └────────┬────────┘ └───────┬────────┘ └──────┬───────┘ └────────┬────────┘
          │                  │                  │                  │
          └──────────────────┼──────────────────┼──────────────────┘
                             │                  │
                    ┌────────▼──────────────────▼┐
                    │      Finding Channel        │
                    │      chan *Finding           │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   PQC Classifier         │
                    │   (pkg/crypto/)           │
                    │                          │
                    │  • Algorithm registry     │
                    │  • CAMM assessment (0-3)  │
                    │  • CNSA 2.0 / NIST IR8547 │
                    │  • Crypto-agility score   │
                    └────────────┬─────────────┘
                                 │
               ┌─────────────────┼─────────────────┐
               │                 │                  │
    ┌──────────▼──────────┐ ┌───▼──────────┐ ┌────▼──────────┐
    │   Policy Engine      │ │ System       │ │ Diff/Trend    │
    │   (pkg/policy/)      │ │ Grouper      │ │ (pkg/diff/)   │
    │                      │ │ (pkg/report/ │ │               │
    │  • Per-system eval   │ │  grouper.go) │ │ Scan-to-scan  │
    │  • Thresholds        │ │              │ │ comparison     │
    │  • Builtin policies  │ │ Findings →   │ │               │
    │  • YAML custom rules │ │ Systems      │ │               │
    └──────────┬───────────┘ └───┬──────────┘ └────┬──────────┘
               │                 │                  │
               └─────────────────┼──────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Report Generator       │
                    │   (pkg/report/)           │
                    │                          │
                    │  • Jadual 1/2 CSV         │
                    │  • CycloneDX CBOM v1.7    │
                    │  • HTML dashboard         │
                    │  • SARIF (CI/CD)          │
                    │  • JSON (Triton schema)   │
                    └──────────────────────────┘
```

Numbers in parentheses indicate the scanning category (see §5).

---

## 3. Data Model

### 3.1 Entity Relationships

```
ScanResult (1)
├── has many → System (N)           ← for Jadual 1 rows
│   └── has many → CryptoAsset (N)  ← for Jadual 2 rows
├── has many → Finding (N)          ← raw scan output
│   └── has one → CryptoAsset (0..1)
└── has one → Summary (1)
```

### 3.2 Core Types

#### ScanResult — Top-Level Container

```go
type ScanResult struct {
    ID          string        // Unique scan ID (UUID)
    Metadata    ScanMetadata  // When, where, how
    Systems     []System      // Grouped for Jadual 1
    Findings    []Finding     // Raw scan results
    Summary     Summary       // Aggregated stats
}

type ScanMetadata struct {
    Timestamp   time.Time
    Hostname    string
    OS          string
    ScanProfile string
    Targets     []ScanTarget
    Duration    time.Duration
    ToolVersion string
}
```

#### System — Application/Service Entity (Jadual 1 Row)

```go
type System struct {
    ID                string   // Internal reference
    Name              string   // "Sistem / Aplikasi"
    Purpose           string   // "Tujuan/Penggunaan"
    URL               string   // Service URL or endpoint
    ServiceMode       string   // "Mod Perkhidmatan" (Online/Offline)
    TargetCustomer    string   // "Sasaran Pelanggan"
    Components        []string // "Komponen Perisian"
    ThirdPartyModules []string // "Modul Third-party"
    ExternalAPIs      []string // "External APIs / Perkhidmatan"
    CriticalityLevel  string   // "Aras Kritikal" (Tinggi/Sederhana/Rendah)
    DataCategory      string   // "Kategori Data"
    InUse             bool     // "Adakah sistem sedang digunakan"
    Developer         string   // "Pembangun Sistem/Aplikasi"
    Vendor            string   // "Nama vendor"
    CBOMRefs          []string // Links to CBOM entries (e.g., "CBOM #1")
    CryptoAssets      []CryptoAsset // All crypto findings for this system
}
```

#### Finding — Raw Scan Result

```go
type Finding struct {
    ID          string       // Unique finding ID
    Category    int          // Scanning category (1-9)
    Source      FindingSource
    CryptoAsset *CryptoAsset // nil if no crypto detected
    Confidence  float64      // 0.0 to 1.0
    Module      string       // Which scanner module produced this
    Timestamp   time.Time
}

type FindingSource struct {
    Type     string // "file", "process", "network"
    Path     string // File path (for file sources)
    PID      int    // Process ID (for process sources)
    Endpoint string // host:port (for network sources)
}
```

#### CryptoAsset — Cryptographic Discovery (Jadual 2 Row)

```go
type CryptoAsset struct {
    ID              string  // CBOM reference (e.g., "CBOM #1")
    SystemName      string  // Parent system name (for Jadual 2)
    Function        string  // "Fungsi Cryptographic" (e.g., "TLS server authentication")
    Algorithm       string  // "Algoritma yang digunakan"
    Library         string  // "Library/Modul"
    KeySize         int     // "Panjang Kunci" in bits
    Purpose         string  // "Tujuan/Penggunaan"
    CryptoAgility   string  // "Sokongan Crypto-Agility" assessment text

    // Classification (not in Jadual 2, used for dashboard/JSON)
    PQCStatus       string  // SAFE, TRANSITIONAL, DEPRECATED, UNSAFE
    MigrationPriority int   // 0-100 urgency score
    BreakYear       int     // Estimated year quantum could break this

    // Dependency reachability (Phase 12)
    Reachability   string   // "direct", "transitive", "unreachable"
    DependencyPath []string // Import chain: ["myapp", "github.com/foo/bar", "crypto/des"]

    // Certificate-specific (optional)
    Subject      string
    Issuer       string
    SerialNumber string
    NotBefore    time.Time
    NotAfter     time.Time
    IsCA         bool
}
```

#### Summary — Aggregated Statistics

```go
type Summary struct {
    TotalSystems     int
    TotalFindings    int
    TotalCryptoAssets int

    // PQC breakdown
    Safe            int
    Transitional    int
    Deprecated      int
    Unsafe          int

    // Category coverage
    CategoriesScanned []int  // Which of 1-9 were executed
    CategoriesSkipped []int  // Which were skipped (and why)

    // Crypto-agility
    OverallAgility  string   // "High", "Limited", "None"
    AgilityDetails  string   // Explanation
}
```

### 3.3 Scan Target Types

```go
type ScanTarget struct {
    Type   string // "filesystem", "network", "process"
    Value  string // Path, CIDR range, or "all"
    Depth  int    // Max recursion depth (-1 = unlimited)
}
```

### 3.4 File-Level to System-Level Mapping

Raw findings are file-level. The System Grouper (§8) maps them to systems using heuristics:

| Signal | Grouping Logic |
|--------|---------------|
| Shared parent directory | Files under `/opt/myapp/` → one system |
| Process name | Running process using multiple crypto libs → one system |
| Network endpoint | TLS cert on port 443 + process listening → one system |
| Package manager | brew/dpkg package → system named after package |
| Manual hints | Config file can specify `system-name: "My App"` |

Fields that cannot be auto-detected (e.g., "Sasaran Pelanggan", "Kategori Data") are populated with placeholder text indicating manual review is needed.

---

## 4. Module Interface

### 4.1 Interface Definition

```go
// Module is the interface all scanner modules must implement
type Module interface {
    Name() string
    Category() ModuleCategory
    ScanTargetType() ScanTargetType
    Scan(ctx context.Context, target ScanTarget, findings chan<- *Finding) error
}

type ModuleCategory int

const (
    CategoryPassiveFile    ModuleCategory = iota // Read files on disk
    CategoryPassiveCode                          // Pattern-match source code
    CategoryActiveRuntime                        // Inspect running processes
    CategoryActiveNetwork                        // Probe network services
)

type ScanTargetType int

const (
    TargetFilesystem ScanTargetType = iota
    TargetNetwork
    TargetProcess
    TargetDatabase
    TargetHSM
    TargetLDAP
)
```

### 4.2 Module Registry (19 Modules)

| Module | Category | Target Type | Scanning Cat. | Requires Root |
|--------|----------|-------------|---------------|---------------|
| CertificateModule | PassiveFile | Filesystem | 5 | No |
| KeyModule | PassiveFile | Filesystem | 5 | No* |
| LibraryModule | PassiveFile | Filesystem | 3 | No |
| BinaryModule | PassiveFile | Filesystem | 2 | No |
| KernelModule | PassiveFile | Filesystem | 4 | No |
| PackageModule | PassiveFile | Process | — | No |
| ConfigModule | PassiveFile | Filesystem | — | No |
| ProcessModule | ActiveRuntime | Process | 1 | Partial** |
| ScriptModule | PassiveCode | Filesystem | 6 | No |
| WebAppModule | PassiveCode | Filesystem | 7 | No |
| NetworkModule | ActiveRuntime | Network | 8 | Partial** |
| ProtocolModule | ActiveNetwork | Network | 9 | No |
| ContainerModule | PassiveFile | Filesystem | — | No |
| CertStoreModule | PassiveFile | Filesystem | 5 | Partial** |
| DatabaseModule | ActiveRuntime | Database | — | No*** |
| HSMModule | ActiveRuntime | HSM | — | No*** |
| LDAPModule | ActiveNetwork | LDAP | — | No |
| CodeSignModule | PassiveFile | Filesystem | — | No |
| DepsModule | PassiveCode | Filesystem | — | No |

\* Key files may have restrictive permissions
\** Full process/network/certstore enumeration may require root; partial results available without
\*** Requires appropriate credentials for database/HSM access

#### DepsModule — Dependency Crypto Reachability (Phase 12)

The DepsModule scans Go modules to classify crypto dependency reachability:

- **Level 1 (Module-level):** Parses `go.mod` + `go.sum` as text to identify which modules contain crypto
- **Level 2 (Import graph):** Parses `.go` files with `go/parser` (stdlib, no external deps) to build import graph and determine which crypto packages are transitively imported

**Reachability classification:**

| Status | Meaning | Confidence | Example |
|--------|---------|------------|---------|
| `direct` | Your code directly imports this crypto package | 0.95 | `import "crypto/aes"` in your `.go` file |
| `transitive` | A dependency you import uses this crypto | 0.75 | Your code → `github.com/foo/bar` → `crypto/des` |
| `unreachable` | Present in go.sum but not in any import chain | 0.50 | Module in go.sum, no package imports it |

**Key features:**
- BFS shortest-path algorithm for import chain discovery (stored in `CryptoAsset.DependencyPath`)
- Migration priority halved for unreachable findings (reduces false positives)
- Graceful degradation: works without Go toolchain
- Vendor directory parsing support
- Crypto registry: 13 `crypto/*` stdlib + 14 `golang.org/x/crypto/*` + 3 PQC third-party prefixes

### 4.3 Module Lifecycle

```
Engine.Scan()
├── Load config → determine which modules to run
├── Group modules by category
├── Schedule execution:
│   ├── PassiveFile modules → run in parallel on filesystem targets
│   ├── PassiveCode modules → run in parallel on filesystem targets
│   ├── ActiveRuntime modules → run after passive (needs context)
│   └── ActiveNetwork modules → run last (most intrusive)
├── Collect findings via channel
├── Classify each finding (PQC status, agility)
├── Group findings into systems
└── Generate reports
```

---

## 5. Scanning Categories — Implementation Details

### Category 1: Binaries in Use (Active/Runtime)

**What:** Running processes that use cryptographic libraries or perform crypto operations.

**How:**
1. Enumerate processes via `ps aux` / `/proc/*/maps` / `lsof`
2. For each process, check loaded libraries (via `lsof -p` or `/proc/PID/maps`)
3. Match against known crypto library names (libcrypto, libssl, etc.)
4. Extract process metadata: name, PID, user, command line

**Output:** Finding with Source.Type="process", linked CryptoAsset showing which crypto library is loaded.

### Category 2: Binaries on Disk (Passive/File)

**What:** Executable files on disk that contain cryptographic patterns.

**How:**
1. Walk filesystem looking for executables (ELF magic bytes, Mach-O headers, .exe)
2. Run `strings` equivalent on each binary
3. Match against crypto pattern registry (see §9)
4. Optionally analyze symbol tables for crypto function exports

**Output:** Finding with Source.Type="file", CryptoAsset listing detected algorithms.

### Category 3: Cryptographic Libraries (Passive/File)

**What:** Shared libraries that provide cryptographic functionality.

**How:**
1. Search known paths for crypto library files:
   - `libcrypto.so*`, `libssl.so*` (OpenSSL)
   - `libmbedcrypto.so*`, `libmbedtls.so*` (mbedTLS)
   - `libwolfssl.so*` (wolfSSL)
   - `libgnutls.so*` (GnuTLS)
   - `libnss3.so*` (NSS)
   - macOS: `*.dylib` equivalents
2. Extract version info where possible (`strings | grep version`)
3. Check for PQC-capable versions

**Output:** Finding with library name, version, PQC capability.

### Category 4: Kernel Modules (Passive/File — Linux Only)

**What:** Kernel crypto modules in `.ko` files.

**How:**
1. Search `/lib/modules/$(uname -r)/kernel/crypto/` for `.ko` files
2. Run `strings` on each, match crypto patterns
3. Also check `lsmod | grep crypto` for loaded modules
4. **macOS:** Skip gracefully — macOS uses kext, crypto is in kernel proper

**Output:** Finding listing kernel-level crypto algorithms available.

### Category 5: Certificates & Keys (Passive/File)

**What:** X.509 certificates, private keys, keystores on the filesystem.

**How:**
1. Walk filesystem matching extensions: `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`, `.jks`, `.key`
2. Parse PEM headers to classify (certificate, private key, public key)
3. For certificates: extract subject, issuer, algorithm, key size, validity, CA flag
4. For keys: extract algorithm, key size from PEM/PKCS#8 headers
5. Classify PQC status based on algorithm + key size

**Output:** CryptoAsset with full certificate/key metadata.

### Category 6: Executable Scripts (Passive/Code)

**What:** Crypto function calls in scripting languages.

**How:**
1. Walk filesystem for `.py`, `.sh`, `.rb`, `.pl`, `.bash` files
2. Pattern-match against language-specific crypto indicators:
   - Python: `import hashlib`, `from cryptography`, `import ssl`, `Crypto.Cipher`
   - Shell: `openssl`, `ssh-keygen`, `gpg`
   - Ruby: `require 'openssl'`, `OpenSSL::Cipher`
   - Perl: `use Crypt::`, `Digest::SHA`
3. Extract the specific algorithm or function called

**Output:** Finding with source file path and detected crypto usage.

### Category 7: Web Applications (Passive/Code)

**What:** Crypto patterns in web application source code.

**How:**
1. Walk filesystem for `.php`, `.js`, `.ts`, `.go`, `.java`, `.cs`, `.jsp` files
2. Pattern-match against web-specific crypto indicators:
   - PHP: `openssl_encrypt`, `mcrypt_*`, `hash()`
   - JavaScript: `crypto.createCipher`, `CryptoJS`, `subtle.encrypt`
   - Go: `crypto/tls`, `crypto/aes`, `crypto/rsa`
   - Java: `javax.crypto.*`, `java.security.*`, `KeyGenerator`
3. Distinguish between test/example code and production usage (heuristic)

**Output:** Finding with source file and crypto API calls detected.

### Category 8: Network Applications (Active/Runtime)

**What:** Services listening on network ports that use cryptographic protocols.

**How:**
1. Enumerate listening ports via `ss -tlnp` / `lsof -i -P` / `netstat -tlnp`
2. Classify port/protocol:
   - 443, 8443 → HTTPS/TLS
   - 22 → SSH
   - 993, 995 → IMAPS, POP3S
   - 636 → LDAPS
   - 500, 4500 → IPsec
3. Map port to owning process (PID → process name)
4. Create system entity linking process + protocol + port

**Output:** Finding with network endpoint and protocol classification.

### Category 9: Network Protocols (Active/Network)

**What:** Active probing of network services to extract cipher suites and certificate details.

**How:**
1. For TLS services: perform TLS handshake, extract:
   - Negotiated cipher suite
   - Server certificate chain (algorithm, key size, validity)
   - Supported protocol versions (TLS 1.0/1.1/1.2/1.3)
   - Available cipher suites (via enumeration)
2. For SSH services: connect and extract:
   - Key exchange algorithms
   - Host key algorithms
   - Encryption algorithms
   - MAC algorithms
3. Classify all discovered algorithms for PQC status

**Output:** CryptoAssets for each cipher/algorithm discovered, linked to network endpoint.

---

## 6. Concurrency Model

### 6.1 Architecture

The engine uses a **semaphore + channels** pattern, consistent with current implementation:

```
                    ┌─────────────────┐
                    │    Engine.Scan() │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
        │ Worker 1  │ │ Worker 2  │ │ Worker N  │
        │ (module)  │ │ (module)  │ │ (module)  │
        └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │ findings channel │
                    │  (buffered: 100) │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Collector goroutine│
                    │  (single writer)   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Results (mutex)  │
                    └─────────────────┘
```

### 6.2 Worker Pool

```go
semaphore := make(chan struct{}, config.Workers)

for _, target := range targets {
    wg.Add(1)
    semaphore <- struct{}{} // Acquire slot
    go func(t ScanTarget) {
        defer wg.Done()
        defer func() { <-semaphore }() // Release slot
        module.Scan(ctx, t, findings)
    }(target)
}
```

- Worker count is set by profile (`quick`=4, `standard`=8, `comprehensive`=16)
- Capped by `runtime.NumCPU()`
- Each worker runs one module on one target at a time

### 6.3 Execution Ordering

1. **Passive/File modules** run first (filesystem scans)
2. **Passive/Code modules** run in parallel with file modules
3. **Active/Runtime modules** run after passive (may use passive results for context)
4. **Active/Network modules** run last (most intrusive, requires explicit opt-in)

### 6.4 Cancellation

All modules receive `context.Context` and must respect cancellation:

```go
func (m *CertificateModule) Scan(ctx context.Context, target ScanTarget, findings chan<- *Finding) error {
    return filepath.WalkDir(target.Value, func(path string, d fs.DirEntry, err error) error {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }
        // ... scan logic
    })
}
```

---

## 7. PQC Classification & Crypto-Agility Assessment

### 7.1 PQC Status Classification

Every discovered algorithm is classified into one of four levels:

| Status | Meaning | Action | Examples |
|--------|---------|--------|----------|
| **SAFE** | Quantum-resistant or adequate key size | No action needed | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, AES-256, SHA-384, RSA-4096 |
| **TRANSITIONAL** | Currently secure, vulnerable to future quantum | Plan migration | RSA-2048, ECDSA-P256, Ed25519, AES-128 |
| **DEPRECATED** | Known weaknesses, quantum accelerates risk | Replace soon | RSA-1024, SHA-1, 3DES, DSA |
| **UNSAFE** | Broken or trivially broken | Replace immediately | DES, RC4, MD4, MD5, NULL cipher |

Classification uses the algorithm registry in `pkg/crypto/pqc.go`, matching by:
1. Exact algorithm name
2. Algorithm family + key size
3. Pattern matching (normalized names)

### 7.2 Crypto-Agility Assessment (CAMM Framework)

Crypto-agility is assessed using the CAMM (Cryptographic Agility Maturity Model) framework, Levels 0-4:

| CAMM Level | Name | Auto-Assessment | Description |
|------------|------|-----------------|-------------|
| 0 | Unknown | Yes | No crypto inventory available |
| 1 | Inventory | Yes | Complete crypto asset inventory exists |
| 2 | Managed | Yes | PQC-safe algorithms ≥50%, diversity in algorithms |
| 3 | Automated | Yes (partial) | Rotation automation detected (certbot/ACME, Vault PKI, cert-manager) |
| 4 | Optimized | No (manual) | Full PQC migration with continuous monitoring |

**Level 3 auto-detection** scans for rotation tool evidence in findings from configs, scripts, and containers modules:
- ACME/certbot: `certbot`, `acme.sh`, `letsencrypt`, `dehydrated`
- Vault PKI: `vault`, `pki/issue`, `transit/`, `VAULT_ADDR`
- cert-manager: `cert-manager`, `ClusterIssuer`, `cert-manager.io`
- Automated renewal: `renew`, `rotate`, `auto-renew`

**Output values** for Jadual 2 column:
- `"Ya (pelbagai algoritma disokong)"` — High agility (CAMM Level ≥ 2)
- `"Terhad (algoritma klasik; tiada hibrid PQC dikesan)"` — Limited (CAMM Level 1)
- `"Tidak (algoritma tetap, tiada sokongan PQC)"` — None (CAMM Level 0)

### 7.3 Migration Priority Scoring

Enhanced from current basic system. Factors:

```
Priority = base_urgency + criticality_modifier + exposure_modifier - agility_discount

Where:
  base_urgency: UNSAFE=100, DEPRECATED=75, TRANSITIONAL=50, SAFE=0
  criticality_modifier: system criticality (Tinggi=+20, Sederhana=+10, Rendah=0)
  exposure_modifier: network-facing=+15, internal-only=0
  agility_discount: high agility=-10, limited=-5, none=0
```

---

## 8. Report Format Mapping

### 8.0 Supported Output Formats

| Format | File | Description |
|--------|------|-------------|
| Jadual 1 CSV (SBOM) | `pkg/report/jadual.go` | Malaysian government system-level inventory |
| Jadual 2 CSV (CBOM) | `pkg/report/jadual.go` | Malaysian government crypto-asset inventory |
| CycloneDX CBOM v1.7 | `pkg/report/cyclonedx.go` | Standard CBOM with crypto object modeling, NIST quantum levels |
| HTML Dashboard | `pkg/report/generator.go` | PQC dashboard with CAMM scoring, per-system policy results |
| SARIF | `pkg/report/sarif.go` | Static Analysis Results Interchange Format for CI/CD |
| JSON | `pkg/report/json.go` | Triton native schema export |

### 8.1 Jadual 1 (SBOM) — System Level

Maps `System` entities to CSV rows.

| CSV Column | Field | Source | Auto-Detected? |
|-----------|-------|--------|-----------------|
| No. | Row number | Auto-increment | Yes |
| Sistem / Aplikasi | `System.Name` | Process name / directory / package name | Yes |
| Tujuan/Penggunaan | `System.Purpose` | Inferred from process / service type | Partial |
| URL | `System.URL` | Network endpoint discovered | Yes (if network scanned) |
| Mod Perkhidmatan | `System.ServiceMode` | "Online" if listening, else "N/A" | Yes |
| Sasaran Pelanggan | `System.TargetCustomer` | Cannot auto-detect | No — placeholder |
| Komponen Perisian | `System.Components` | Binary names, versions | Yes |
| Modul Third-party | `System.ThirdPartyModules` | Linked libraries | Yes |
| External APIs / Perkhidmatan | `System.ExternalAPIs` | Cannot auto-detect fully | No — placeholder |
| Aras Kritikal | `System.CriticalityLevel` | Based on worst PQC status of crypto assets | Yes |
| Kategori Data | `System.DataCategory` | Cannot auto-detect | No — placeholder |
| Adakah sistem/Aplikasi sedang digunakan | `System.InUse` | Process running = "Ya" | Partial |
| Pembangun Sistem/Aplikasi | `System.Developer` | Package metadata | Partial |
| Nama vendor | `System.Vendor` | Package metadata | Partial |
| Adakah Agensi mempunyai kepakaran | — | Manual assessment | No — placeholder |
| Adakah agensi mempunyai peruntukan khas? | — | Manual assessment | No — placeholder |
| Pautan ke CBOM | `System.CBOMRefs` | Generated CBOM IDs | Yes |

**Placeholder text for non-detectable fields:** `"Perlu disahkan oleh pemilik sistem"`

### 8.2 Jadual 2 (CBOM) — Crypto Asset Level

Maps `CryptoAsset` entities to CSV rows.

| CSV Column | Field | Source | Auto-Detected? |
|-----------|-------|--------|-----------------|
| No. | Row number | Auto-increment | Yes |
| # (CBOM) | `CryptoAsset.ID` | "CBOM #N" sequential | Yes |
| Sistem/Aplikasi | `CryptoAsset.SystemName` | Parent system name | Yes |
| Fungsi Cryptographic | `CryptoAsset.Function` | Inferred from context (TLS auth, key exchange, etc.) | Yes |
| Algoritma yang digunakan | `CryptoAsset.Algorithm` | Parsed from cert/key/probe | Yes |
| Library/Modul | `CryptoAsset.Library` | Source library name | Yes |
| Panjang Kunci | `CryptoAsset.KeySize` | Parsed from cert/key | Yes |
| Tujuan/Penggunaan | `CryptoAsset.Purpose` | Inferred from context | Partial |
| Sokongan Crypto-Agility | `CryptoAsset.CryptoAgility` | Agility assessment (see §7.2) | Yes |

### 8.3 System Grouper Logic

The grouper maps raw findings into `System` entities:

```
Findings → Group by heuristic → System entities

Heuristics (applied in order):
1. Process-based: findings sharing same PID → one system
2. Network-based: findings sharing same endpoint → one system
3. Path-based: findings under same application directory → one system
4. Package-based: findings from same installed package → one system
5. Ungrouped: remaining findings → individual systems (one per finding)
```

Each system gets a generated name from the most descriptive finding (process name > package name > directory name > filename).

---

## 9. Detection Rules — Crypto Pattern Registry

### 9.1 Structure

```go
type CryptoRule struct {
    Pattern     string         // Regex pattern
    Algorithm   string         // Matched algorithm name
    Family      string         // Algorithm family
    Function    string         // Cryptographic function (encryption, hashing, signing, etc.)
    Confidence  float64        // 0.0-1.0 match confidence
    Contexts    []string       // Where this pattern is relevant: "binary", "source", "config"
}
```

### 9.2 Pattern Categories

**Symmetric encryption:**
```
AES[-_]?(128|192|256)[-_]?(GCM|CBC|CTR|CCM|ECB)?
DES|3DES|TDES|Triple.?DES
Blowfish|BF[-_]CBC
RC4|ARCFOUR
ChaCha20[-_]?Poly1305
Camellia[-_]?(128|256)
```

**Asymmetric / key exchange:**
```
RSA[-_]?(1024|2048|3072|4096|8192)
ECDSA[-_]?(P[-_]?256|P[-_]?384|P[-_]?521|secp256r1|secp384r1)
Ed25519|Ed448|EdDSA
DH[-_]?(1024|2048|4096)|Diffie[-_]?Hellman
ECDH[-_]?(P[-_]?256|P[-_]?384|X25519|X448)
DSA[-_]?(1024|2048)
```

**Hash functions:**
```
SHA[-_]?(1|224|256|384|512)|SHA3[-_]?(224|256|384|512)
MD[245]
RIPEMD[-_]?(128|160|256)
BLAKE[23]
HMAC[-_]?(SHA|MD5)
```

**PQC algorithms (all 4 NIST standards):**
```
ML[-_]?KEM[-_]?(512|768|1024)?|CRYSTALS[-_]?Kyber|Kyber(512|768|1024)
ML[-_]?DSA[-_]?(44|65|87)?|CRYSTALS[-_]?Dilithium|Dilithium[2345]
SLH[-_]?DSA[-_]?(128[sf]|192[sf]|256[sf])?|SPHINCS\+?
FN[-_]?DSA[-_]?(512|1024)?|FALCON[-_]?(512|1024)
```

**NIST PQC Standards Coverage:**
| Standard | FIPS | Algorithms | Status |
|----------|------|-----------|--------|
| ML-KEM | FIPS 203 | ML-KEM-512/768/1024 | SAFE |
| ML-DSA | FIPS 204 | ML-DSA-44/65/87 | SAFE |
| SLH-DSA | FIPS 205 | SLH-DSA-128s through 256f | SAFE |
| FN-DSA | FIPS 206 | FN-DSA-512/1024 | SAFE |

**Protocol patterns:**
```
TLS[-_]?(1[._][0123])|SSLv[23]
SSH[-_]?(RSA|ED25519|ECDSA)
IPsec|IKEv[12]
```

**Library-specific function patterns (for code scanning):**

| Language | Patterns |
|----------|----------|
| Python | `hashlib\.\w+`, `Crypto\.Cipher`, `from cryptography`, `import ssl` |
| Go | `crypto/(aes\|rsa\|ecdsa\|tls\|sha256)` |
| Java | `javax\.crypto\.\w+`, `java\.security\.\w+`, `KeyGenerator` |
| PHP | `openssl_(encrypt\|decrypt\|sign\|verify)`, `mcrypt_\w+`, `hash\(` |
| JavaScript | `crypto\.create\w+`, `CryptoJS`, `subtle\.(encrypt\|decrypt\|sign)` |
| C/C++ | `EVP_(Encrypt\|Decrypt\|Digest)\w+`, `SSL_CTX_\w+` |

### 9.3 Confidence Levels

| Source | Base Confidence |
|--------|----------------|
| Certificate parsing (X.509) | 0.95 |
| Dependency analysis — direct import | 0.95 |
| PEM header match | 0.90 |
| TLS handshake result | 0.95 |
| SSH algorithm negotiation | 0.95 |
| Library file detection | 0.85 |
| Dependency analysis — transitive import | 0.75 |
| Source code pattern match | 0.70 |
| Kernel module strings | 0.65 |
| Binary strings match | 0.60 |
| Dependency analysis — unreachable | 0.50 |

---

## 10. Policy Engine

### 10.1 Policy Definition

Policies are defined in YAML and support rules (per-finding conditions) and thresholds (aggregate limits):

```yaml
version: "1"
name: "my-policy"
rules:
  - id: no-unsafe
    severity: error
    condition:
      pqc_status: UNSAFE
    action: fail
  - id: no-small-rsa
    severity: error
    condition:
      algorithm_family: RSA
      key_size_below: 4096
      system_pattern: "TLS*"     # Only apply to TLS systems
    action: fail
thresholds:
  max_unsafe_count: 0
  min_nacsa_readiness: 60.0
  per_system:
    - system_pattern: "*"
      max_unsafe_count: 0
      min_safe_percent: 50.0
```

### 10.2 Per-System Evaluation

The policy engine evaluates rules both at the aggregate level (all findings) and per-system level (grouped by `model.System`):

- **SystemPattern** in rule conditions — glob-style matching (`TLS*`, `*ssl*`, `Files*`) against system names
- **Per-system thresholds** — max_unsafe_count, max_deprecated_count, min_safe_percent per system
- **Verdict escalation** — worst per-system verdict escalates overall verdict (PASS < WARN < FAIL)

### 10.3 Builtin Policies

| Policy | File | Description |
|--------|------|-------------|
| nacsa-2030 | `pkg/policy/builtin/nacsa-2030.yaml` | NACSA PQC Migration Framework compliance |
| cnsa-2.0 | `pkg/policy/builtin/cnsa-2.0.yaml` | NSA CNSA 2.0 requirements |

---

## 11. Security Considerations

### 11.1 Principle: Read-Only, No Modification

Triton **never modifies** the target system. It is a read-only assessment tool.

- No files are written to the scanned system (reports go to specified output directory)
- No system configuration is changed
- No packages are installed or removed
- No services are started or stopped
- Network probes are read-only (TLS handshake, SSH banner)

### 11.2 Privilege Requirements

| Operation | Minimum Privilege | Degradation |
|-----------|-------------------|-------------|
| File scanning (categories 2-7) | User read access | Skips unreadable files |
| Certificate/key parsing | User read access | Skips permission-denied files |
| Process enumeration (category 1) | User (own processes) / root (all) | Shows only user's processes |
| Network port listing (category 8) | User (partial) / root (full) | May miss some listeners |
| Network probing (category 9) | User | No degradation |
| Kernel module scanning (category 4) | User read access | Skips if /lib/modules unreadable |
| OS certificate store | User (partial) / root (full) | May miss system-level certs |
| Database encryption auditing | Database credentials | Skips if connection fails |
| HSM scanning | PKCS#11 credentials | Skips if slot unavailable |
| LDAP scanning | LDAP bind credentials | Skips if bind fails |

### 11.3 Output Security

- Report files written with `0640` permissions (owner read/write, group read)
- No credentials, private key material, or sensitive data included in reports
- Private key findings record only: type, algorithm, key size, file path
- Certificate findings exclude private key components

### 11.4 Network Scanning Safety

- Active network scanning (categories 8, 9) is **off by default**
- Requires explicit `--targets` flag to enable
- Only scans specified hosts/ranges — never auto-discovers
- TLS probes use standard handshake — no exploit attempts
- All network operations have 10-second default timeout
- Rate limiting: max 50 concurrent connections

---

## 12. Package Structure

```
triton/
├── main.go                          # Entry point
├── cmd/
│   └── root.go                      # Cobra CLI + BubbleTea TUI
├── internal/
│   ├── config/
│   │   └── config.go                # Profile-based config, scan targets
│   └── version/
│       └── version.go               # Version constant
├── pkg/
│   ├── model/
│   │   └── types.go                 # ScanResult, System, Finding, CryptoAsset
│   ├── scanner/
│   │   ├── engine.go                # Orchestrator, module registry, concurrency
│   │   ├── certificate.go           # Category 5: certificates
│   │   ├── key.go                   # Category 5: private/public keys
│   │   ├── library.go               # Category 3: crypto shared libraries
│   │   ├── binary.go                # Category 2: binaries on disk
│   │   ├── kernel.go                # Category 4: kernel modules (Linux)
│   │   ├── package.go               # Package manager queries
│   │   ├── config.go                # Config file scanner (sshd, crypto-policies, certbot)
│   │   ├── process.go               # Category 1: binaries in use
│   │   ├── script.go                # Category 6: executable scripts
│   │   ├── webapp.go                # Category 7: web application code
│   │   ├── network.go               # Category 8: network applications
│   │   ├── protocol.go              # Category 9: network protocol probing
│   │   ├── container.go             # Dockerfile/compose/k8s config scanning
│   │   ├── certstore.go             # OS certificate store scanning
│   │   ├── database.go              # Database encryption auditing (TDE)
│   │   ├── hsm.go                   # PKCS#11 / HSM scanning
│   │   ├── ldap.go                  # LDAP directory certificate scanning
│   │   ├── codesign.go              # Code signing verification
│   │   ├── deps.go                  # Go dependency crypto reachability (Phase 12)
│   │   ├── doctor.go                # Pre-scan environment check
│   │   └── walker.go                # Filesystem walker utility
│   ├── crypto/
│   │   ├── pqc.go                   # Algorithm registry (~240+ algorithms), PQC classification
│   │   ├── oid.go                   # ASN.1 OID → algorithm mapping (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
│   │   ├── camm.go                  # CAMM Level 0-3 auto-assessment
│   │   ├── agility.go               # Crypto-agility assessment
│   │   └── rules.go                 # Detection pattern registry
│   ├── policy/
│   │   ├── policy.go                # Policy types (rules, conditions, thresholds)
│   │   ├── engine.go                # Policy evaluation engine (per-system + aggregate)
│   │   └── builtin/                 # Embedded policies (nacsa-2030, cnsa-2.0)
│   ├── diff/
│   │   └── diff.go                  # Scan diff/trend analysis
│   ├── store/
│   │   ├── store.go                 # Store interface (8 methods)
│   │   └── postgres.go              # PostgreSQL implementation (pgx v5)
│   ├── server/
│   │   ├── server.go                # REST API server (go-chi/chi/v5)
│   │   └── ui/                      # Embedded web UI (vanilla JS + Chart.js)
│   ├── agent/
│   │   └── agent.go                 # HTTP agent for remote scan submission
│   └── report/
│       ├── generator.go             # HTML report with PQC dashboard + per-system policy
│       ├── cyclonedx.go             # CycloneDX CBOM v1.7 with crypto objects
│       ├── jadual.go                # Jadual 1 (SBOM) + Jadual 2 (CBOM) CSV
│       ├── grouper.go               # Finding → System grouper
│       ├── sarif.go                 # SARIF output for CI/CD
│       └── json.go                  # Triton JSON schema export
├── test/
│   └── fixtures/                    # Test data (certs, keys, scripts, etc.)
├── docs/
│   ├── DEVELOPMENT_PLAN.md          # Full development plan (Phases 1-12)
│   ├── SYSTEM_ARCHITECTURE.md       # This document
│   ├── CODE_REVIEW_CHECKLIST.md     # Review checklist
│   ├── QA_GATE_CHECKLIST.md         # QA gate checklist
│   ├── GO_QUICK_REFERENCE.md        # Go beginner reference
│   └── sample/
│       ├── Jadual_1_SBOM.csv        # Government format sample
│       └── Jadual_2_CBOM.csv        # Government format sample
├── compose.yaml                     # PostgreSQL 18 container (port 5434)
├── Makefile
├── go.mod
├── go.sum
└── CLAUDE.md
```

---

## 13. Client-Server Architecture (Implemented)

```
┌──────────────────┐     ┌──────────────────┐
│  Triton Agent     │     │  Triton Agent     │
│  (Machine A)      │     │  (Machine B)      │
│  Runs local scan  │     │  Runs local scan  │
└────────┬─────────┘     └────────┬─────────┘
         │ HTTPS POST             │ HTTPS POST
         │ (ScanResult JSON)      │ (ScanResult JSON)
         ▼                        ▼
┌──────────────────────────────────────────┐
│         Triton Server (go-chi/chi/v5)     │
│                                           │
│  • REST API for scan submission/query     │
│  • PostgreSQL 18 storage (pgx/v5)         │
│  • Policy evaluation (per-system + agg)   │
│  • Scan diff/trend analysis               │
│  • Embedded Web UI (Chart.js)             │
│  • CycloneDX CBOM v1.7 export             │
└───────────────────────────────────────────┘
```

**Key components:**
- `pkg/server/server.go` — REST API with go-chi/chi/v5 router
- `pkg/store/postgres.go` — PostgreSQL 18 via pgx/v5 (JSONB storage, connection pooling)
- `pkg/agent/agent.go` — HTTP client for remote scan submission
- `pkg/server/ui/` — Embedded vanilla JS + Chart.js web dashboard
- `pkg/policy/` — YAML policy engine with builtins (nacsa-2030, cnsa-2.0)
- `pkg/diff/` — Composite-key matching for scan-to-scan comparison

**Database:** PostgreSQL 18 on port 5434 (via `compose.yaml`), using JSONB for scan results and TIMESTAMPTZ for timestamps.

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| SBOM | Software Bill of Materials — inventory of software components |
| CBOM | Cryptographic Bill of Materials — inventory of cryptographic assets |
| PQC | Post-Quantum Cryptography — algorithms resistant to quantum computers |
| Jadual 1 | Malaysian government SBOM format (system-level inventory) |
| Jadual 2 | Malaysian government CBOM format (crypto-asset inventory) |
| Crypto-agility | Ability of a system to switch cryptographic algorithms without major redesign |
| NCII | National Critical Information Infrastructure |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism (NIST PQC standard, formerly Kyber) |
| ML-DSA | Module-Lattice Digital Signature Algorithm (NIST PQC standard, formerly Dilithium) |
