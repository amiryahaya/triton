# Scanner Platform Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Address three major architecture concerns (F2, F4, F7) surfaced by the review of PR #47 so the next scanner (Crypto Agility, .NET IL, Python AST, etc.) builds on a single source of truth instead of N-place coordination hazards.

**Why now:** With three scanner modules landed on the same template (asn1_oid PR #43, hybrid PQC PR #44, java_bytecode PR #47), the drift surface is visible but still small. Each additional format scanner multiplies the refactor cost.

**Architecture:**

1. **F2 — Algorithm registry single-source-of-truth.** `pkg/crypto/pqc.go::algorithmRegistry` (keyed by canonical name) becomes the sole authority for `Status`/`Family`. Format-specific registries (OID, TLS groups, Java literals) map `format-key → AlgorithmID` only, then resolve Status/Family via the canonical registry. A startup-time validator panics if a format entry references an unknown algorithm.

2. **F4 — `RegisterDefaultModules` typed catalog.** Replace the 142-line imperative `e.RegisterModule(NewXxx(e.config))` list with a `[]func(*scannerconfig.Config) Module` slice. Drops ~120 lines, removes stale sprint/phase comments, keeps deterministic registration order.

3. **F7 — `FileReaderAware` contract enforcement.** Today `asn1_oid.go` and `java_bytecode.go` implement `SetFileReader` but never read the value — agentless scans silently drop findings. Pick one direction per module: either (a) plumb `fsadapter.FileReader` through `ExtractSections`/`ScanJAR` so agentless works, or (b) remove `SetFileReader` from modules that can't support it. Document the chosen contract.

**Tech Stack:** Go 1.26, existing registries, existing Module interface. No new dependencies. Pure refactor — behavior-preserving except where F7 explicitly enables agentless for existing modules.

---

## Pre-flight

- [ ] **Step 0: Baseline compiles and tests pass on `feat/platform-cleanup`.**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/platform-cleanup
make build && make test && make lint
```

---

## Phase 1 — F2: Registry Single-Source-of-Truth

### Task 1: Add canonical-algorithm validator to `pkg/crypto/pqc.go`

**Files:**
- Modify: `pkg/crypto/pqc.go`
- Create: `pkg/crypto/canonical.go`
- Create: `pkg/crypto/canonical_test.go`

- [ ] **Step 1: Write failing test asserting every OID/TLS-group/Java-alg entry names a known algorithm**

Create `pkg/crypto/canonical_test.go`:
```go
package crypto

import "testing"

// TestCanonicalAlgorithmReferences_OID asserts every OID-registry entry names
// an algorithm that exists in the authoritative algorithmRegistry. Catches
// the case where someone adds a new OID but forgets to register the
// underlying algorithm — which would make the finding classify as unknown.
func TestCanonicalAlgorithmReferences_OID(t *testing.T) {
    missing := ValidateOIDRegistryAlgorithms()
    if len(missing) > 0 {
        t.Errorf("OID entries reference %d algorithms not in algorithmRegistry: %v", len(missing), missing)
    }
}

func TestCanonicalAlgorithmReferences_TLSGroups(t *testing.T) {
    missing := ValidateTLSGroupAlgorithms()
    if len(missing) > 0 {
        t.Errorf("TLS group entries reference %d algorithms not in algorithmRegistry: %v", len(missing), missing)
    }
}

func TestCanonicalAlgorithmReferences_JavaAlgorithms(t *testing.T) {
    missing := ValidateJavaAlgorithmReferences()
    if len(missing) > 0 {
        t.Errorf("Java-algorithm entries reference %d algorithms not in algorithmRegistry: %v", len(missing), missing)
    }
}
```

- [ ] **Step 2: Run — expect FAIL (undefined)**

```bash
go test -v -run TestCanonicalAlgorithmReferences ./pkg/crypto
```

- [ ] **Step 3: Implement `pkg/crypto/canonical.go`**

```go
package crypto

// ValidateOIDRegistryAlgorithms returns the list of algorithm names that
// OID-registry entries reference but algorithmRegistry does not define.
// An empty result means the two registries are consistent.
//
// Any name returned here indicates a format-specific registry added an
// entry without the corresponding authoritative algorithm metadata.
// Fix by adding the algorithm to algorithmRegistry in pqc.go.
func ValidateOIDRegistryAlgorithms() []string {
    var missing []string
    seen := map[string]bool{}
    for _, entry := range oidRegistry {
        name := entry.Algorithm
        if name == "" || seen[name] {
            continue
        }
        seen[name] = true
        if _, ok := algorithmRegistry[name]; !ok {
            missing = append(missing, name)
        }
    }
    return missing
}

// ValidateTLSGroupAlgorithms returns the list of algorithm names that
// TLS-group entries reference but algorithmRegistry does not define.
func ValidateTLSGroupAlgorithms() []string {
    var missing []string
    seen := map[string]bool{}
    for _, entry := range tlsGroupRegistry {
        name := entry.Name
        if name == "" || seen[name] {
            continue
        }
        seen[name] = true
        if _, ok := algorithmRegistry[name]; !ok {
            missing = append(missing, name)
        }
    }
    return missing
}

// ValidateJavaAlgorithmReferences returns the list of canonical algorithm
// names that Java-algorithm entries reference but algorithmRegistry does
// not define.
func ValidateJavaAlgorithmReferences() []string {
    var missing []string
    seen := map[string]bool{}
    for _, entry := range javaAlgorithmRegistry {
        name := entry.Algorithm
        if name == "" || seen[name] {
            continue
        }
        seen[name] = true
        if _, ok := algorithmRegistry[name]; !ok {
            missing = append(missing, name)
        }
    }
    return missing
}
```

- [ ] **Step 4: Run — expect failures listing unregistered algorithm names.**

This is the important step: the test will report which names are referenced but missing. Examples you'll likely see:
- `"SHA256-RSA"` (OID registry uses hyphenated form, pqc.go may use `"SHA256withRSA"`)
- `"MLKEM768"` (TLS group uses no-hyphen form)
- `"X25519Kyber768Draft00"` (no algorithmRegistry entry)

Record the full list — this is your work queue for Step 5.

- [ ] **Step 5: For every missing name, resolve by ONE of:**
  - **(a)** Add the name as an alias in `algorithmRegistry` (`pqc.go`) when it's a legitimately-distinct form. Example: `"SHA256-RSA": {Name: "SHA256withRSA", Family: "RSA", Status: TRANSITIONAL}` (same metadata, different canonical spelling).
  - **(b)** Fix the format-specific registry entry to reference the correct canonical name. Example: change the OID entry's `Algorithm` field from `"SHA256-RSA"` to `"SHA256withRSA"`.

For this PR, prefer (a) — it's additive and won't change existing finding output. Option (b) changes the algorithm name that users see in reports and should be a separate contracted change.

- [ ] **Step 6: Re-run tests — expect PASS.**

```bash
go test -v -run TestCanonicalAlgorithmReferences ./pkg/crypto
```

- [ ] **Step 7: Commit**

```bash
git add pkg/crypto/canonical.go pkg/crypto/canonical_test.go pkg/crypto/pqc.go pkg/crypto/oid_data_pqc.go pkg/crypto/oid_data_classical.go pkg/crypto/tls_groups.go pkg/crypto/java_algorithms.go
git commit -m "feat(crypto): add cross-registry algorithm-name consistency validator"
```

---

### Task 2: Wire validator into `init()` as a panic guard

**Files:**
- Modify: `pkg/crypto/canonical.go`
- Create: `pkg/crypto/canonical_init_test.go`

Rationale: a startup panic is loud and immediate when a developer introduces drift. Better than a silent missed-classification bug in production.

- [ ] **Step 1: Write failing test that asserts `init()` panics on injected drift**

In a test file that uses `TestMain` or a helper, can't directly test `init()` panic. Use a go:build tag + a separate test binary, OR test the helper function in isolation.

Simpler approach: expose a `validateRegistriesConsistent() error` function and have `init()` call it, panicking on non-nil error. Test the pure function directly.

```go
// canonical_init_test.go
package crypto

import "testing"

func TestValidateRegistriesConsistent_CurrentStateIsClean(t *testing.T) {
    if err := validateRegistriesConsistent(); err != nil {
        t.Fatalf("registries have drift after Task 1 fixes: %v", err)
    }
}
```

- [ ] **Step 2: Run — expect PASS if Task 1 was complete**

- [ ] **Step 3: Add `validateRegistriesConsistent()` + `init()` call**

Append to `canonical.go`:
```go
import "fmt"

// validateRegistriesConsistent runs all three ValidateXxx checks and
// returns a combined error listing every drift it finds. Called from
// init() to fail fast on startup if format-specific registries reference
// algorithms not defined in the authoritative algorithmRegistry.
func validateRegistriesConsistent() error {
    var errs []string
    if m := ValidateOIDRegistryAlgorithms(); len(m) > 0 {
        errs = append(errs, fmt.Sprintf("OID registry references unknown algorithms: %v", m))
    }
    if m := ValidateTLSGroupAlgorithms(); len(m) > 0 {
        errs = append(errs, fmt.Sprintf("TLS group registry references unknown algorithms: %v", m))
    }
    if m := ValidateJavaAlgorithmReferences(); len(m) > 0 {
        errs = append(errs, fmt.Sprintf("Java algorithm registry references unknown algorithms: %v", m))
    }
    if len(errs) > 0 {
        return fmt.Errorf("crypto registry drift detected:\n  - %s", strings.Join(errs, "\n  - "))
    }
    return nil
}

func init() {
    if err := validateRegistriesConsistent(); err != nil {
        panic(err)
    }
}
```

Add the `strings` import if needed.

- [ ] **Step 4: Run — PASS expected**

```bash
go test ./pkg/crypto/...
```

If there's an init-ordering issue (format registries init AFTER canonical.go's init), move the `init()` panic-guard to a separate file whose name sorts last alphabetically (e.g., `zz_validate.go`) — Go runs init() in lexical filename order within a package.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/canonical.go pkg/crypto/canonical_init_test.go
git commit -m "feat(crypto): panic on registry drift at init() for fail-fast feedback"
```

---

## Phase 2 — F4: `RegisterDefaultModules` typed catalog

### Task 3: Replace imperative registration list with a factory slice

**Files:**
- Modify: `pkg/scanner/engine.go`
- Modify: `pkg/scanner/engine_test.go`

- [ ] **Step 1: Write failing test asserting all 30 modules still register**

Read existing `TestRegisterDefaultModules_Count` in `engine_test.go`. It likely asserts module count = 30. Change it to also assert specific module names are present (spot-check for regression coverage).

```go
func TestRegisterDefaultModules_AllKnownModulesPresent(t *testing.T) {
    cfg := &scannerconfig.Config{}
    e := New(cfg)
    e.RegisterDefaultModules()
    got := map[string]bool{}
    for _, m := range e.modules {
        got[m.Name()] = true
    }
    expected := []string{
        "certificate", "key", "library", "binary", "kernel", "package", "config",
        "script", "webapp", "process", "network", "protocol",
        "container", "certstore", "database", "hsm", "ldap", "codesign",
        "deps", "deps_ecosystems", "auth_material", "blockchain", "db_atrest",
        "dnssec", "enrollment", "fido2", "container_signatures", "codesign_pe_jar",
        "web_server", "vpn_config", "asn1_oid", "java_bytecode",
        // ... match the full set
    }
    for _, name := range expected {
        if !got[name] {
            t.Errorf("missing module: %s", name)
        }
    }
}
```

Before writing the list: grep the current `RegisterDefaultModules()` body to enumerate every `NewXxx(e.config)` constructor. The test should enumerate exactly that set.

- [ ] **Step 2: Run — expect PASS with current imperative implementation**

- [ ] **Step 3: Refactor to typed catalog**

Replace the current body of `RegisterDefaultModules()` with:

```go
// defaultModuleFactories enumerates every Module constructor registered by
// the engine on startup. Adding a new scanner: append its factory here and
// add a profile entry in internal/scannerconfig/config.go. Engine dispatch
// (getTargetsForModule + shouldRunModule) handles per-profile / per-tier
// filtering, so registration itself is a pure enumeration.
//
// Registration order is preserved for deterministic behavior in tests that
// might assert iteration order; concurrent execution at scan time means
// runtime ordering is not observable to users.
var defaultModuleFactories = []func(*scannerconfig.Config) Module{
    func(c *scannerconfig.Config) Module { return NewCertificateModule(c) },
    func(c *scannerconfig.Config) Module { return NewKeyModule(c) },
    func(c *scannerconfig.Config) Module { return NewLibraryModule(c) },
    func(c *scannerconfig.Config) Module { return NewBinaryModule(c) },
    func(c *scannerconfig.Config) Module { return NewKernelModule(c) },
    func(c *scannerconfig.Config) Module { return NewPackageModule(c) },
    func(c *scannerconfig.Config) Module { return NewConfigModule(c) },
    func(c *scannerconfig.Config) Module { return NewScriptModule(c) },
    func(c *scannerconfig.Config) Module { return NewWebAppModule(c) },
    func(c *scannerconfig.Config) Module { return NewProcessModule(c) },
    func(c *scannerconfig.Config) Module { return NewNetworkModule(c) },
    func(c *scannerconfig.Config) Module { return NewProtocolModule(c) },
    func(c *scannerconfig.Config) Module { return NewContainerModule(c) },
    func(c *scannerconfig.Config) Module { return NewCertStoreModule(c) },
    func(c *scannerconfig.Config) Module { return NewDatabaseModule(c) },
    func(c *scannerconfig.Config) Module { return NewHSMModule(c) },
    func(c *scannerconfig.Config) Module { return NewLDAPModule(c) },
    func(c *scannerconfig.Config) Module { return NewCodeSignModule(c) },
    func(c *scannerconfig.Config) Module { return NewDepsModule(c) },
    func(c *scannerconfig.Config) Module { return NewDepsEcosystemsModule(c) },
    func(c *scannerconfig.Config) Module { return NewAuthMaterialModule(c) },
    func(c *scannerconfig.Config) Module { return NewBlockchainModule(c) },
    func(c *scannerconfig.Config) Module { return NewDBAtRestModule(c) },
    func(c *scannerconfig.Config) Module { return NewDNSSECModule(c) },
    func(c *scannerconfig.Config) Module { return NewEnrollmentModule(c) },
    func(c *scannerconfig.Config) Module { return NewFIDO2Module(c) },
    func(c *scannerconfig.Config) Module { return NewContainerSignaturesModule(c) },
    func(c *scannerconfig.Config) Module { return NewCodeSignPEJARModule(c) },
    func(c *scannerconfig.Config) Module { return NewWebServerModule(c) },
    func(c *scannerconfig.Config) Module { return NewVPNConfigModule(c) },
    func(c *scannerconfig.Config) Module { return NewASN1OIDModule(c) },
    func(c *scannerconfig.Config) Module { return NewJavaBytecodeModule(c) },
}

// RegisterDefaultModules registers every factory in defaultModuleFactories.
// Per-profile / per-tier filtering happens later in the dispatch pipeline.
func (e *Engine) RegisterDefaultModules() {
    for _, factory := range defaultModuleFactories {
        e.RegisterModule(factory(e.config))
    }
}
```

Before writing the slice: **grep `engine.go` for every `e.RegisterModule(New...)` call and map them all** — the list above may be slightly incomplete relative to current main. Don't ship a refactor that drops a module.

- [ ] **Step 4: Run tests — expect PASS (module count unchanged, names unchanged)**

```bash
go test ./pkg/scanner/...
```

- [ ] **Step 5: Run full scanner-related integration tests to verify no regressions**

```bash
go test -tags integration -run 'TestASN1OID|TestJavaBytecode|TestHybridPQC|TestProtocol' ./test/integration/...
```

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/engine.go pkg/scanner/engine_test.go
git commit -m "refactor(scanner): replace imperative module registration with typed factory catalog"
```

---

## Phase 3 — F7: `FileReaderAware` contract

### Task 4: Decision — plumb `FileReader` into binsections + javaclass, or remove `SetFileReader`?

**This is the key decision for Phase 3.** Before writing code, make the choice:

**Option 1 (plumb through):** Add `ExtractSectionsWithReader(r fsadapter.FileReader, path string)` and `ScanJARWithReader(r fsadapter.FileReader, path string)`. Module's `scanBinary`/`scanArtifact` calls the `-WithReader` variant when `m.reader != nil`, otherwise the standard variant.
  - **Pros:** agentless scanning actually works for both scanners. Unblocks downstream remote-scan features.
  - **Cons:** More code; `fsadapter.FileReader` interface must support random-access read (ELF/Mach-O/PE section parsing needs `ReaderAt`) and ZIP decoding (`archive/zip.NewReader` needs `io.ReaderAt` + `int64` size). Some agentless readers may not support `ReaderAt` efficiently (network-backed readers would need to buffer).

**Option 2 (remove dead adapter):** Delete `SetFileReader` + `reader` field from `asn1_oid.go` and `java_bytecode.go`. Document in each scanner's file header: "This module does not support agentless scans; it reads from the local filesystem only."
  - **Pros:** Interface tells the truth. Trivial change. Zero runtime behavior change (current behavior is already "reader is stored and ignored").
  - **Cons:** Remote scans won't find Java/JAR or ELF-OID findings. If agentless mode is on the roadmap, this is a temporary retreat.

**Recommendation:** Option 2 for this PR. Rationale: Option 1 requires reworking `fsadapter.FileReader` interface + both internal packages — genuine agentless binary scanning is a feature PR, not a cleanup PR. Today the code lies about supporting agentless; make it honest. Agentless binary scanning can be its own PR when someone has a concrete customer need.

**Confirm choice with user-level ADR note before proceeding.**

- [ ] **Step 0: ASK the controller if Option 1 vs Option 2 — default to Option 2 if no answer in 10s.**

(For subagent executing this plan: if spawned fresh, default to Option 2 per recommendation above. If you're the controller dispatching this plan, pick one and tell the subagent.)

---

### Task 5 (Option 2 path): Remove `SetFileReader` from asn1_oid + java_bytecode

**Files:**
- Modify: `pkg/scanner/asn1_oid.go`
- Modify: `pkg/scanner/asn1_oid_test.go`
- Modify: `pkg/scanner/java_bytecode.go`
- Modify: `pkg/scanner/java_bytecode_test.go`
- Modify: `docs/scanners/asn1_oid.md`
- Modify: `docs/scanners/java_bytecode.md`

- [ ] **Step 1: Write failing test asserting neither module implements `FileReaderAware`**

```go
// pkg/scanner/fileReaderAware_test.go — adds or appends to existing test file
package scanner

import "testing"

// TestFileReaderAware_OnlyAgentlessCompatibleModules asserts that only
// modules which actually honor the reader implement FileReaderAware.
// Prevents the "dead adapter" pattern from returning (modules that store
// the reader but call os.Open directly, silently missing remote files).
func TestFileReaderAware_OnlyAgentlessCompatibleModules(t *testing.T) {
    cfg := &scannerconfig.Config{}
    e := New(cfg)
    e.RegisterDefaultModules()
    for _, m := range e.modules {
        name := m.Name()
        _, implements := m.(FileReaderAware)
        // asn1_oid and java_bytecode do NOT support agentless (they call
        // os.Open / zip.OpenReader directly). They must not implement
        // FileReaderAware.
        isBinaryReader := name == "asn1_oid" || name == "java_bytecode"
        if isBinaryReader && implements {
            t.Errorf("%s implements FileReaderAware but doesn't honor reader — remove SetFileReader until agentless is wired", name)
        }
    }
}
```

- [ ] **Step 2: Run — expect FAIL (both currently implement it)**

- [ ] **Step 3: Remove `SetFileReader` + `reader` field from both modules**

In `pkg/scanner/asn1_oid.go`:
- Remove `reader fsadapter.FileReader` field from struct
- Remove `SetFileReader` method
- Remove `reader: m.reader` from the `walkerConfig{}` literal (keep the rest)
- Remove `fsadapter` import if now unused

In `pkg/scanner/java_bytecode.go`: same changes.

Add a file-header doc comment to each:
```go
// This module does not currently support agentless (remote) scanning.
// Section extraction / ZIP reading uses stdlib os.Open and zip.OpenReader
// which are filesystem-local. Remote agentless support requires an
// io.ReaderAt-capable FileReader adapter and is tracked as a follow-up.
```

- [ ] **Step 4: Update tests if any assert `SetFileReader` on these modules**

Search for `SetFileReader.*asn1_oid\|SetFileReader.*java_bytecode` in test files — update or remove.

- [ ] **Step 5: Run — expect PASS**

```bash
go test ./pkg/scanner/...
```

- [ ] **Step 6: Update docs**

In `docs/scanners/asn1_oid.md` and `docs/scanners/java_bytecode.md`, add a "Limitations" subsection:
```
## Agentless / remote scanning

Not supported. This scanner reads local filesystem files via stdlib
`os.Open` / `archive/zip.OpenReader`. Agentless binary scanning requires
an `io.ReaderAt`-capable FileReader adapter — planned as a follow-up.
```

- [ ] **Step 7: Commit**

```bash
git add pkg/scanner/asn1_oid.go pkg/scanner/java_bytecode.go pkg/scanner/*_test.go docs/scanners/
git commit -m "refactor(scanner): remove dead FileReaderAware adapters from binary scanners

asn1_oid and java_bytecode stored the injected FileReader but never used
it — they read via os.Open / zip.OpenReader, so agentless scans silently
produced zero findings. Remove SetFileReader from both until the readers
are genuinely plumbed through section extraction + ZIP decoding.

Agentless binary scanning remains a planned feature; documented in each
scanner's docs/scanners/<name>.md."
```

---

## Phase 4 — Final Verification

### Task 6: Full CI gate

- [ ] **Step 1: Build + unit tests + lint**

```bash
make build && make test && make lint
```
All green.

- [ ] **Step 2: Integration tests (scanner-specific)**

```bash
go test -tags integration -run 'TestASN1OID|TestJavaBytecode|TestHybridPQC|TestProtocol' ./test/integration/...
```
All pass.

- [ ] **Step 3: Verify module count didn't change**

```bash
go test -v -run TestRegisterDefaultModules ./pkg/scanner
```
Same count as pre-refactor.

- [ ] **Step 4: Update CLAUDE.md if anything shifted**

Architecture-notes section may want a line about the canonical algorithm registry + validator.

- [ ] **Step 5: Commit docs touch if any**

---

## Self-Review

**Spec coverage:** F2 (canonical + validator) → Tasks 1-2. F4 (catalog refactor) → Task 3. F7 (dead adapter removal) → Tasks 4-5. Final CI → Task 6.

**Placeholder scan:** Task 4 has a decision point (Option 1 vs Option 2) flagged as an ADR-style check-in; the recommendation defaults to Option 2.

**Type consistency:** `ValidateOIDRegistryAlgorithms`, `ValidateTLSGroupAlgorithms`, `ValidateJavaAlgorithmReferences`, `validateRegistriesConsistent`, `defaultModuleFactories` — consistent across tasks.

## Known open questions

- **`init()` ordering for the panic guard (Task 2).** Go runs init() in lexical filename order within a package. `canonical.go` runs before `oid_data_pqc.go` (alphabetical). If the format registries init AFTER canonical's init(), the validator runs before the registries are populated and always passes. Mitigation: move the panic guard to `zz_validate.go` to ensure it runs last. Verify at Task 2 Step 3.

- **Algorithm name aliases in pqc.go (Task 1 Step 5).** Some drift may require adding aliases to `algorithmRegistry`. Each alias is a design choice about the canonical name. If the number of aliases gets uncomfortable (>10), consider this a signal that the format registries should be fixed to use the canonical spelling (Option (b)) rather than pqc.go expanding.

- **Module count in Task 3 test.** Enumerate the actual module set from current main before writing the test expectation — don't trust the count I guessed.
