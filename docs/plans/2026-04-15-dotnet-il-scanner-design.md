# .NET IL Crypto Scanner — Design

> **Status:** approved scope; ready for implementation plan. Symmetric to PR #47 (Java bytecode).

## Why

Triton ships a Java bytecode crypto scanner (`pkg/scanner/java_bytecode.go`, PR #47) but no equivalent for .NET assemblies. .NET dominates Windows enterprise + government Malaysian deployments — the same population NACSA-2030 targets. Without IL coverage, Triton classifies a .NET service as "no findings" when it imports `RSACryptoServiceProvider` from inside compiled DLLs.

This PR adds depth parity for .NET: parse PE/CLI metadata directly (no `dotnet` SDK dependency), extract crypto type references and string literals, classify via a new registry mirroring the Java one.

## Scope

**In scope (PR #1):**

| Surface | How |
|---|---|
| BCL type references (`System.Security.Cryptography.*`) | `#~` TypeRef table walk |
| String literals (`"AES-256-CBC"`, CAPI/CNG names) | `#US` UserString heap walk |
| BouncyCastle.NET PQC types | TypeRef registry entries (no separate path) |
| CAPI/CNG identifiers | UserString registry entries |
| NuGet `.deps.json` reachability | `pkg/scanner/deps.go` extension (sibling work — *not in this PR*) |
| Classic multi-file publish (`.exe` + `.dll`) | direct PE parse |
| Single-file publish (.NET 5+) | locate bundle marker, parse manifest, recurse into bundled DLLs |

**Out of scope (deferred PRs):**
- `.nupkg` archive walker (symmetric to JAR scanner)
- NativeAOT pure-native binaries (no IL — already covered by `asn1_oid` + `binaries`)
- IL opcode walking (only metadata + strings; opcode-level call-graph reachability is a future abstraction-layer feature)
- ReadyToRun pre-compiled image variants (metadata still parses; R2R header is informational)
- Obfuscated/protected assemblies (best-effort string extraction only)

## Architecture

```
Filesystem walk
   ↓ (.exe / .dll, MZ magic check)
PE open  ←  reuse pkg/scanner/internal/binsections
   ↓
Locate CLI header (PE optional header data dir #14)
   ↓
Parse #~ tables (TypeRef, AssemblyRef) + #Strings + #US heaps
   ↓
[for single-file bundles: marker scan → manifest parse → io.SectionReader per inner DLL → recurse]
   ↓
Collect (typeRefs, userStrings)
   ↓
Classify against pkg/crypto/dotnet_algorithms.go registry (~80 entries)
   ↓
Emit one *Finding per unique (assembly, algorithm) pair
```

## Package Layout

```
pkg/scanner/dotnet_il.go               # Module entry: walk + dispatch + finding emit
pkg/scanner/internal/cli/              # Pure-Go ECMA-335 reader, no third-party deps
  pe_cli.go                            # locate CLI directory in PE (uses binsections)
  metadata.go                          # parse #~ tables (TypeRef, AssemblyRef, ModuleRef)
  heaps.go                             # parse #Strings + #US heaps with UTF-16 decode
  bundle.go                            # .NET 5+ single-file bundle manifest parser
  testdata/generate_test.go            # build-tag ignore: emit fixture .dll + bundle
pkg/crypto/dotnet_algorithms.go        # classification registry
```

**Boundary contract:** `cli.ReadAssembly(io.ReaderAt) (*Assembly, error)` returns plain `[]string` slices for type refs and user strings — zero crypto knowledge in `pkg/scanner/internal/cli/`. All classification lives in `dotnet_il.go` + `pkg/crypto/dotnet_algorithms.go`. Mirrors the Java boundary (`javaclass` returns constant-pool literals, classification happens upstairs).

## Crypto Registry — `pkg/crypto/dotnet_algorithms.go`

Map-based, `O(1)` lookup. Three logical layers (single map; layers documented in code comments):

1. **BCL types** — fully-qualified .NET cryptography type names. Examples: `System.Security.Cryptography.RSACryptoServiceProvider` → `(RSA, TRANSITIONAL)`, `AesManaged` → `(AES, SAFE)`, `MD5CryptoServiceProvider` → `(MD5, UNSAFE)`, `DSACryptoServiceProvider` → `(DSA, DEPRECATED)`. The `Cng` / `Managed` / `CryptoServiceProvider` suffixes are stripped before lookup so we have one entry per algorithm.

2. **CAPI/CNG string identifiers** — Windows cryptography provider constants from `wincrypt.h` and `bcrypt.h`. Examples: `BCRYPT_RSA_ALGORITHM`, `BCRYPT_KYBER_ALGORITHM` (Windows 11 24H2+), `szOID_RSA_RSA`, `CALG_MD5`, `CALG_3DES_112`. Found in the `#US` heap.

3. **BouncyCastle.NET PQC types** — `Org.BouncyCastle.Pqc.Crypto.MLKem.*`, `Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.*`, Falcon, SPHINCS+. Until BCL ships ML-KEM/ML-DSA in .NET 10 (preview), BC-NET is the only PQC route on .NET.

Total: ~80 entries. Fed into the existing `ClassifyAlgorithm()` chain; no new classification logic.

## Single-File Bundle Handling

.NET 5+ `dotnet publish --self-contained -p:PublishSingleFile=true` produces a host EXE with all DLLs concatenated at the end:

```
[PE host header + .text/.data/.rsrc sections]
[bundled DLL #1 raw bytes]
[bundled DLL #2 raw bytes (optionally gzip'd)]
...
[bundle manifest: list of (path, offset, size, compression_flag)]
[BundleHeader: version, file count, manifest offset]
[24-byte marker: ".NetCoreBundle" or SHA-256 prefix `8b17ff58`]
```

Algorithm:

1. `memmem` search for the marker in the last 64 KB of the host file.
2. Read `BundleHeader` immediately before the marker (8-byte offset → header start).
3. Walk manifest entries. For each `*.dll`:
   - `io.NewSectionReader(host, offset, size)`.
   - If compression flag set, wrap in `gzip.Reader`.
   - Pass to `cli.ReadAssembly()`.
4. Defensive caps: skip individual entries >32 MB; abort entire bundle if manifest claims >2000 entries (sanity cap).

Findings from bundled DLLs carry `Source.Evidence = "bundled in: <host.exe>"` for provenance.

## Engine Wiring

| Property | Value |
|---|---|
| Module name | `dotnet_il` |
| Category | `CategoryPassiveFile` |
| Target | `TargetFilesystem` |
| Profile | `comprehensive` only |
| Tier | Pro+ (free tier skips via existing license guard) |
| File matcher | extension `.exe` / `.dll`, then PE magic `0x5A4D`, then CLI header presence |
| Concurrency | engine-managed (semaphore + worker pool, same as `java_bytecode`) |
| External deps | none |

Registered in `defaultModuleFactories` (engine.go) alongside `asn1_oid` and `java_bytecode`. No `doctor.go` entries (no external tools).

## Tests

| Layer | File | What |
|---|---|---|
| Unit — heaps | `cli/heaps_test.go` | `#US` UTF-16 decoder; #Strings null-terminated reader |
| Unit — metadata | `cli/metadata_test.go` | hand-crafted `#~` blob → assert TypeRef + AssemblyRef extraction |
| Unit — bundle | `cli/bundle_test.go` | concatenate 2 tiny test DLLs + manifest → assert both extracted |
| Unit — registry | `crypto/dotnet_algorithms_test.go` | every registry entry classifies; no UNSAFE→SAFE regression |
| Module | `scanner/dotnet_il_test.go` | walk fixture dir with 3 DLLs (RSA / AES / MLKem) → assert findings + statuses |
| Integration | `test/integration/dotnet_il_test.go` | comprehensive scan over `testdata/` + tier gating (free tier → 0 findings) + bundle case |

**Fixture strategy:** `pkg/scanner/internal/cli/testdata/generate_test.go` (build-tag `ignore`, run via `go run`) emits 3 minimal valid .NET assemblies + 1 fake single-file bundle. Avoids needing the `dotnet` SDK in CI.

Coverage target: ≥ 80% for `pkg/scanner/internal/cli/`.

## Risks & Decisions

- **Bundle marker variations across .NET SDK versions** — .NET 5 used SHA-256 constant; .NET 6+ uses `.NetCoreBundle` ASCII string. Parser tries both, in order.
- **UTF-16 strings in `#US` heap** — heap entries are length-prefixed UTF-16; decoder must use `unicode/utf16` correctly. Easy bug; covered by explicit unit test.
- **Stripped/IL-trimmed assemblies** — `dotnet publish -p:PublishTrimmed=true` removes unreferenced types from metadata. Findings will reflect *actually-used* crypto, not all-imported — this is a feature for false-positive reduction.
- **Mixed-mode assemblies** (C++/CLI) — have both native code AND CLI metadata. Our scanner reads the metadata side; the native side is `binaries`/`asn1_oid`'s job. No conflict.

## Follow-up PRs

- `.nupkg` archive walker (sibling to JAR walker)
- NuGet reachability inside `pkg/scanner/deps.go` (extends Go-module reachability to `.deps.json`)
- IL opcode walking for abstraction-layer detection (e.g., distinguishing `Aes.Create()` vs hardcoded `new AesManaged()`)

## Estimated Effort

~1–1.5 days subagent-driven. ~8 tasks across 4 phases:

1. PE-CLI locator + metadata table reader + heaps reader (`pkg/scanner/internal/cli/`)
2. Bundle parser
3. Crypto registry + classification
4. Module wiring + integration tests + docs
