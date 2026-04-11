# Wave 0 + OCI Image Scanner — Design Spec

**Date:** 2026-04-12
**Parent roadmap:** `docs/plans/2026-04-11-scanner-gaps-roadmap.md` (Wave 0 + Wave 1 §5.1)
**Status:** Design approved, pending spec review before implementation plan.

> **For Claude:** After this spec is approved by the user, invoke `superpowers:writing-plans` to produce the step-by-step implementation plan. Do NOT invoke any other skill.

---

## 1. Goal

Land the cross-cutting infrastructure every new scanner in Waves 1–4 will depend on (new `ScanTargetType` values, global scanner credentials, CLI flag surface, licence tier wiring, engine dispatch adjustments) **bundled with the OCI image scanner as its first real consumer**. The infrastructure is validated against a live use case instead of shipping abstractions that have no concrete caller.

**Success looks like:** `triton --image nginx:1.25 --profile standard` pulls the image, extracts it to a sandboxed tmpfs, runs the existing `certificates`/`keys`/`library`/`binary`/`deps`/`configs`/`webapp`/`package`/`certstore`/`deps_ecosystems` modules against the extracted rootfs, emits findings annotated with `ImageRef` + `ImageDigest`, and routes those findings through the existing policy engine (NACSA-2030, CNSA-2.0) and CycloneDX CBOM output without schema breakage.

---

## 2. Scope

### In scope

- Two new `ScanTargetType` enum values: `TargetOCIImage`, `TargetKubernetesCluster`
- New `pkg/scanner/credentials.go` with a minimal `ScanCredentials` struct (Wave 1 fields only, strict YAGNI)
- New field `Credentials ScanCredentials` on `scannerconfig.Config`
- Four new CLI flags on root command: `--image` (repeatable), `--kubeconfig`, `--k8s-context`, `--registry-auth`
- Filesystem-default suppression rule: setting `--image` or `--kubeconfig` drops the profile's default filesystem targets
- Mixing-mode error: cannot combine image/k8s targets with filesystem targets in one run
- Licence tier allowlist additions: `oci_image` → Pro+Enterprise, `k8s_live` → Enterprise only (stub, actual module lands Sprint 1b)
- `cmd.Guard.FilterConfig()` drops blocked target types with a visible warning (not silent)
- Server-mode enforcement: refuse to start image/k8s scanners if credentials flag/env not explicit (no ambient SDK default chain fallback in server mode)
- New scanner module `pkg/scanner/oci_image.go` implementing `Module` interface
- `imageFetcher` interface with `remoteFetcher` real impl (uses `github.com/google/go-containerregistry`) and `fakeFetcher` for unit tests
- New optional `ImageRef` + `ImageDigest` fields on `CryptoAsset` (omit-empty)
- Schema v10 migration: add nullable `image_ref TEXT` + `image_digest TEXT` columns to the `findings` read-model table (no backfill required)
- Per-scan tmpfs sandbox with 4 GB uncompressed cap, 128 layer cap, symlink traversal protection
- Multi-arch manifest handling: deterministic first-match `linux/amd64`
- Curated delegation list: which existing modules run inside an image scan
- `doctor` command extension: reports OCI scanning availability + credential resolution dry-run
- Unit tests with fake fetcher + committed rootfs fixture (~50 KB)
- Integration test against pinned public image digest (Chainguard static, ~1 MB)
- Licence tier × target-type test matrix
- Documentation updates: `MEMORY.md` completion marker, `docs/SYSTEM_ARCHITECTURE.md` paragraph, `README.md` `--image` usage example

### Out of scope (explicit)

- **Live Kubernetes scanner** — Sprint 1b, separate PR
- **Multi-arch manifest fan-out** — v1 picks first `linux/amd64` match; multi-arch is a v2 feature
- **Image diff** — comparing two image digests for crypto drift, future work
- **SBOM ingestion** — reading pre-existing SBOM files at `/usr/share/doc/**/sbom.json` inside images, future work
- **Registry signature verification** — cosign/notary chain verification against remote images, tracked under Wave 1 `container_signatures.go` extension
- **Docker daemon socket scanning** — `docker-daemon:<id>` refs add non-trivial daemon auth surface, deferred
- **Cloud credential helper testing** — ECR/GCR/ACR auth paths work by delegating to `authn.DefaultKeychain` but are not unit-tested (no CI cloud credentials); integration test uses public Chainguard image only
- **Jadual 1/2 CSV column mapping** — deferred until real findings available for user review (per parent roadmap §4.4)
- **Subprocess isolation** — delegated modules run in-process against the extracted rootfs, not in a separate process or container
- **Wave 0 prerequisites beyond what OCI image scanner needs** — Vault/AWS/Azure credential fields land in their own Wave 3 sprints

---

## 3. Architecture

### 3.1 New `ScanTargetType` values

`pkg/model/types.go`:

```go
const (
    TargetFilesystem ScanTargetType = iota
    TargetNetwork
    TargetProcess
    TargetDatabase
    TargetHSM
    TargetLDAP
    TargetOCIImage          // NEW — Value = image ref, Depth unused
    TargetKubernetesCluster // NEW — Value = kubeconfig path, Depth unused
)
```

Additive. Existing zero-value (`TargetFilesystem`) and ordering preserved, so no migration of persisted scan data.

### 3.2 `ScanCredentials` struct

New file `pkg/scanner/credentials.go`:

```go
package scanner

// ScanCredentials holds optional auth for target types that need it.
// Every secret field is tagged json:"-" and redacted by String().
type ScanCredentials struct {
    // OCI image registry
    RegistryAuthFile string `json:"-"` // path to docker config.json override
    RegistryUsername string `json:"-"` // explicit override
    RegistryPassword string `json:"-"` // explicit override (redacted)

    // Kubernetes (Sprint 1b consumer, infra lands now)
    Kubeconfig string `json:"-"` // kubeconfig path override ("" = default chain)
    K8sContext string `json:"-"` // context name override
}

// String returns a representation safe to log — all secret fields redacted.
func (c ScanCredentials) String() string {
    return fmt.Sprintf(
        "ScanCredentials{RegistryAuthFile=%q, RegistryUsername=%q, "+
            "RegistryPassword=%s, Kubeconfig=%q, K8sContext=%q}",
        c.RegistryAuthFile, c.RegistryUsername,
        redact(c.RegistryPassword), c.Kubeconfig, c.K8sContext,
    )
}
```

`redact()` returns `"REDACTED"` if non-empty, `""` otherwise.

New field on `scannerconfig.Config`:

```go
type Config struct {
    // ...existing fields...
    Credentials ScanCredentials
}
```

### 3.3 CLI flag surface

`cmd/root.go` gains four persistent flags:

| Flag | Type | Description |
|------|------|-------------|
| `--image` | StringSlice | Repeatable image ref, e.g. `--image nginx:1.25 --image redis:7` |
| `--kubeconfig` | String | Kubeconfig path override (Sprint 1b consumer; flag parsed now) |
| `--k8s-context` | String | Kubeconfig context name (Sprint 1b consumer) |
| `--registry-auth` | String | Path to docker config.json override |

### 3.4 Filesystem suppression rule

In `internal/scannerconfig/config.go`, when `BuildConfig()` runs:

```
if len(cfg.Credentials.Kubeconfig) > 0 || len(imageRefs) > 0 {
    // Image or k8s mode — do NOT append profile default filesystem targets.
    // Only append explicit image/k8s targets.
}
```

**Mixing-mode error:** if both `--image` (or `--kubeconfig`) AND explicit filesystem paths are supplied in the same invocation (when the filesystem-target config system lands, currently profile-defaulted), return a clear error from `BuildConfig()`:

```
cannot mix --image or --kubeconfig with filesystem targets in a single scan;
run triton separately for each target type
```

Since today's CLI doesn't accept positional filesystem paths, this rule is primarily enforced against the default-target-injection path: setting `--image` disables the defaults; no collision possible unless a future flag adds user-specified filesystem targets. The check lives in `BuildConfig()` so it's ready when that flag arrives.

### 3.5 Engine dispatch adjustment

`pkg/scanner/engine.go`'s `getTargetsForModule()` already filters by `ScanTargetType()` — no change required. The only edit is in the filesystem walker initialization path: when zero `TargetFilesystem` entries exist in `ScanTargets`, the walker must skip setup gracefully instead of assuming at least one. Today it likely works by accident; Sprint 0 adds an explicit guard and a test case (`TestEngine_NoFilesystemTargets`).

### 3.6 Licence tier wiring

`internal/license/guard.go`:

```go
var tierModuleWhitelist = map[Tier]map[string]bool{
    TierFree: { /* unchanged, 3 modules */ },
    TierPro: { /* existing + */ "oci_image": true },
    TierEnterprise: { /* existing + */ "oci_image": true, "k8s_live": true },
}
```

`FilterConfig()` behaviour change: when a `ScanTarget` of type `TargetOCIImage` or `TargetKubernetesCluster` is present but the corresponding module is not in the allowed set, drop that target **and** emit a warning via the existing guard-warning path (not silent). Currently `FilterConfig` only restricts `Modules`; this extends it to restrict `ScanTargets` by type.

### 3.7 CLI vs server credential resolution

**CLI mode** (`triton --image ...`): if `--registry-auth` not set, fall back to `authn.DefaultKeychain` (docker config, env, cloud helpers). Ergonomic default for security engineers on their laptops.

**Server mode** (`triton server`): explicit credentials required. Any scan request that arrives at the API with image/k8s targets but no explicit credentials in the request body is rejected with HTTP 400. No ambient SDK default chain fallback in server mode — a daemon should never silently pick up whatever creds happen to live in its environment.

This distinction is enforced in a new helper `resolveCredentials(ctx, cfg, mode)` where `mode` is `CLI` or `Server`. Server-mode scan handlers pass `Server`; CLI root command passes `CLI`.

---

## 4. OCI image scanner design

### 4.1 Module interface

`pkg/scanner/oci_image.go`:

```go
type OCIImageModule struct {
    config      *scannerconfig.Config
    fetcher     imageFetcher
    store       store.Store
    lastScanned int64
    lastMatched int64
}

func NewOCIImageModule(cfg *scannerconfig.Config) *OCIImageModule {
    return &OCIImageModule{config: cfg, fetcher: newRemoteFetcher()}
}

func (m *OCIImageModule) Name() string                         { return "oci_image" }
func (m *OCIImageModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *OCIImageModule) ScanTargetType() model.ScanTargetType { return model.TargetOCIImage }
func (m *OCIImageModule) SetStore(s store.Store)               { m.store = s }
func (m *OCIImageModule) FileStats() (scanned, matched int64)  { /* atomic loads */ }
```

### 4.2 Fetcher abstraction

```go
type imageFetcher interface {
    Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error)
}

type fetchedImage struct {
    RootFS    string  // extracted rootfs path on local disk
    Ref       string  // canonical ref
    Digest    string  // sha256:...
    LayerN    int     // layer count
    SizeBytes int64   // total uncompressed size
    Cleanup   func() error
}
```

Two implementations:

- **`remoteFetcher`** (production) — uses `github.com/google/go-containerregistry/pkg/v1/remote` for manifest pull, `pkg/v1/mutate` for flattening, custom extractor that enforces the 4 GB / 128 layer caps and does symlink-safe extraction. Credentials resolved via explicit username/password > `RegistryAuthFile` > `authn.DefaultKeychain` (CLI mode only).

- **`fakeFetcher`** (test-only) — constructed with a pre-baked rootfs path. `Fetch()` returns the path immediately with a no-op `Cleanup`. Lives in `oci_image_test.go`, not compiled into production binary.

### 4.3 Scan flow

`Scan(ctx, target, findings)` pseudocode:

```
1. Parse target.Value as image ref. If invalid → emit error finding, return nil.
2. img, err := m.fetcher.Fetch(ctx, target.Value, m.config.Credentials)
   On error → emit error finding with image ref annotation, return nil (never fail the scan).
3. defer img.Cleanup()
4. Build a synthetic sub-config:
     subCfg := *m.config          // copy
     subCfg.ScanTargets = []model.ScanTarget{{
         Type: model.TargetFilesystem, Value: img.RootFS, Depth: -1,
     }}
     subCfg.Profile = "image-scan" // internal marker
5. For each delegated module in the curated allowlist:
     - Construct the module with subCfg
     - Run module.Scan(ctx, syntheticTarget, wrappedFindings)
     - wrappedFindings is a goroutine that reads the inner channel, annotates each
       finding with ImageRef + ImageDigest, and forwards to the outer findings channel
6. Report aggregated metrics via FileStats().
```

### 4.4 Delegated module allowlist

Modules that make sense inside an image:

```
certificates, keys, certstore, library, binaries, deps, deps_ecosystems,
configs, webapp, package
```

Modules **not** run (no meaning inside a static rootfs):

```
protocol, network, processes, hsm, ldap, database, service_mesh,
container_signatures (the image is the thing being scanned, not signed locally),
kernel (images rarely contain loaded kernel modules), codesign variants,
auth_material (keytabs etc. rarely in images), xml_dsig, vpn_config,
password_hash, mail_server, web_server, containers (meta — don't re-scan)
```

The exclusion list is encoded in `oci_image.go` as a constant map for clarity, with a comment per exclusion.

User can override with `--modules` flag — if they pass `--modules scripts` and it's not in the allowlist, scripts still run (user override respected). The allowlist only affects the **default** delegation set.

### 4.5 Finding annotation

New optional fields on `CryptoAsset` in `pkg/model/types.go`:

```go
ImageRef    string `json:"imageRef,omitempty"`
ImageDigest string `json:"imageDigest,omitempty"`
```

Populated by the wrapper goroutine in step 5 above. Omit-empty → existing filesystem-scan reports unchanged. CycloneDX exporter learns to emit these as component properties under the `triton:container` namespace.

### 4.6 Sandbox safety

- Sandbox root: `os.TempDir()/triton-oci-<digest-short-12>/` — mode 0700
- Hard caps: 4 GB total uncompressed, 128 layers, 1 MB single-file name length
- Symlink handling: layers are extracted with `securejoin.SecureJoin()` or equivalent; any path that resolves outside the sandbox root is skipped with a warning finding
- Whiteout handling: OCI whiteout files (`.wh.*`) applied correctly during multi-layer extraction
- Cleanup: `defer img.Cleanup()` always runs; on `ctx.Done()` the cleanup goroutine receives the cancel signal and removes the tmpfs root before returning

### 4.7 Multi-arch manifest handling

For v1: when pulling a manifest list (OCI index), pick the first entry matching `linux/amd64`. If none exists, fall back to the first entry and emit an info finding noting which platform was scanned. Explicit TODO comment referencing the roadmap for multi-arch fan-out.

---

## 5. Testing strategy

### 5.1 Unit tests — `oci_image_test.go`

Fixture: `test/fixtures/oci/minimal-rootfs/` (~50 KB, committed to repo):

```
etc/ssl/certs/test-ca.pem   # self-signed RSA-2048 cert
usr/lib/libssl.so.3         # empty file (library module matches on name)
usr/bin/curl                # empty file (binary module matches on name)
```

Test cases:

- `TestOCIImage_HappyPath` — fake fetcher returns minimal rootfs → expect ≥3 findings, all annotated with `ImageRef` + `ImageDigest`
- `TestOCIImage_FetcherError` — fetcher returns error → one error finding emitted, scan continues gracefully
- `TestOCIImage_ContextCancel` — cancel mid-scan → cleanup runs, tmpfs removed, no goroutine leak
- `TestOCIImage_SymlinkEscape` — fixture contains symlink pointing to `/etc/passwd` → symlink not followed, warning finding emitted
- `TestOCIImage_SizeCap` — fake fetcher reports 5 GB size → scan aborts with size-cap finding
- `TestOCIImage_LayerCap` — fake fetcher reports 200 layers → scan aborts with layer-cap finding
- `TestOCIImage_Redaction` — `RegistryPassword` set in credentials → never appears in any emitted finding, log output, or JSON marshal
- `TestOCIImage_ModuleAllowlist` — default delegation only runs allowlisted modules
- `TestOCIImage_ModuleOverride` — `--modules` flag honors user override

### 5.2 Integration test — `test/integration/oci_image_test.go`

Build tag `//go:build integration`. Pins a public Chainguard static image by digest:

```go
const testImageRef = "cgr.dev/chainguard/static:latest"
const testImageDigest = "sha256:<pinned>" // locked during implementation
```

- `TestIntegration_OCIImage_RealPull` — pulls `testImageRef`, verifies digest matches `testImageDigest`, expects ≥1 certificate finding (Chainguard static ships CA bundle), verifies `ImageRef` + `ImageDigest` populated, verifies tmpfs cleanup post-scan
- `TestIntegration_OCIImage_InvalidRef` — pulls `does.not.exist/nothing:nothing` → error finding emitted, scan doesn't panic
- `TestIntegration_OCIImage_PolicyRoute` — findings from real pull route through NACSA-2030 policy evaluation without error

Timeout: 30 s per test. Run in CI with network access (already required by existing integration tests).

### 5.3 Licence tier tests — `internal/license/guard_test.go`

Matrix:

| Tier | `--image` flag | Expected |
|------|---------------|----------|
| Free | set | Target dropped, warning logged, scan proceeds with filesystem defaults |
| Pro | set | Target passes through, scan runs |
| Enterprise | set | Target passes through, scan runs |
| Free | `--kubeconfig` set | Target dropped, warning logged |
| Pro | `--kubeconfig` set | Target dropped (k8s is Enterprise-only), warning logged |
| Enterprise | `--kubeconfig` set | Target passes through (stub — module lands Sprint 1b) |

### 5.4 `BuildConfig` / CLI tests

- `TestBuildConfig_ImageSuppressesFSDefaults` — setting `--image nginx` → `ScanTargets` contains only the image target, no filesystem defaults
- `TestBuildConfig_MultipleImages` — `--image a --image b` → two `TargetOCIImage` entries
- `TestBuildConfig_ImageAndKubeconfigError` — setting both → error
- `TestEngine_NoFilesystemTargets` — engine handles zero-filesystem-target config without panic

### 5.5 Coverage targets

- `oci_image.go`: ≥85% line coverage
- `credentials.go`: 100% (trivial struct + redaction)
- New CLI flag paths in `cmd/root.go`: ≥80%
- New tier allowlist branches in `guard.go`: 100%

### 5.6 `doctor` command extension

`pkg/scanner/doctor.go` gains:

```
OCI image scanning:
  go-containerregistry:  available (vX.Y.Z, imported library)
  docker config:         found at ~/.docker/config.json
  default keychain:      resolvable (dry-run succeeded)
  status:                READY
```

Purely informational. Never blocks the scan.

---

## 6. Dependencies

### 6.1 New Go module

```
github.com/google/go-containerregistry
```

Pure Go, zero CGO, Apache 2.0 license. Used by Kaniko, Buildpacks, crane, Flux — mature and trusted. Adds ~40 transitive dependencies, all already common in the Go ecosystem.

### 6.2 Existing modules exercised

No version bumps required. The OCI scanner delegates to existing module constructors with a synthetic `scannerconfig.Config` and reuses their scanner logic unchanged.

---

## 7. Migration / compatibility

- **Persisted scan data:** additive `ScanTargetType` enum values don't affect existing rows. `CryptoAsset` gains two optional fields with `omitempty` JSON — old rows deserialize cleanly.
- **API contract:** new `ImageRef` / `ImageDigest` fields appear in `/api/v1/scans/{id}` responses only when present; clients ignoring unknown fields (standard practice) unaffected.
- **CLI contract:** no existing flag changes behaviour. New flags are opt-in. Default scans continue to scan the filesystem as before.
- **Profile behaviour:** existing `quick`/`standard`/`comprehensive` profiles unchanged. `--image` triggers a runtime filtering of the active module list to the delegated allowlist; this happens at `BuildConfig` time, not at profile definition time.
- **Database schema:** no migration required. Findings already persist via the existing `findings` projection; the new `ImageRef`/`ImageDigest` columns are added to the `findings` read-model table as nullable text (schema v10).

Schema v10 migration: two nullable columns on `findings` (`image_ref TEXT`, `image_digest TEXT`). Backfill unnecessary — existing rows remain NULL and analytics views don't reference these columns yet.

---

## 8. Observability

- Prometheus metric: `triton_oci_image_pulls_total{status="success|failure"}` (counter)
- Prometheus metric: `triton_oci_image_pull_duration_seconds` (histogram)
- Prometheus metric: `triton_oci_image_extracted_bytes` (gauge, last value)
- Log line at info level per pull: `"oci pull: ref=<canonical> digest=<sha256> layers=<n> size=<bytes> duration=<ms>"`
- Log line at warn level per cap violation or symlink escape

---

## 9. Documentation updates

- **`MEMORY.md`** — add "v2.8 Wave 0 + OCI Image Scanner (completed YYYY-MM-DD)" section with key files, decisions, caveats
- **`scanner-coverage-gaps.md`** — mark Wave 1 §5.1 ✅
- **`docs/SYSTEM_ARCHITECTURE.md`** — new subsection under §10 "Scanner modules" describing OCI image scan flow and credential resolution model
- **`README.md`** — new "Scanning container images" subsection under Usage, with `triton --image nginx:1.25` example and licence tier note
- **`docs/DEPLOYMENT_GUIDE.md`** — server-mode credential plumbing requirement (no ambient fallback) added to §5

---

## 10. Open questions (resolve during implementation, not blockers)

1. **Test fixture certs** — generate the self-signed RSA-2048 cert with `openssl` as a one-shot script in `test/fixtures/oci/Makefile`? Or commit a frozen `.pem`? Recommend frozen — no build-time crypto generation.
2. **Pinned Chainguard digest** — lock at implementation time. Document the pin update cadence (yearly during release).
3. **Sandbox root location** — `os.TempDir()` may be small on some systems. Expose via env var `TRITON_OCI_SANDBOX_ROOT` for operators? Defer unless integration tests hit disk-full.
4. **`redact()` helper location** — add to `pkg/scanner/credentials.go` or a shared `internal/redact` package? Put in `credentials.go` for now, promote if a second caller appears.

---

## 11. Success criteria

- All unit tests pass (`make test`)
- All integration tests pass (`make test-integration`) including real Chainguard pull
- `make lint` clean
- Coverage targets met per §5.5
- Manual smoke: `triton --image nginx:1.25 --profile standard --format json` produces a report with ≥5 findings, each annotated with `ImageRef` + `ImageDigest`
- Licence tier matrix verified
- Code review signed off per project workflow
- `MEMORY.md` updated
- `scanner-coverage-gaps.md` wave marker updated
- PR merged to main via GitHub Actions CI green

---

## 12. Estimated effort

~2 weeks of focused work (one sprint per project cadence). Breakdown:

- Days 1–2: Wave 0 infrastructure (ScanTargetType, ScanCredentials, CLI flags, guard wiring) — all TDD
- Days 3–6: `oci_image.go` module with fake fetcher, unit tests
- Days 7–8: `remoteFetcher` real implementation, integration test with Chainguard
- Days 9–10: Licence tier matrix, doctor extension, docs, code review fixes
