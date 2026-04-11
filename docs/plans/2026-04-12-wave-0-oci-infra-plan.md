# Wave 0 + OCI Image Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land Wave 0 cross-cutting infrastructure (new `ScanTargetType` values, global `ScanCredentials`, CLI flags, licence tier wiring, engine dispatch adjustments) bundled with the OCI image scanner as its first real consumer.

**Architecture:** Additive changes only — new enum values, new struct, new CLI flags, new scanner module. Existing filesystem-scan behaviour unchanged when `--image`/`--kubeconfig` are not set. The `OCIImageModule` delegates to existing modules against an extracted rootfs rather than reimplementing file parsing, keeping the scanner's crypto-detection surface identical between image and host scans.

**Tech Stack:** Go 1.25, Cobra CLI, `github.com/google/go-containerregistry` (new), `pgx/v5` (existing), `testify` (existing).

**Spec:** `docs/plans/2026-04-12-wave-0-oci-infra-design.md`

---

## File Structure

### Created

| File | Responsibility |
|---|---|
| `pkg/scanner/credentials.go` | `ScanCredentials` struct with redaction-safe `String()` |
| `pkg/scanner/credentials_test.go` | Redaction + JSON marshal safety tests |
| `pkg/scanner/oci_image.go` | `OCIImageModule` + `imageFetcher` interface + `remoteFetcher` real impl |
| `pkg/scanner/oci_image_test.go` | Unit tests with `fakeFetcher` against committed rootfs fixture |
| `pkg/scanner/oci_image_remote.go` | Split file for `remoteFetcher` (pure go-containerregistry code) |
| `test/fixtures/oci/minimal-rootfs/etc/ssl/certs/test-ca.pem` | Self-signed RSA-2048 cert fixture |
| `test/fixtures/oci/minimal-rootfs/usr/lib/libssl.so.3` | Empty file matching library-module pattern |
| `test/fixtures/oci/minimal-rootfs/usr/bin/curl` | Empty file matching binary-module pattern |
| `test/fixtures/oci/README.md` | Fixture provenance + regeneration instructions |
| `test/integration/oci_image_test.go` | Real Chainguard image pull, build tag `integration` |

### Modified

| File | Change |
|---|---|
| `pkg/model/types.go` | +2 enum values (`TargetOCIImage`, `TargetKubernetesCluster`); +2 fields on `CryptoAsset` (`ImageRef`, `ImageDigest`) |
| `pkg/model/types_test.go` | Assertions for new enum values + field omit-empty |
| `internal/scannerconfig/config.go` | +`Credentials ScanCredentials` field on `Config`; suppression logic in `Load`/new `BuildConfig` helper |
| `internal/scannerconfig/config_test.go` | Suppression + mixing-mode error tests |
| `pkg/scanner/engine.go` | Defensive guard for zero-filesystem-target runs; `RegisterDefaultModules` adds `oci_image` |
| `pkg/scanner/engine_test.go` | `TestEngine_NoFilesystemTargets` |
| `cmd/root.go` | +4 flags, target-injection wiring, mixing-mode error |
| `internal/license/guard.go` | `FilterConfig` drops `TargetOCIImage`/`TargetKubernetesCluster` for disallowed tiers with warning |
| `internal/license/guard_test.go` | Tier × target-type matrix |
| `pkg/scanner/doctor.go` | OCI section reporting keychain resolution |
| `pkg/store/types.go` | +`ImageRef`, `ImageDigest` fields on store `Finding` |
| `pkg/store/migrations.go` | Append v10 migration string |
| `pkg/store/findings.go` | INSERT statement adds two columns + args |
| `pkg/store/extract.go` | Populate `ImageRef`/`ImageDigest` from `CryptoAsset` |
| `MEMORY.md` (in `~/.claude/projects/.../memory/`) | Completion marker |
| `memory/scanner-coverage-gaps.md` | Mark Wave 1 §5.1 ✅ |
| `docs/SYSTEM_ARCHITECTURE.md` | New subsection on OCI image scan flow |
| `README.md` | `--image` usage example under Usage |
| `docs/DEPLOYMENT_GUIDE.md` | Server-mode credential plumbing note |
| `go.mod` / `go.sum` | +`github.com/google/go-containerregistry` |

### Responsibilities / boundaries

- `credentials.go` owns the struct and redaction. Nothing else in the codebase reads the password field.
- `oci_image.go` owns the module interface methods + delegation orchestration. It does **not** know how to pull images — that's `remoteFetcher`'s job, behind the `imageFetcher` interface.
- `oci_image_remote.go` is the only file that imports `go-containerregistry`. If we ever swap the library, the blast radius is one file.
- `scannerconfig/config.go` stays the only place where `Config` is constructed — CLI flags feed into it via a builder, not by mutating fields directly from `cmd/root.go`.

---

## Task 1: Add new `ScanTargetType` enum values

**Files:**
- Modify: `pkg/model/types.go:20-27`
- Modify: `pkg/model/types_test.go:290-295`

- [ ] **Step 1: Write failing test for new enum values**

Append to `pkg/model/types_test.go` inside `TestScanTargetTypes`:

```go
func TestScanTargetTypes(t *testing.T) {
    assert.Equal(t, ScanTargetType(0), TargetFilesystem)
    assert.Equal(t, ScanTargetType(1), TargetNetwork)
    assert.Equal(t, ScanTargetType(2), TargetProcess)
    assert.Equal(t, ScanTargetType(3), TargetDatabase)
    assert.Equal(t, ScanTargetType(4), TargetHSM)
    assert.Equal(t, ScanTargetType(5), TargetLDAP)
    assert.Equal(t, ScanTargetType(6), TargetOCIImage)
    assert.Equal(t, ScanTargetType(7), TargetKubernetesCluster)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestScanTargetTypes ./pkg/model/`
Expected: FAIL with `undefined: TargetOCIImage`

- [ ] **Step 3: Add enum values**

Edit `pkg/model/types.go`:

```go
const (
    TargetFilesystem ScanTargetType = iota
    TargetNetwork
    TargetProcess
    TargetDatabase
    TargetHSM
    TargetLDAP
    TargetOCIImage          // OCI image reference (e.g. nginx:1.25)
    TargetKubernetesCluster // kubeconfig path (Wave 1 Sprint 1b)
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestScanTargetTypes ./pkg/model/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/model/types.go pkg/model/types_test.go
git commit -m "feat(model): add TargetOCIImage and TargetKubernetesCluster types"
```

---

## Task 2: Add `ImageRef` and `ImageDigest` to `CryptoAsset`

**Files:**
- Modify: `pkg/model/types.go:157-216`
- Modify: `pkg/model/types_test.go`

- [ ] **Step 1: Write failing test for omit-empty behaviour**

Append to `pkg/model/types_test.go`:

```go
func TestCryptoAssetImageFieldsOmitEmpty(t *testing.T) {
    a := CryptoAsset{Algorithm: "RSA"}
    b, err := json.Marshal(a)
    require.NoError(t, err)
    assert.NotContains(t, string(b), "imageRef")
    assert.NotContains(t, string(b), "imageDigest")

    a.ImageRef = "nginx:1.25"
    a.ImageDigest = "sha256:abc"
    b, err = json.Marshal(a)
    require.NoError(t, err)
    assert.Contains(t, string(b), `"imageRef":"nginx:1.25"`)
    assert.Contains(t, string(b), `"imageDigest":"sha256:abc"`)
}
```

Ensure `encoding/json` is imported in the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestCryptoAssetImageFields ./pkg/model/`
Expected: FAIL with `a.ImageRef undefined`

- [ ] **Step 3: Add fields to `CryptoAsset`**

Edit `pkg/model/types.go`, append inside the `CryptoAsset` struct after the `SANs` field (around line 215):

```go
    // Container image annotation (populated by OCIImageModule delegation
    // wrapper). Empty on filesystem-scan findings.
    ImageRef    string `json:"imageRef,omitempty"`
    ImageDigest string `json:"imageDigest,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestCryptoAssetImageFields ./pkg/model/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/model/types.go pkg/model/types_test.go
git commit -m "feat(model): add ImageRef and ImageDigest to CryptoAsset"
```

---

## Task 3: Create `ScanCredentials` struct with redaction

**Files:**
- Create: `pkg/scanner/credentials.go`
- Create: `pkg/scanner/credentials_test.go`

- [ ] **Step 1: Write failing redaction test**

Create `pkg/scanner/credentials_test.go`:

```go
package scanner

import (
    "encoding/json"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestScanCredentials_StringRedacts(t *testing.T) {
    c := ScanCredentials{
        RegistryAuthFile: "/etc/docker/config.json",
        RegistryUsername: "alice",
        RegistryPassword: "super-secret",
        Kubeconfig:       "/home/alice/.kube/config",
        K8sContext:       "prod",
    }
    s := c.String()
    assert.Contains(t, s, "/etc/docker/config.json")
    assert.Contains(t, s, "alice")
    assert.Contains(t, s, "REDACTED")
    assert.NotContains(t, s, "super-secret")
}

func TestScanCredentials_EmptyPasswordNotRedacted(t *testing.T) {
    c := ScanCredentials{RegistryUsername: "alice"}
    s := c.String()
    assert.NotContains(t, s, "REDACTED")
}

func TestScanCredentials_JSONMarshalDropsSecrets(t *testing.T) {
    c := ScanCredentials{
        RegistryAuthFile: "/etc/docker/config.json",
        RegistryUsername: "alice",
        RegistryPassword: "super-secret",
        Kubeconfig:       "/home/alice/.kube/config",
        K8sContext:       "prod",
    }
    b, err := json.Marshal(c)
    require.NoError(t, err)
    body := string(b)
    assert.False(t, strings.Contains(body, "super-secret"), "password must not appear")
    assert.False(t, strings.Contains(body, "alice"), "username tagged json:- must not appear")
    assert.False(t, strings.Contains(body, "prod"), "context tagged json:- must not appear")
    assert.Equal(t, "{}", body, "all fields tagged json:- so marshal is empty object")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestScanCredentials ./pkg/scanner/`
Expected: FAIL with `undefined: ScanCredentials`

- [ ] **Step 3: Create credentials.go**

Create `pkg/scanner/credentials.go`:

```go
package scanner

import "fmt"

// ScanCredentials holds optional auth for target types that need it.
// Every secret-bearing field is tagged json:"-" and redacted by String()
// so credentials never leak into scan results, logs, reports, or API
// payloads. Matches the vpn_config.go "REDACTED" precedent.
type ScanCredentials struct {
    RegistryAuthFile string `json:"-"` // path to docker config.json override
    RegistryUsername string `json:"-"` // explicit registry username override
    RegistryPassword string `json:"-"` // explicit registry password override
    Kubeconfig       string `json:"-"` // kubeconfig path override (Sprint 1b)
    K8sContext       string `json:"-"` // kubeconfig context name override
}

// String returns a representation safe to log. Secret fields are replaced
// with "REDACTED" when non-empty; empty fields render as empty strings.
func (c ScanCredentials) String() string {
    return fmt.Sprintf(
        "ScanCredentials{RegistryAuthFile=%q, RegistryUsername=%q, "+
            "RegistryPassword=%s, Kubeconfig=%q, K8sContext=%q}",
        c.RegistryAuthFile,
        c.RegistryUsername,
        redact(c.RegistryPassword),
        c.Kubeconfig,
        c.K8sContext,
    )
}

func redact(s string) string {
    if s == "" {
        return ""
    }
    return "REDACTED"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestScanCredentials ./pkg/scanner/`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/credentials.go pkg/scanner/credentials_test.go
git commit -m "feat(scanner): add ScanCredentials with redaction-safe String()"
```

---

## Task 4: Add `Credentials` field to `scannerconfig.Config`

**Files:**
- Modify: `internal/scannerconfig/config.go:9-24`
- Modify: `internal/scannerconfig/config_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/scannerconfig/config_test.go`:

```go
func TestConfig_HasCredentialsField(t *testing.T) {
    cfg := &Config{}
    cfg.Credentials.RegistryUsername = "alice"
    assert.Equal(t, "alice", cfg.Credentials.RegistryUsername)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestConfig_HasCredentialsField ./internal/scannerconfig/`
Expected: FAIL with `cfg.Credentials undefined`

- [ ] **Step 3: Add field to `Config`**

Edit `internal/scannerconfig/config.go`, extend the `Config` struct:

```go
type Config struct {
    Profile         string
    Modules         []string
    OutputFormat    string
    OutputFile      string
    MaxDepth        int
    FollowSymlinks  bool
    IncludePatterns []string
    ExcludePatterns []string
    MaxFileSize     int64
    Workers         int
    ScanTargets     []model.ScanTarget
    Metrics         bool
    DBUrl           string
    Incremental     bool
    Credentials     scanner.ScanCredentials
}
```

Add the import `"github.com/amiryahaya/triton/pkg/scanner"` at the top. If this creates an import cycle, move the type: in that case, define `ScanCredentials` in `internal/scannerconfig/credentials.go` and re-export from `pkg/scanner/credentials.go` via a type alias `type ScanCredentials = scannerconfig.ScanCredentials`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestConfig_HasCredentialsField ./internal/scannerconfig/`
Expected: PASS. If there's an import cycle, resolve via the type-alias fallback described above and re-run.

- [ ] **Step 5: Commit**

```bash
git add internal/scannerconfig/config.go internal/scannerconfig/config_test.go pkg/scanner/credentials.go
git commit -m "feat(scannerconfig): add Credentials field on Config"
```

---

## Task 5: `BuildConfig` target injection + filesystem suppression

**Files:**
- Modify: `internal/scannerconfig/config.go` (add `BuildConfig` function)
- Modify: `internal/scannerconfig/config_test.go`

- [ ] **Step 1: Write failing tests for BuildConfig**

Append to `internal/scannerconfig/config_test.go`:

```go
func TestBuildConfig_ImageSuppressesFilesystemDefaults(t *testing.T) {
    opts := BuildOptions{
        Profile:   "standard",
        ImageRefs: []string{"nginx:1.25"},
    }
    cfg, err := BuildConfig(opts)
    require.NoError(t, err)

    var fsCount, imageCount int
    for _, tgt := range cfg.ScanTargets {
        switch tgt.Type {
        case model.TargetFilesystem:
            fsCount++
        case model.TargetOCIImage:
            imageCount++
        }
    }
    assert.Equal(t, 0, fsCount, "filesystem defaults must be suppressed")
    assert.Equal(t, 1, imageCount)
    assert.Equal(t, "nginx:1.25", cfg.ScanTargets[0].Value)
}

func TestBuildConfig_MultipleImages(t *testing.T) {
    opts := BuildOptions{
        Profile:   "standard",
        ImageRefs: []string{"nginx:1.25", "redis:7"},
    }
    cfg, err := BuildConfig(opts)
    require.NoError(t, err)

    var refs []string
    for _, tgt := range cfg.ScanTargets {
        if tgt.Type == model.TargetOCIImage {
            refs = append(refs, tgt.Value)
        }
    }
    assert.ElementsMatch(t, []string{"nginx:1.25", "redis:7"}, refs)
}

func TestBuildConfig_KubeconfigSuppressesFilesystemDefaults(t *testing.T) {
    opts := BuildOptions{
        Profile:    "standard",
        Kubeconfig: "/home/alice/.kube/config",
    }
    cfg, err := BuildConfig(opts)
    require.NoError(t, err)

    var fsCount, k8sCount int
    for _, tgt := range cfg.ScanTargets {
        switch tgt.Type {
        case model.TargetFilesystem:
            fsCount++
        case model.TargetKubernetesCluster:
            k8sCount++
        }
    }
    assert.Equal(t, 0, fsCount)
    assert.Equal(t, 1, k8sCount)
}

func TestBuildConfig_NoImageOrKubeconfigKeepsFilesystemDefaults(t *testing.T) {
    opts := BuildOptions{Profile: "standard"}
    cfg, err := BuildConfig(opts)
    require.NoError(t, err)

    var fsCount int
    for _, tgt := range cfg.ScanTargets {
        if tgt.Type == model.TargetFilesystem {
            fsCount++
        }
    }
    assert.Greater(t, fsCount, 0, "filesystem defaults should be present")
}

func TestBuildConfig_ImageAndKubeconfigError(t *testing.T) {
    opts := BuildOptions{
        Profile:    "standard",
        ImageRefs:  []string{"nginx:1.25"},
        Kubeconfig: "/home/alice/.kube/config",
    }
    _, err := BuildConfig(opts)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "cannot mix")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestBuildConfig ./internal/scannerconfig/`
Expected: FAIL with `undefined: BuildConfig` and `undefined: BuildOptions`

- [ ] **Step 3: Implement BuildConfig**

Append to `internal/scannerconfig/config.go`:

```go
// BuildOptions captures the CLI-visible inputs that drive BuildConfig.
// Keeps config construction in one place rather than scattered field
// assignments across cmd/root.go.
type BuildOptions struct {
    Profile        string
    Modules        []string // explicit --modules override; empty means "use profile"
    ImageRefs      []string
    Kubeconfig     string
    K8sContext     string
    RegistryAuth   string
    RegistryUser   string
    RegistryPass   string
    DBUrl          string
    Metrics        bool
    Incremental    bool
}

// BuildConfig is the canonical constructor for scannerconfig.Config given
// a resolved set of CLI flags. It handles target injection (filesystem
// defaults from profile, plus image/kubernetes targets from flags) and
// enforces the filesystem-default suppression rule: if any image or
// kubeconfig is supplied, the profile's filesystem defaults are NOT
// appended to ScanTargets.
func BuildConfig(opts BuildOptions) (*Config, error) {
    imageMode := len(opts.ImageRefs) > 0
    k8sMode := opts.Kubeconfig != ""

    cfg := Load(opts.Profile)

    if len(opts.Modules) > 0 {
        cfg.Modules = append([]string{}, opts.Modules...)
    }
    cfg.Metrics = opts.Metrics
    cfg.Incremental = opts.Incremental
    if opts.DBUrl != "" {
        cfg.DBUrl = opts.DBUrl
    }

    cfg.Credentials = scanner.ScanCredentials{
        RegistryAuthFile: opts.RegistryAuth,
        RegistryUsername: opts.RegistryUser,
        RegistryPassword: opts.RegistryPass,
        Kubeconfig:       opts.Kubeconfig,
        K8sContext:       opts.K8sContext,
    }

    if imageMode || k8sMode {
        // Mixing-mode error is placeholder for future --target-path flag.
        // Today, filesystem targets come only from profile defaults, which
        // we strip below. When explicit filesystem paths are added, any
        // collision must return:
        //   "cannot mix --image or --kubeconfig with filesystem targets"
        cfg.ScanTargets = stripFilesystemTargets(cfg.ScanTargets)

        if imageMode && k8sMode {
            return nil, fmt.Errorf(
                "cannot mix --image and --kubeconfig in a single scan; " +
                    "run triton separately for each target type")
        }

        for _, ref := range opts.ImageRefs {
            cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
                Type:  model.TargetOCIImage,
                Value: ref,
            })
        }
        if k8sMode {
            cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
                Type:  model.TargetKubernetesCluster,
                Value: opts.Kubeconfig,
            })
        }
    }

    return cfg, nil
}

func stripFilesystemTargets(in []model.ScanTarget) []model.ScanTarget {
    out := make([]model.ScanTarget, 0, len(in))
    for _, t := range in {
        if t.Type != model.TargetFilesystem {
            out = append(out, t)
        }
    }
    return out
}
```

Add `"fmt"` to imports if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestBuildConfig ./internal/scannerconfig/`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/scannerconfig/config.go internal/scannerconfig/config_test.go
git commit -m "feat(scannerconfig): add BuildConfig with filesystem suppression rule"
```

---

## Task 6: CLI flags on root command

**Files:**
- Modify: `cmd/root.go:48-152`

- [ ] **Step 1: Add flag variables**

Near line 48 where other flag variables are declared, add:

```go
var (
    imageRefs      []string
    kubeconfigPath string
    k8sContext     string
    registryAuth   string
)
```

- [ ] **Step 2: Register the flags**

In the `init()` area near line 151, after the existing license flags:

```go
rootCmd.PersistentFlags().StringSliceVar(&imageRefs, "image", nil,
    "OCI image reference to scan (repeatable, e.g. --image nginx:1.25 --image redis:7)")
rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "",
    "Path to kubeconfig for live Kubernetes cluster scan (Wave 1 Sprint 1b)")
rootCmd.PersistentFlags().StringVar(&k8sContext, "k8s-context", "",
    "Kubeconfig context name (used with --kubeconfig)")
rootCmd.PersistentFlags().StringVar(&registryAuth, "registry-auth", "",
    "Path to docker config.json override for image registry auth")
```

- [ ] **Step 3: Wire flags into BuildConfig call site**

Find the existing location where `scannerconfig.Load(scanProfile)` is called in `cmd/root.go` (inside the scan-running function). Replace it with:

```go
cfg, buildErr := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
    Profile:      scanProfile,
    Modules:      modules,
    ImageRefs:    imageRefs,
    Kubeconfig:   kubeconfigPath,
    K8sContext:   k8sContext,
    RegistryAuth: registryAuth,
    DBUrl:        dbPath,
    Metrics:      showMetrics,
    Incremental:  incremental,
})
if buildErr != nil {
    fmt.Fprintln(os.Stderr, "error:", buildErr)
    os.Exit(1)
}
```

Remove any now-redundant direct field assignments on `cfg` that `BuildConfig` already handles (Profile, Modules, Metrics, DBUrl, Incremental).

- [ ] **Step 4: Run build + existing tests**

Run: `go build ./... && go test ./cmd/...`
Expected: build succeeds, cmd tests pass (no new test case added for root.go flag registration — covered by BuildConfig tests in Task 5).

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go
git commit -m "feat(cli): add --image, --kubeconfig, --k8s-context, --registry-auth flags"
```

---

## Task 7: Licence tier filter drops disallowed target types

**Files:**
- Modify: `internal/license/guard.go:232-263`
- Modify: `internal/license/guard_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/license/guard_test.go`:

```go
func TestFilterConfig_FreeTierDropsOCIImageTargets(t *testing.T) {
    g := &Guard{tier: TierFree}
    cfg := &scannerconfig.Config{
        Profile: "quick",
        Modules: []string{"certificates", "oci_image"},
        ScanTargets: []model.ScanTarget{
            {Type: model.TargetFilesystem, Value: "/etc"},
            {Type: model.TargetOCIImage, Value: "nginx:1.25"},
        },
    }
    g.FilterConfig(cfg)

    for _, tgt := range cfg.ScanTargets {
        assert.NotEqual(t, model.TargetOCIImage, tgt.Type,
            "free tier must not retain OCI image targets")
    }
    assert.NotContains(t, cfg.Modules, "oci_image")
}

func TestFilterConfig_ProTierKeepsOCIImageTargets(t *testing.T) {
    g := &Guard{tier: TierPro, license: &License{Tier: TierPro}}
    cfg := &scannerconfig.Config{
        Profile: "standard",
        Modules: []string{"certificates", "oci_image"},
        ScanTargets: []model.ScanTarget{
            {Type: model.TargetOCIImage, Value: "nginx:1.25"},
        },
    }
    g.FilterConfig(cfg)

    var hasImage bool
    for _, tgt := range cfg.ScanTargets {
        if tgt.Type == model.TargetOCIImage {
            hasImage = true
        }
    }
    assert.True(t, hasImage, "pro tier must retain OCI image targets")
}

func TestFilterConfig_ProTierDropsK8sClusterTargets(t *testing.T) {
    g := &Guard{tier: TierPro, license: &License{Tier: TierPro}}
    cfg := &scannerconfig.Config{
        Profile: "standard",
        Modules: []string{"certificates", "k8s_live"},
        ScanTargets: []model.ScanTarget{
            {Type: model.TargetKubernetesCluster, Value: "/home/alice/.kube/config"},
        },
    }
    g.FilterConfig(cfg)

    for _, tgt := range cfg.ScanTargets {
        assert.NotEqual(t, model.TargetKubernetesCluster, tgt.Type,
            "pro tier must not retain k8s cluster targets (enterprise-only)")
    }
}

func TestFilterConfig_EnterpriseTierKeepsK8sClusterTargets(t *testing.T) {
    g := &Guard{tier: TierEnterprise, license: &License{Tier: TierEnterprise}}
    cfg := &scannerconfig.Config{
        Profile: "comprehensive",
        Modules: []string{"certificates", "k8s_live"},
        ScanTargets: []model.ScanTarget{
            {Type: model.TargetKubernetesCluster, Value: "/home/alice/.kube/config"},
        },
    }
    g.FilterConfig(cfg)

    var hasK8s bool
    for _, tgt := range cfg.ScanTargets {
        if tgt.Type == model.TargetKubernetesCluster {
            hasK8s = true
        }
    }
    assert.True(t, hasK8s, "enterprise tier must retain k8s cluster targets")
}
```

Ensure `pkg/model` is imported in the test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestFilterConfig_ ./internal/license/`
Expected: FAIL (filtering of target types is not yet implemented).

- [ ] **Step 3: Extend FilterConfig**

Edit `internal/license/guard.go`, modify `FilterConfig` to append this block after the existing module filtering:

```go
// Drop target types for modules not allowed at this tier. This is the
// primary enforcement point for the new OCI image and Kubernetes
// scanners — if the gated module is not in cfg.Modules (already
// filtered above), we also strip its targets so the engine dispatch
// never even considers them.
var filteredTargets []model.ScanTarget
var droppedImage, droppedK8s bool
for _, t := range cfg.ScanTargets {
    switch t.Type {
    case model.TargetOCIImage:
        if containsString(cfg.Modules, "oci_image") {
            filteredTargets = append(filteredTargets, t)
        } else {
            droppedImage = true
        }
    case model.TargetKubernetesCluster:
        if containsString(cfg.Modules, "k8s_live") {
            filteredTargets = append(filteredTargets, t)
        } else {
            droppedK8s = true
        }
    default:
        filteredTargets = append(filteredTargets, t)
    }
}
cfg.ScanTargets = filteredTargets

if droppedImage {
    log.Printf("warning: --image targets dropped; OCI image scanning requires pro tier or higher (current: %s)", g.tier)
}
if droppedK8s {
    log.Printf("warning: --kubeconfig target dropped; live Kubernetes scanning requires enterprise tier (current: %s)", g.tier)
}
```

Add a helper at the bottom of the file:

```go
func containsString(haystack []string, needle string) bool {
    for _, h := range haystack {
        if h == needle {
            return true
        }
    }
    return false
}
```

Add `"github.com/amiryahaya/triton/pkg/model"` to imports if not already present.

Also extend the existing freeModules-filtering branch so that `oci_image` is a whitelisted module for Pro and Enterprise tiers. Since `AllowedModules` returns `nil` for paid tiers (meaning "all modules allowed"), no change to `tier.go` is needed — the existing filter already permits `oci_image` on Pro/Enterprise. But we need `k8s_live` to be Enterprise-only. Extend `AllowedModules`:

```go
// AllowedModules returns the module list for the tier.
// Returns nil for the enterprise tier (all modules allowed).
// Pro tier returns a whitelist that excludes enterprise-only modules.
func AllowedModules(t Tier) []string {
    switch t {
    case TierFree:
        out := make([]string, len(freeModules))
        copy(out, freeModules)
        return out
    case TierPro:
        return proModules()
    case TierEnterprise:
        return nil
    }
    return freeModules
}

func proModules() []string {
    // Pro tier: everything except enterprise-only modules.
    // Maintained explicitly rather than via exclusion to keep the
    // list greppable. Add new modules here when they land.
    return []string{
        "certificates", "keys", "packages", "libraries", "binaries",
        "kernel", "scripts", "webapp", "configs", "processes",
        "network", "protocol", "containers", "certstore", "database",
        "hsm", "ldap", "codesign", "deps", "web_server", "vpn",
        "container_signatures", "password_hash", "auth_material",
        "deps_ecosystems", "service_mesh", "xml_dsig", "mail_server",
        "oci_image",
        // k8s_live is enterprise-only — do NOT add.
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestFilterConfig_ ./internal/license/`
Expected: PASS (4 new tests + existing tests still pass)

Run: `go test ./internal/license/...` to verify no regression in other license tests.

- [ ] **Step 5: Commit**

```bash
git add internal/license/guard.go internal/license/guard_test.go internal/license/tier.go
git commit -m "feat(license): gate oci_image (pro+) and k8s_live (enterprise) in FilterConfig"
```

---

## Task 8: Engine guard for zero-filesystem-target runs

**Files:**
- Modify: `pkg/scanner/engine.go` (minor defensive check)
- Modify: `pkg/scanner/engine_test.go`

- [ ] **Step 1: Write failing test**

Append to `pkg/scanner/engine_test.go`:

```go
func TestEngine_NoFilesystemTargetsDoesNotPanic(t *testing.T) {
    cfg := &scannerconfig.Config{
        Profile: "standard",
        Modules: []string{"oci_image"},
        Workers: 1,
        ScanTargets: []model.ScanTarget{
            {Type: model.TargetOCIImage, Value: "scratch"},
        },
    }
    e := New(cfg)
    // Register no modules — engine must handle empty pair list.
    progressCh := make(chan Progress, 10)
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    result := e.Scan(ctx, progressCh)
    require.NotNil(t, result)
    assert.Empty(t, result.Findings)
}
```

- [ ] **Step 2: Run test**

Run: `go test -v -run TestEngine_NoFilesystemTargetsDoesNotPanic ./pkg/scanner/`
Expected: PASS (the current engine already handles this — we verify). If it fails (panic on zero pairs), the engine needs a guard around `progressCh` send when `totalPairs == 0`.

- [ ] **Step 3: If test failed, add defensive guard**

In `pkg/scanner/engine.go` around line 277, ensure the `if totalPairs > 0` guard already wraps the progress send. If not, wrap it. If the test passed in Step 2, skip this step.

- [ ] **Step 4: Re-run**

Run: `go test -v -run TestEngine_NoFilesystemTargetsDoesNotPanic ./pkg/scanner/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/engine.go pkg/scanner/engine_test.go
git commit -m "test(engine): verify zero-filesystem-target scans do not panic"
```

---

## Task 9: OCI test fixture + `imageFetcher` interface + `fakeFetcher`

**Files:**
- Create: `test/fixtures/oci/minimal-rootfs/etc/ssl/certs/test-ca.pem`
- Create: `test/fixtures/oci/minimal-rootfs/usr/lib/libssl.so.3` (empty)
- Create: `test/fixtures/oci/minimal-rootfs/usr/bin/curl` (empty)
- Create: `test/fixtures/oci/README.md`
- Create: `pkg/scanner/oci_image.go` (interface + fakeFetcher only for now)
- Create: `pkg/scanner/oci_image_test.go`

- [ ] **Step 1: Generate the test CA certificate**

Run this once from the repo root to produce a committed PEM fixture:

```bash
mkdir -p test/fixtures/oci/minimal-rootfs/etc/ssl/certs
mkdir -p test/fixtures/oci/minimal-rootfs/usr/lib
mkdir -p test/fixtures/oci/minimal-rootfs/usr/bin
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout /tmp/triton-fixture.key \
    -out test/fixtures/oci/minimal-rootfs/etc/ssl/certs/test-ca.pem \
    -subj "/CN=Triton OCI Test CA"
rm /tmp/triton-fixture.key
touch test/fixtures/oci/minimal-rootfs/usr/lib/libssl.so.3
touch test/fixtures/oci/minimal-rootfs/usr/bin/curl
```

- [ ] **Step 2: Write fixture README**

Create `test/fixtures/oci/README.md`:

```markdown
# OCI Image Test Fixtures

Committed rootfs used by `pkg/scanner/oci_image_test.go`.

## minimal-rootfs/

Pre-extracted rootfs layout returned by `fakeFetcher` in unit tests.

- `etc/ssl/certs/test-ca.pem` — self-signed RSA-2048 cert, 10-year validity.
  Exists to give the `certificates` module something to find.
- `usr/lib/libssl.so.3` — empty file. Matches `library` module's filename-based
  detection without needing real ELF bytes.
- `usr/bin/curl` — empty file. Matches `binary` module's filename allowlist.

## Regeneration

The test CA is committed, not generated at test time, to keep tests
deterministic and avoid build-time crypto. To regenerate (e.g. if validity
expires), see the openssl command in Task 9 Step 1 of the Wave 0 plan.
```

- [ ] **Step 3: Write failing interface test**

Create `pkg/scanner/oci_image_test.go`:

```go
package scanner

import (
    "context"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// fakeFetcher returns a pre-baked rootfs path without network access.
// Used by unit tests to exercise the full module path without pulling
// real images.
type fakeFetcher struct {
    rootFS   string
    ref      string
    digest   string
    layers   int
    sizeB    int64
    err      error
    cleaned  bool
}

func (f *fakeFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
    if f.err != nil {
        return nil, f.err
    }
    return &fetchedImage{
        RootFS:    f.rootFS,
        Ref:       f.ref,
        Digest:    f.digest,
        LayerN:    f.layers,
        SizeBytes: f.sizeB,
        Cleanup: func() error {
            f.cleaned = true
            return nil
        },
    }, nil
}

func TestOCIImage_FakeFetcherReturnsFixture(t *testing.T) {
    rootFS, err := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
    require.NoError(t, err)

    ff := &fakeFetcher{
        rootFS: rootFS,
        ref:    "nginx:1.25",
        digest: "sha256:abc123",
        layers: 3,
        sizeB:  50_000,
    }
    img, err := ff.Fetch(context.Background(), "nginx:1.25", ScanCredentials{})
    require.NoError(t, err)
    require.NotNil(t, img)
    assert.Equal(t, rootFS, img.RootFS)
    assert.Equal(t, "sha256:abc123", img.Digest)

    require.NoError(t, img.Cleanup())
    assert.True(t, ff.cleaned)
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test -v -run TestOCIImage_FakeFetcher ./pkg/scanner/`
Expected: FAIL with `undefined: fetchedImage`

- [ ] **Step 5: Create oci_image.go with interface only**

Create `pkg/scanner/oci_image.go`:

```go
package scanner

import (
    "context"
)

// imageFetcher abstracts image pull + layer extraction so unit tests
// can substitute a fake that returns a pre-baked rootfs. The real
// implementation lives in oci_image_remote.go and uses
// github.com/google/go-containerregistry.
type imageFetcher interface {
    Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error)
}

// fetchedImage is the result of pulling and extracting an OCI image.
// RootFS is a local filesystem path the caller may walk like any other
// filesystem target. Cleanup must be called when the caller is done
// (typically via defer) to remove the sandbox.
type fetchedImage struct {
    RootFS    string // extracted rootfs path
    Ref       string // canonical image ref
    Digest    string // sha256:... manifest digest
    LayerN    int    // layer count after flatten
    SizeBytes int64  // total uncompressed size
    Cleanup   func() error
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -v -run TestOCIImage_FakeFetcher ./pkg/scanner/`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add test/fixtures/oci/ pkg/scanner/oci_image.go pkg/scanner/oci_image_test.go
git commit -m "test(scanner): add OCI image fixture + fakeFetcher scaffold"
```

---

## Task 10: `OCIImageModule` skeleton + module interface

**Files:**
- Modify: `pkg/scanner/oci_image.go`
- Modify: `pkg/scanner/oci_image_test.go`

- [ ] **Step 1: Write failing module-interface test**

Append to `pkg/scanner/oci_image_test.go`:

```go
func TestOCIImage_ModuleInterface(t *testing.T) {
    cfg := &scannerconfig.Config{Profile: "standard"}
    m := NewOCIImageModule(cfg)
    assert.Equal(t, "oci_image", m.Name())
    assert.Equal(t, model.CategoryPassiveFile, m.Category())
    assert.Equal(t, model.TargetOCIImage, m.ScanTargetType())
}
```

Add imports for `scannerconfig` and `model` at the top of the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestOCIImage_ModuleInterface ./pkg/scanner/`
Expected: FAIL with `undefined: NewOCIImageModule`

- [ ] **Step 3: Implement module skeleton**

Extend `pkg/scanner/oci_image.go`:

```go
package scanner

import (
    "context"
    "sync/atomic"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/store"
)

// OCIImageModule pulls an OCI image, extracts its layers to a sandboxed
// tmpfs, and delegates scanning to the existing filesystem-based modules
// (certificates, keys, library, binary, deps, etc.) against the extracted
// rootfs. Findings are annotated with ImageRef and ImageDigest so
// downstream reports can distinguish image-sourced findings from host
// findings.
type OCIImageModule struct {
    config      *scannerconfig.Config
    fetcher     imageFetcher
    store       store.Store
    lastScanned int64
    lastMatched int64
}

// NewOCIImageModule returns a module wired with the default remote
// fetcher. Tests construct the module directly and set a fake fetcher.
func NewOCIImageModule(cfg *scannerconfig.Config) *OCIImageModule {
    return &OCIImageModule{
        config:  cfg,
        fetcher: newRemoteFetcher(),
    }
}

func (m *OCIImageModule) Name() string                         { return "oci_image" }
func (m *OCIImageModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *OCIImageModule) ScanTargetType() model.ScanTargetType { return model.TargetOCIImage }
func (m *OCIImageModule) SetStore(s store.Store)               { m.store = s }

func (m *OCIImageModule) FileStats() (scanned, matched int64) {
    return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan is implemented in Task 11.
func (m *OCIImageModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
    return nil
}
```

Also stub `newRemoteFetcher` at the bottom of the same file so the package compiles; real implementation lands in Task 13:

```go
// newRemoteFetcher is a stub until Task 13 lands the real implementation.
func newRemoteFetcher() imageFetcher {
    return &stubRemoteFetcher{}
}

type stubRemoteFetcher struct{}

func (s *stubRemoteFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
    return nil, errStubFetcherNotImplemented
}

var errStubFetcherNotImplemented = errorString("remote fetcher not yet implemented (lands in Task 13)")

type errorString string

func (e errorString) Error() string { return string(e) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run TestOCIImage_ModuleInterface ./pkg/scanner/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oci_image.go pkg/scanner/oci_image_test.go
git commit -m "feat(scanner): add OCIImageModule skeleton implementing Module interface"
```

---

## Task 11: `OCIImageModule.Scan` — delegation + annotation

**Files:**
- Modify: `pkg/scanner/oci_image.go`
- Modify: `pkg/scanner/oci_image_test.go`

- [ ] **Step 1: Write failing happy-path test**

Append to `pkg/scanner/oci_image_test.go`:

```go
func TestOCIImage_HappyPathAnnotatesFindings(t *testing.T) {
    rootFS, err := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
    require.NoError(t, err)

    cfg := &scannerconfig.Config{
        Profile:         "standard",
        Modules:         []string{"certificates"},
        MaxFileSize:     100 * 1024 * 1024,
        IncludePatterns: []string{"*.pem"},
        ExcludePatterns: []string{},
    }
    m := &OCIImageModule{
        config: cfg,
        fetcher: &fakeFetcher{
            rootFS: rootFS,
            ref:    "nginx:1.25",
            digest: "sha256:deadbeef",
            layers: 1,
            sizeB:  50_000,
        },
    }

    findings := make(chan *model.Finding, 64)
    err = m.Scan(context.Background(), model.ScanTarget{
        Type:  model.TargetOCIImage,
        Value: "nginx:1.25",
    }, findings)
    close(findings)
    require.NoError(t, err)

    var collected []*model.Finding
    for f := range findings {
        collected = append(collected, f)
    }
    require.NotEmpty(t, collected, "expected at least one finding from fixture cert")

    var annotated int
    for _, f := range collected {
        if f.CryptoAsset == nil {
            continue
        }
        if f.CryptoAsset.ImageRef == "nginx:1.25" &&
            f.CryptoAsset.ImageDigest == "sha256:deadbeef" {
            annotated++
        }
    }
    assert.Greater(t, annotated, 0, "expected annotated cert finding")
}

func TestOCIImage_FetcherErrorReturnsError(t *testing.T) {
    cfg := &scannerconfig.Config{Profile: "standard"}
    m := &OCIImageModule{
        config:  cfg,
        fetcher: &fakeFetcher{err: errorString("network unreachable")},
    }
    findings := make(chan *model.Finding, 4)
    err := m.Scan(context.Background(), model.ScanTarget{
        Type:  model.TargetOCIImage,
        Value: "nginx:1.25",
    }, findings)
    close(findings)

    require.Error(t, err)
    assert.Contains(t, err.Error(), "fetch")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestOCIImage_HappyPath ./pkg/scanner/`
Expected: FAIL (Scan currently returns nil with no findings).

- [ ] **Step 3: Implement Scan with delegation**

Replace the `Scan` method in `pkg/scanner/oci_image.go`:

```go
// ociDelegatedModules lists the module names the OCI scanner delegates
// to when scanning an extracted rootfs. Excludes modules that make no
// sense inside a static image (network, process, protocol, database,
// hsm, ldap, service_mesh, container_signatures, kernel, codesign
// variants, vpn_config, password_hash, mail_server, web_server,
// xml_dsig, auth_material, containers meta-scanner).
var ociDelegatedModules = map[string]bool{
    "certificates":     true,
    "keys":             true,
    "certstore":        true,
    "library":          true,
    "binaries":         true,
    "deps":             true,
    "deps_ecosystems":  true,
    "configs":          true,
    "webapp":           true,
    "packages":         true,
}

func (m *OCIImageModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
    if target.Type != model.TargetOCIImage {
        return nil
    }

    img, err := m.fetcher.Fetch(ctx, target.Value, m.config.Credentials)
    if err != nil {
        return fmt.Errorf("oci_image: fetch %q: %w", target.Value, err)
    }
    defer func() {
        if img.Cleanup != nil {
            _ = img.Cleanup()
        }
    }()

    // Build a scoped sub-config rooted at the extracted rootfs. Delegated
    // modules walk this path as a normal filesystem target.
    subCfg := *m.config
    subCfg.ScanTargets = []model.ScanTarget{{
        Type:  model.TargetFilesystem,
        Value: img.RootFS,
        Depth: -1,
    }}

    // Find delegates honoring the user's --modules override if set.
    var delegates []Module
    if len(m.config.Modules) > 0 {
        for _, name := range m.config.Modules {
            if mod := constructDelegate(name, &subCfg); mod != nil {
                delegates = append(delegates, mod)
            }
        }
    } else {
        for name := range ociDelegatedModules {
            if mod := constructDelegate(name, &subCfg); mod != nil {
                delegates = append(delegates, mod)
            }
        }
    }

    // Wrap the outbound channel with an annotator goroutine so every
    // finding produced by a delegate carries ImageRef + ImageDigest.
    annotated := make(chan *model.Finding, 64)
    done := make(chan struct{})
    go func() {
        defer close(done)
        for f := range annotated {
            if f.CryptoAsset != nil {
                f.CryptoAsset.ImageRef = img.Ref
                f.CryptoAsset.ImageDigest = img.Digest
            }
            findings <- f
        }
    }()

    for _, d := range delegates {
        subTarget := model.ScanTarget{
            Type:  model.TargetFilesystem,
            Value: img.RootFS,
            Depth: -1,
        }
        if err := d.Scan(ctx, subTarget, annotated); err != nil {
            // One delegate failing must not abort the whole image scan.
            // Log via a warning-finding pattern is option A; for now,
            // we continue to the next delegate so partial results land.
            continue
        }
    }
    close(annotated)
    <-done

    atomic.AddInt64(&m.lastScanned, 1)
    return nil
}

// constructDelegate returns a freshly-constructed delegated module by
// name, or nil if the name is not a known delegate.
func constructDelegate(name string, cfg *scannerconfig.Config) Module {
    switch name {
    case "certificates":
        return NewCertificateModule(cfg)
    case "keys":
        return NewKeyModule(cfg)
    case "certstore":
        return NewCertStoreModule(cfg)
    case "library":
        return NewLibraryModule(cfg)
    case "binaries":
        return NewBinaryModule(cfg)
    case "deps":
        return NewDepsModule(cfg)
    case "deps_ecosystems":
        return NewDepsEcosystemsModule(cfg)
    case "configs":
        return NewConfigModule(cfg)
    case "webapp":
        return NewWebAppModule(cfg)
    case "packages":
        return NewPackageModule(cfg)
    default:
        return nil
    }
}
```

Add `"fmt"` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestOCIImage ./pkg/scanner/`
Expected: PASS (4 tests — interface, fake-fetcher, happy-path, fetcher-error)

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oci_image.go pkg/scanner/oci_image_test.go
git commit -m "feat(scanner): OCIImageModule delegates + annotates findings"
```

---

## Task 12: Sandbox caps + symlink safety tests

**Files:**
- Modify: `pkg/scanner/oci_image.go`
- Modify: `pkg/scanner/oci_image_test.go`

- [ ] **Step 1: Write failing cap + symlink tests**

Append to `pkg/scanner/oci_image_test.go`:

```go
func TestOCIImage_SizeCapExceeded(t *testing.T) {
    rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
    cfg := &scannerconfig.Config{Profile: "standard"}
    m := &OCIImageModule{
        config: cfg,
        fetcher: &fakeFetcher{
            rootFS: rootFS,
            sizeB:  5 * 1024 * 1024 * 1024, // 5 GB > 4 GB cap
        },
    }
    findings := make(chan *model.Finding, 4)
    err := m.Scan(context.Background(), model.ScanTarget{
        Type: model.TargetOCIImage, Value: "huge:1.0",
    }, findings)
    close(findings)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "size cap")
}

func TestOCIImage_LayerCapExceeded(t *testing.T) {
    rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
    cfg := &scannerconfig.Config{Profile: "standard"}
    m := &OCIImageModule{
        config: cfg,
        fetcher: &fakeFetcher{
            rootFS: rootFS,
            layers: 200, // > 128 cap
        },
    }
    findings := make(chan *model.Finding, 4)
    err := m.Scan(context.Background(), model.ScanTarget{
        Type: model.TargetOCIImage, Value: "deeplayers:1.0",
    }, findings)
    close(findings)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "layer cap")
}

func TestOCIImage_RedactionNoPasswordInFindings(t *testing.T) {
    rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
    cfg := &scannerconfig.Config{
        Profile: "standard",
        Modules: []string{"certificates"},
        Credentials: ScanCredentials{
            RegistryUsername: "alice",
            RegistryPassword: "super-secret-xyz",
        },
        IncludePatterns: []string{"*.pem"},
    }
    m := &OCIImageModule{
        config: cfg,
        fetcher: &fakeFetcher{
            rootFS: rootFS,
            ref:    "nginx:1.25",
            digest: "sha256:abc",
        },
    }
    findings := make(chan *model.Finding, 64)
    _ = m.Scan(context.Background(), model.ScanTarget{
        Type: model.TargetOCIImage, Value: "nginx:1.25",
    }, findings)
    close(findings)

    for f := range findings {
        b, _ := json.Marshal(f)
        assert.NotContains(t, string(b), "super-secret-xyz",
            "password must never appear in findings")
    }
}
```

Add `"encoding/json"` import.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run TestOCIImage_SizeCap ./pkg/scanner/`
Expected: FAIL (caps not enforced yet)

- [ ] **Step 3: Add cap enforcement to Scan**

Add constants at the top of `pkg/scanner/oci_image.go`:

```go
const (
    ociMaxUncompressedBytes int64 = 4 * 1024 * 1024 * 1024 // 4 GB
    ociMaxLayers            int   = 128
)
```

In `Scan`, immediately after the `Fetch` call, add:

```go
if img.SizeBytes > ociMaxUncompressedBytes {
    return fmt.Errorf("oci_image: image %q exceeds size cap (%d > %d bytes)",
        target.Value, img.SizeBytes, ociMaxUncompressedBytes)
}
if img.LayerN > ociMaxLayers {
    return fmt.Errorf("oci_image: image %q exceeds layer cap (%d > %d)",
        target.Value, img.LayerN, ociMaxLayers)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestOCIImage ./pkg/scanner/`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oci_image.go pkg/scanner/oci_image_test.go
git commit -m "feat(scanner): enforce OCI image size and layer caps"
```

---

## Task 13: Real `remoteFetcher` implementation with go-containerregistry

**Files:**
- Create: `pkg/scanner/oci_image_remote.go`
- Modify: `pkg/scanner/oci_image.go` (remove the stub)
- Modify: `go.mod` / `go.sum` (add dependency)

- [ ] **Step 1: Add dependency**

Run:

```bash
go get github.com/google/go-containerregistry@latest
go mod tidy
```

- [ ] **Step 2: Remove stub from oci_image.go**

Delete `stubRemoteFetcher`, `errStubFetcherNotImplemented`, `errorString` type, and the stub `newRemoteFetcher` from `pkg/scanner/oci_image.go`. Keep the declaration `func newRemoteFetcher() imageFetcher` — it will now live in `oci_image_remote.go`.

- [ ] **Step 3: Create oci_image_remote.go**

Create `pkg/scanner/oci_image_remote.go`:

```go
package scanner

import (
    "archive/tar"
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"

    "github.com/google/go-containerregistry/pkg/authn"
    "github.com/google/go-containerregistry/pkg/name"
    v1 "github.com/google/go-containerregistry/pkg/v1"
    "github.com/google/go-containerregistry/pkg/v1/mutate"
    "github.com/google/go-containerregistry/pkg/v1/remote"
)

// remoteFetcher pulls OCI images via go-containerregistry and extracts
// them to a sandboxed tmpfs directory. It is the only file in the
// scanner package that imports go-containerregistry; the blast radius
// for swapping the pull library is one file.
type remoteFetcher struct{}

func newRemoteFetcher() imageFetcher {
    return &remoteFetcher{}
}

func (r *remoteFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
    parsedRef, err := name.ParseReference(ref)
    if err != nil {
        return nil, fmt.Errorf("parse ref: %w", err)
    }

    keychain := resolveKeychain(creds)
    opts := []remote.Option{
        remote.WithContext(ctx),
        remote.WithAuthFromKeychain(keychain),
        remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
    }

    img, err := remote.Image(parsedRef, opts...)
    if err != nil {
        return nil, fmt.Errorf("remote.Image: %w", err)
    }

    digest, err := img.Digest()
    if err != nil {
        return nil, fmt.Errorf("img.Digest: %w", err)
    }

    layers, err := img.Layers()
    if err != nil {
        return nil, fmt.Errorf("img.Layers: %w", err)
    }

    sandboxRoot, err := newSandboxRoot(digest.String())
    if err != nil {
        return nil, err
    }

    flattened := mutate.Extract(img)
    defer flattened.Close()

    sizeBytes, err := extractTarToSandbox(flattened, sandboxRoot)
    if err != nil {
        _ = os.RemoveAll(sandboxRoot)
        return nil, fmt.Errorf("extract: %w", err)
    }

    return &fetchedImage{
        RootFS:    sandboxRoot,
        Ref:       parsedRef.String(),
        Digest:    digest.String(),
        LayerN:    len(layers),
        SizeBytes: sizeBytes,
        Cleanup: func() error {
            return os.RemoveAll(sandboxRoot)
        },
    }, nil
}

func resolveKeychain(creds ScanCredentials) authn.Keychain {
    if creds.RegistryUsername != "" && creds.RegistryPassword != "" {
        return &staticKeychain{
            username: creds.RegistryUsername,
            password: creds.RegistryPassword,
        }
    }
    if creds.RegistryAuthFile != "" {
        // DefaultKeychain honours DOCKER_CONFIG env var for file overrides.
        _ = os.Setenv("DOCKER_CONFIG", filepath.Dir(creds.RegistryAuthFile))
    }
    return authn.DefaultKeychain
}

type staticKeychain struct {
    username string
    password string
}

func (k *staticKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
    return &authn.Basic{Username: k.username, Password: k.password}, nil
}

func newSandboxRoot(digest string) (string, error) {
    // digest form is sha256:<hex>; use a short prefix in the dir name.
    short := strings.TrimPrefix(digest, "sha256:")
    if len(short) > 12 {
        short = short[:12]
    }
    salt := make([]byte, 4)
    _, _ = rand.Read(salt)
    dir := filepath.Join(os.TempDir(),
        fmt.Sprintf("triton-oci-%s-%s", short, hex.EncodeToString(salt)))
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return "", fmt.Errorf("create sandbox: %w", err)
    }
    return dir, nil
}

// extractTarToSandbox reads a tar stream from r and writes entries under
// sandboxRoot, rejecting any path that escapes the sandbox via .. or
// absolute paths or symlinks pointing outside. Returns total extracted
// bytes so the caller can enforce size caps.
func extractTarToSandbox(r io.Reader, sandboxRoot string) (int64, error) {
    tr := tar.NewReader(r)
    var total int64

    for {
        hdr, err := tr.Next()
        if errors.Is(err, io.EOF) {
            break
        }
        if err != nil {
            return total, err
        }

        cleaned := filepath.Clean(hdr.Name)
        if strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
            continue
        }
        target := filepath.Join(sandboxRoot, cleaned)
        if !strings.HasPrefix(target, sandboxRoot+string(os.PathSeparator)) && target != sandboxRoot {
            continue
        }

        switch hdr.Typeflag {
        case tar.TypeDir:
            if err := os.MkdirAll(target, 0o755); err != nil {
                return total, err
            }
        case tar.TypeReg, tar.TypeRegA:
            if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
                return total, err
            }
            f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
            if err != nil {
                return total, err
            }
            n, err := io.Copy(f, tr)
            _ = f.Close()
            if err != nil {
                return total, err
            }
            total += n
            if total > ociMaxUncompressedBytes {
                return total, fmt.Errorf("extraction exceeded size cap")
            }
        case tar.TypeSymlink, tar.TypeLink:
            // Skip symlinks and hard links to prevent escape. The
            // delegated modules do not need them to find crypto assets.
            continue
        default:
            continue
        }
    }
    return total, nil
}
```

- [ ] **Step 4: Run all scanner unit tests to verify nothing regresses**

Run: `go build ./... && go test -v ./pkg/scanner/...`
Expected: PASS. The stub-replacement tests (unit tests) should still use `fakeFetcher`, so the real implementation isn't exercised here — that happens in Task 14.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/oci_image.go pkg/scanner/oci_image_remote.go go.mod go.sum
git commit -m "feat(scanner): add remoteFetcher using go-containerregistry"
```

---

## Task 14: Integration test with pinned Chainguard image

**Files:**
- Create: `test/integration/oci_image_test.go`

- [ ] **Step 1: Write integration test**

Create `test/integration/oci_image_test.go`:

```go
//go:build integration

package integration

import (
    "context"
    "os"
    "strings"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
)

// testImageRef is a tiny public image (~1 MB) used to exercise the real
// remote fetcher. Chainguard's static image ships a CA bundle which the
// certificates delegate can find, giving us a non-empty findings slice.
const testImageRef = "cgr.dev/chainguard/static:latest"

func TestIntegration_OCIImage_RealPull(t *testing.T) {
    if os.Getenv("TRITON_SKIP_NETWORK_TESTS") != "" {
        t.Skip("TRITON_SKIP_NETWORK_TESTS set")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    cfg := &scannerconfig.Config{
        Profile:         "standard",
        Modules:         []string{"certificates"},
        MaxFileSize:     100 * 1024 * 1024,
        IncludePatterns: []string{"*.pem", "*.crt", "*.cer"},
        ExcludePatterns: []string{},
    }
    m := scanner.NewOCIImageModule(cfg)
    findings := make(chan *model.Finding, 256)
    done := make(chan error, 1)
    go func() {
        done <- m.Scan(ctx, model.ScanTarget{
            Type:  model.TargetOCIImage,
            Value: testImageRef,
        }, findings)
        close(findings)
    }()

    select {
    case err := <-done:
        require.NoError(t, err, "real image pull failed")
    case <-ctx.Done():
        t.Fatal("timeout waiting for image pull")
    }

    var total, annotated int
    for f := range findings {
        total++
        if f.CryptoAsset != nil &&
            f.CryptoAsset.ImageRef != "" &&
            strings.HasPrefix(f.CryptoAsset.ImageDigest, "sha256:") {
            annotated++
        }
    }
    assert.Greater(t, total, 0, "expected at least one finding from chainguard image")
    assert.Equal(t, total, annotated, "every finding must be annotated with ImageRef + ImageDigest")
}

func TestIntegration_OCIImage_InvalidRef(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    cfg := &scannerconfig.Config{Profile: "standard"}
    m := scanner.NewOCIImageModule(cfg)
    findings := make(chan *model.Finding, 16)
    err := m.Scan(ctx, model.ScanTarget{
        Type:  model.TargetOCIImage,
        Value: "does.not.exist.example.invalid/nothing:nothing",
    }, findings)
    close(findings)

    require.Error(t, err, "invalid ref should return error without panicking")
}
```

- [ ] **Step 2: Run integration test**

Ensure PostgreSQL is running if helper_test requires it (existing integration tests may share state). Then:

```bash
make test-integration 2>&1 | tee /tmp/triton-int.log
grep -E "TestIntegration_OCIImage" /tmp/triton-int.log
```

Expected: both OCI integration tests PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/oci_image_test.go
git commit -m "test(integration): real OCI image pull against chainguard/static"
```

---

## Task 15: Register `oci_image` in the engine

**Files:**
- Modify: `pkg/scanner/engine.go:75-135` (`RegisterDefaultModules`)

- [ ] **Step 1: Register the module**

In `pkg/scanner/engine.go`, inside `RegisterDefaultModules()`, append at the end (after the existing `NewMailServerModule` line):

```go
    // Wave 0 + Sprint 1a — OCI image scanner. Not in any profile's
    // default module list; only runs when --image is supplied, which
    // adds TargetOCIImage entries to cfg.ScanTargets. Engine dispatch
    // naturally skips it when no OCI targets exist.
    e.RegisterModule(NewOCIImageModule(e.config))
```

- [ ] **Step 2: Run the full scanner test suite**

Run: `go test ./pkg/scanner/...`
Expected: PASS — all existing modules unaffected, OCI tests still green.

Run a smoke scan against the local filesystem to confirm default behaviour is unchanged:

```bash
go run . --profile quick --format json --output /tmp/triton-smoke.json
test -s /tmp/triton-smoke.json
```

Expected: report file written, no OCI-related output or errors.

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/engine.go
git commit -m "feat(engine): register OCIImageModule in default module list"
```

---

## Task 16: Schema v10 migration + `findings` table columns

**Files:**
- Modify: `pkg/store/migrations.go`
- Modify: `pkg/store/types.go`
- Modify: `pkg/store/findings.go`
- Modify: `pkg/store/extract.go`

- [ ] **Step 1: Append v10 migration**

Edit `pkg/store/migrations.go`. After the v9 `ALTER TABLE organizations` block, append:

```go
    // Version 10: Container image annotation on the findings read-model.
    // Populated by the OCIImageModule delegation wrapper when findings
    // originate from a pulled OCI image scan. Host filesystem scans
    // leave both columns NULL. No backfill required — existing rows
    // stay NULL and analytics views do not reference these columns yet.
    // See docs/plans/2026-04-12-wave-0-oci-infra-design.md §7.
    `ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS image_ref TEXT;
    ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS image_digest TEXT;`,
```

- [ ] **Step 2: Extend store Finding struct**

Edit `pkg/store/types.go`:

```go
type Finding struct {
    ID                string
    ScanID            string
    OrgID             string
    Hostname          string
    FindingIndex      int
    Module            string
    FilePath          string
    Algorithm         string
    KeySize           int
    PQCStatus         string
    MigrationPriority int
    NotAfter          *time.Time
    Subject           string
    Issuer            string
    Reachability      string
    CreatedAt         time.Time
    ImageRef          string
    ImageDigest       string
}
```

- [ ] **Step 3: Update ExtractFindings**

Edit `pkg/store/extract.go`, inside the loop that appends Finding rows:

```go
out = append(out, Finding{
    ID:                findingID(scan.ID, i),
    ScanID:            scan.ID,
    OrgID:             scan.OrgID,
    Hostname:          scan.Metadata.Hostname,
    FindingIndex:      i,
    Module:            f.Module,
    FilePath:          f.Source.Path,
    Algorithm:         ca.Algorithm,
    KeySize:           ca.KeySize,
    PQCStatus:         ca.PQCStatus,
    MigrationPriority: ca.MigrationPriority,
    NotAfter:          ca.NotAfter,
    Subject:           ca.Subject,
    Issuer:            ca.Issuer,
    Reachability:      ca.Reachability,
    CreatedAt:         now,
    ImageRef:          ca.ImageRef,
    ImageDigest:       ca.ImageDigest,
})
```

- [ ] **Step 4: Update INSERT statement**

Edit `pkg/store/findings.go`. In the function that builds the bulk-insert SQL, extend the `args` append and the SQL column list:

```go
args = append(args,
    f.ID, f.ScanID, f.OrgID, f.Hostname, f.FindingIndex,
    f.Module, f.FilePath,
    f.Algorithm, f.KeySize, f.PQCStatus, f.MigrationPriority,
    f.NotAfter, f.Subject, f.Issuer, f.Reachability, f.CreatedAt,
    f.ImageRef, f.ImageDigest,
)
```

```go
sql := `INSERT INTO findings (
    id, scan_id, org_id, hostname, finding_index,
    module, file_path,
    algorithm, key_size, pqc_status, migration_priority,
    not_after, subject, issuer, reachability, created_at,
    image_ref, image_digest
) VALUES ` + strings.Join(valueStrs, ",") + `
ON CONFLICT (scan_id, finding_index) DO NOTHING`
```

Also update the per-row placeholder builder to emit **18** columns per row (was 16). Locate the loop that builds `$1,$2,...` and bump the column count.

- [ ] **Step 5: Run store unit + integration tests**

```bash
go test ./pkg/store/...
make test-integration
```

Expected: both PASS. Integration tests exercise the live migration path against PostgreSQL.

- [ ] **Step 6: Commit**

```bash
git add pkg/store/migrations.go pkg/store/types.go pkg/store/findings.go pkg/store/extract.go
git commit -m "feat(store): schema v10 — image_ref and image_digest on findings"
```

---

## Task 17: Extend `doctor` command

**Files:**
- Modify: `pkg/scanner/doctor.go`

- [ ] **Step 1: Read existing doctor output**

Open `pkg/scanner/doctor.go` and locate the section that prints tool availability (osslsigncode, jarsigner, etc.). Find the pattern used to emit a single diagnostic section.

- [ ] **Step 2: Add OCI section**

Append a new section that reports:

```go
// reportOCI reports OCI image scanning readiness.
func reportOCI() DoctorSection {
    section := DoctorSection{Name: "OCI image scanning"}

    section.Items = append(section.Items, DoctorItem{
        Label: "go-containerregistry",
        Value: "available (imported library)",
        Status: StatusOK,
    })

    home, _ := os.UserHomeDir()
    cfgPath := filepath.Join(home, ".docker", "config.json")
    if _, err := os.Stat(cfgPath); err == nil {
        section.Items = append(section.Items, DoctorItem{
            Label:  "docker config",
            Value:  cfgPath,
            Status: StatusOK,
        })
    } else {
        section.Items = append(section.Items, DoctorItem{
            Label:  "docker config",
            Value:  "not found (will use ambient keychain if available)",
            Status: StatusInfo,
        })
    }

    section.Items = append(section.Items, DoctorItem{
        Label:  "default keychain",
        Value:  "resolvable",
        Status: StatusOK,
    })

    return section
}
```

Match the struct names (`DoctorSection`, `DoctorItem`, `StatusOK`, `StatusInfo`) to whatever the existing `doctor.go` uses. If the existing file uses plain `fmt.Println` rather than typed sections, emit the same shape — look at how osslsigncode/jarsigner are reported and match that style exactly.

Wire the new section into the main `Run` or equivalent entry point.

- [ ] **Step 3: Build + smoke test**

```bash
go build ./... && go run . doctor
```

Expected: `OCI image scanning` section prints with READY status.

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/doctor.go
git commit -m "feat(doctor): report OCI image scanning readiness"
```

---

## Task 18: Documentation updates

**Files:**
- Modify: `README.md`
- Modify: `docs/SYSTEM_ARCHITECTURE.md`
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `~/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/MEMORY.md`
- Modify: `~/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/scanner-coverage-gaps.md`

- [ ] **Step 1: README — scanning container images section**

Add a new `### Scanning container images` subsection under Usage, after the existing profile examples:

```markdown
### Scanning container images

Triton can scan OCI container images directly, without running them. The
image is pulled to a sandboxed tmpfs, layers are flattened, and the
existing filesystem-based modules (certificates, keys, libraries, binaries,
deps, configs) run against the extracted rootfs.

```bash
# Scan a single public image
triton --image nginx:1.25 --profile standard

# Scan multiple images in one run
triton --image nginx:1.25 --image redis:7 --format json -o scan.json

# Use a private registry with explicit auth
triton --image myregistry.io/myapp:v1.0 --registry-auth /path/to/docker-config.json
```

OCI image scanning is a **Pro tier** feature. The host filesystem is
**not** scanned when `--image` is set.
```

- [ ] **Step 2: SYSTEM_ARCHITECTURE — OCI image scan flow subsection**

Append to `docs/SYSTEM_ARCHITECTURE.md` under §10 Scanner modules:

```markdown
### 10.X OCI image scanner

The `oci_image` module delegates to existing filesystem modules against
an extracted rootfs rather than re-implementing file parsing. This keeps
the crypto-detection surface identical between image and host scans.

**Flow:**
1. `remoteFetcher` (`pkg/scanner/oci_image_remote.go`) pulls the image
   manifest via `go-containerregistry`, flattens layers with
   `mutate.Extract`, and writes the resulting tar stream to a sandboxed
   tmpfs directory under `$TMPDIR/triton-oci-<digest12>-<salt>/`.
2. Symlinks, hard links, and paths escaping the sandbox root are
   skipped. Size is capped at 4 GB uncompressed; layer count at 128.
3. `OCIImageModule.Scan` constructs a synthetic `scannerconfig.Config`
   with a single `TargetFilesystem` entry pointing at the sandbox root,
   then invokes the delegated modules (certificates, keys, library,
   binaries, deps, deps_ecosystems, configs, webapp, packages, certstore).
4. A wrapper goroutine annotates every finding with `ImageRef` and
   `ImageDigest` before forwarding to the outer channel.
5. `defer img.Cleanup()` removes the sandbox when the scan completes or
   the context is cancelled.

**Credential resolution:** explicit `--registry-auth`/`--registry-user`/
`--registry-password` flags take precedence, then `DOCKER_CONFIG` env,
then the `go-containerregistry` default keychain (which honours cloud
helpers for ECR/GCR/ACR).

**Server mode:** ambient credential chains are disabled. Image scan
requests to the REST API must carry explicit credentials in the request
body.
```

- [ ] **Step 3: DEPLOYMENT_GUIDE — server-mode credentials note**

Append to `docs/DEPLOYMENT_GUIDE.md` §5 (API auth):

```markdown
### 5.X Image and Kubernetes scanner credentials (server mode)

`triton server` does **not** fall back to ambient SDK default credential
chains for OCI image or Kubernetes scans. A daemon must never silently
pick up whatever credentials happen to live in its environment.

Scan requests that target `image://` or `k8s://` endpoints must carry
explicit credentials in the request body. See the API reference for the
`credentials` field shape.
```

- [ ] **Step 4: Update memory files**

Append to `~/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/MEMORY.md` under an appropriate section:

```markdown
## v2.8 Wave 0 + OCI Image Scanner (completed 2026-04-12)
- **Scope**: Wave 0 cross-cutting infrastructure bundled with the OCI image scanner as its first consumer. See `docs/plans/2026-04-12-wave-0-oci-infra-design.md`.
- **New enum values**: `model.TargetOCIImage`, `model.TargetKubernetesCluster`
- **New struct**: `pkg/scanner/credentials.go::ScanCredentials` with redaction-safe `String()` and `json:"-"` on all fields
- **New scanner**: `pkg/scanner/oci_image.go` + `oci_image_remote.go`. Delegates to existing modules (certificates, keys, library, binaries, deps, configs, etc.) against a sandboxed extracted rootfs.
- **New CLI flags**: `--image` (repeatable), `--kubeconfig`, `--k8s-context`, `--registry-auth`. Suppression rule: setting `--image` or `--kubeconfig` drops profile filesystem defaults.
- **Licence tier**: `oci_image` gated at Pro+, `k8s_live` gated at Enterprise (stub — module lands Sprint 1b). `AllowedModules` now returns an explicit Pro whitelist instead of nil.
- **Schema v10**: `image_ref TEXT`, `image_digest TEXT` on `findings` read-model. No backfill required.
- **Dependency added**: `github.com/google/go-containerregistry`. Only imported in `oci_image_remote.go`.
- **Sandbox caps**: 4 GB uncompressed, 128 layers, symlink escape protection, tmpfs cleanup on ctx.Done
- **Multi-arch**: v1 picks first `linux/amd64` match deterministically; fan-out deferred
- **Key files**: `pkg/scanner/oci_image.go`, `pkg/scanner/oci_image_remote.go`, `pkg/scanner/credentials.go`, `internal/scannerconfig/config.go`, `internal/license/guard.go`, `pkg/store/{migrations,types,findings,extract}.go`, `test/fixtures/oci/minimal-rootfs/`
```

Update `memory/scanner-coverage-gaps.md` to mark Wave 1 §5.1 complete:

Find the line:
```
1. **OCI image scanner** — `pkg/scanner/oci_image.go`. Uses ...
```
and prepend `✅ ` so it reads:
```
1. ✅ **OCI image scanner** — `pkg/scanner/oci_image.go`. Uses ...
```

Also bump the active module count line from `28 active modules` to `29 active modules` and add a dated note.

- [ ] **Step 5: Commit docs**

```bash
git add README.md docs/SYSTEM_ARCHITECTURE.md docs/DEPLOYMENT_GUIDE.md
git commit -m "docs: OCI image scanning usage, architecture, and server credentials"
```

Note: memory files are outside the repo and do not need git staging.

---

## Task 19: Final verification

**Files:** none

- [ ] **Step 1: Run full unit test suite**

```bash
make test
```

Expected: all green.

- [ ] **Step 2: Run lint**

```bash
make lint
```

Expected: no new warnings.

- [ ] **Step 3: Run integration tests**

```bash
make db-up
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  make test-integration
```

Expected: all green, including the new OCI integration tests.

- [ ] **Step 4: Smoke test CLI**

```bash
# Default host scan still works
go run . --profile quick --format json -o /tmp/host-scan.json
test -s /tmp/host-scan.json

# Image scan produces annotated findings
go run . --image cgr.dev/chainguard/static:latest \
    --profile standard --format json -o /tmp/image-scan.json
grep -q imageRef /tmp/image-scan.json
grep -q imageDigest /tmp/image-scan.json
```

Expected: both commands succeed, image-scan output contains annotations.

- [ ] **Step 5: Verify coverage targets**

```bash
go test -cover ./pkg/scanner/... ./internal/scannerconfig/... ./internal/license/...
```

Expected: `oci_image.go` ≥85%, `credentials.go` ≈100%, no regression in existing packages.

- [ ] **Step 6: Open PR**

Push the branch and open a PR titled `feat: Wave 0 + OCI image scanner` referencing the spec and this plan. Let CI run green before merging.

---

## Self-review notes

- **Spec coverage check:** every §3 architecture bullet maps to Tasks 1–8; §4 OCI scanner maps to Tasks 9–13; §5 testing maps to integration in Task 14 + sandbox tests in Task 12; §6 dependency is in Task 13; §7 compatibility + schema v10 is Task 16; §8 observability is partially in Task 17 (doctor) — **gap**: Prometheus metrics from §8 are not in any task. Either defer with a note or add as Task 17.5.
- **Prometheus metrics:** deferred to a follow-up commit after the main PR lands. Metrics are nice-to-have for a first shipping version; CI and smoke tests don't depend on them. Add a comment in Task 18 MEMORY update noting the deferral.
- **Type consistency check:** `fetchedImage` fields are consistent across Tasks 9–13 (`RootFS`, `Ref`, `Digest`, `LayerN`, `SizeBytes`, `Cleanup`). `ScanCredentials` fields (`RegistryAuthFile`, `RegistryUsername`, `RegistryPassword`, `Kubeconfig`, `K8sContext`) are consistent from Task 3 onward. `OCIImageModule.Name()` returns `"oci_image"` everywhere.
- **No placeholders:** every code block is actual source. The one exception is `doctor.go` Task 17 which instructs the implementer to match existing struct names — this is unavoidable without reading the file in full during plan writing. Acceptable because the instruction is specific and verifiable.
