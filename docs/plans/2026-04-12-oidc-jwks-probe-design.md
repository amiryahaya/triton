# OIDC/JWKS Discovery Probe Scanner — Design Spec

**Date:** 2026-04-12
**Parent roadmap:** `docs/plans/2026-04-11-scanner-gaps-roadmap.md` (Wave 2 §6.2)
**Status:** Design approved, pending spec review before implementation plan.

> **For Claude:** After this spec is approved by the user, invoke `superpowers:writing-plans` to produce the step-by-step implementation plan. Do NOT invoke any other skill.

---

## 1. Goal

Add an OIDC/JWKS discovery probe scanner that fetches `/.well-known/openid-configuration` from user-specified identity provider endpoints, follows the `jwks_uri` to retrieve the JWK signing key set, normalizes JWA algorithm names to Triton's canonical crypto registry forms, and emits PQC-classified findings for both deployed keys and advertised-but-unused algorithms.

**Success looks like:** `triton --oidc-endpoint https://auth.example.com --profile standard` fetches the discovery doc and JWKS, emits one finding per JWK signing key (confidence 0.90) and one finding per advertised algorithm not backed by a deployed key (confidence 0.60), all routed through the existing policy engine (NACSA-2030, CNSA-2.0) and CycloneDX CBOM output.

**Effort:** ~3 days focused work. One new scanner module, one new CLI flag, ~400 LOC + tests.

---

## 2. Scope

### In scope

- New scanner module `pkg/scanner/oidc_probe.go` implementing `Module` interface
- `httpDoer` interface for testability (production: `http.Client`, tests: `httptest.Server`)
- HTTP GET to `<endpoint>/.well-known/openid-configuration` with 15s timeout, 1 MB response cap, up to 3 redirects
- JSON parsing of discovery doc: `jwks_uri`, `id_token_signing_alg_values_supported`, `token_endpoint_auth_signing_alg_values_supported`, `userinfo_signing_alg_values_supported`, `request_object_signing_alg_values_supported`
- HTTP GET to `jwks_uri` with same timeout/size constraints
- JWK set parsing: extract `kty`, `alg`, `crv`, `kid`, `use`, RSA modulus `n` for key size derivation
- JWA → canonical algorithm normalization via `oidcAlgoTokenMap` (RS256→RSA, ES384→ECDSA-P384, PS256→RSA-PSS, EdDSA→Ed25519, etc.)
- RSA key size derivation from base64url-decoded modulus length
- EC key size derivation from curve name (P-256→256, P-384→384, P-521→521)
- Two finding types: JWK key findings (confidence 0.90, `DetectionMethod: "network-probe"`) and advertised-algorithm findings (confidence 0.60, `DetectionMethod: "configuration"`)
- Deduplication of advertised algorithms across discovery doc fields
- Skip `alg: "none"` (unsigned, not a crypto asset)
- Skip `use: "enc"` keys (encryption, not signing — not PQC-relevant for auth)
- Infer algorithm from `kty`+`crv` when `alg` field is absent (Azure AD pattern)
- Warning finding when discovery doc is served over `http://` (insecure transport)
- New CLI flag `--oidc-endpoint` (StringSlice, repeatable)
- `BuildConfig` injects `oidc_probe` module + `TargetNetwork` entries when `--oidc-endpoint` is set
- `--oidc-endpoint` does NOT suppress filesystem defaults (unlike `--image`)
- Licence tier: Pro+ (add to `proModules()` in `tier.go`)
- Register module in `engine.go::RegisterDefaultModules`
- Unit tests with `httptest.Server` fakes (11+ test cases)
- `BuildConfig` tests (3 test cases)

### Out of scope

- Auto-discovery of OIDC endpoints from network scan (Wave 2 v2 — option (b) from brainstorming)
- Token validation, introspection, or authentication flow testing
- Client registration / dynamic OIDC RP
- Certificate pinning on OIDC endpoints (protocol scanner covers TLS)
- Server-mode OIDC endpoint scanning (API handler changes deferred)
- Prometheus metrics for probe timing
- New `ScanTargetType` (reuses `TargetNetwork`)
- Schema migration (no new columns — findings already have all needed fields)

---

## 3. Architecture

### 3.1 Module interface

```go
type OIDCProbeModule struct {
    config      *scannerconfig.Config
    httpClient  httpDoer
    lastScanned int64
    lastMatched int64
}

type httpDoer interface {
    Do(req *http.Request) (*http.Response, error)
}

func (m *OIDCProbeModule) Name() string                         { return "oidc_probe" }
func (m *OIDCProbeModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *OIDCProbeModule) ScanTargetType() model.ScanTargetType { return model.TargetNetwork }
```

Uses `TargetNetwork` with URL values (distinguished from `host:port` protocol-scanner targets by the `https://` prefix check in `Scan()`). Category is `CategoryActiveNetwork` since it makes outbound HTTP requests.

### 3.2 Scan flow

```
1. Filter targets: skip any TargetNetwork entry without https:// or http:// prefix
2. For each OIDC endpoint URL:
   a. GET <url>/.well-known/openid-configuration (15s timeout, 1 MB cap)
   b. Parse JSON → oidcDiscovery struct
   c. Collect all advertised algorithms (deduplicated) from *_signing_alg_values_supported fields
   d. GET jwks_uri (15s timeout, 1 MB cap)
   e. Parse JSON → jwkSet struct
   f. For each JWK key where use != "enc":
      - Normalize alg via oidcAlgoTokenMap (or infer from kty+crv if alg absent)
      - Derive key size (RSA: modulus length, EC: curve bits, OKP: curve bits)
      - Emit finding (confidence 0.90, DetectionMethod: "network-probe")
      - Record the canonical algorithm as "covered"
   g. For each advertised algorithm not in the "covered" set:
      - Skip "none"
      - Normalize via oidcAlgoTokenMap
      - Emit finding (confidence 0.60, DetectionMethod: "configuration")
   h. If endpoint is http:// (not https://): emit warning finding
```

### 3.3 JWA → canonical normalization map

```go
var oidcAlgoTokenMap = map[string]string{
    "RS256": "RSA",    "RS384": "RSA",    "RS512": "RSA",
    "PS256": "RSA-PSS","PS384": "RSA-PSS","PS512": "RSA-PSS",
    "ES256": "ECDSA-P256", "ES384": "ECDSA-P384", "ES512": "ECDSA-P521",
    "EdDSA": "Ed25519",
}
```

For `EdDSA`, the actual curve is resolved from the JWK's `crv` field: `Ed25519` or `Ed448`. The map provides the default; `crv` overrides when present.

### 3.4 Key size derivation

- **RSA:** `len(base64url_decode(jwk.N)) * 8` bits. Uses `encoding/base64.RawURLEncoding`.
- **EC:** Curve name lookup: `P-256`→256, `P-384`→384, `P-521`→521.
- **OKP:** `Ed25519`→256, `Ed448`→456.
- **Fallback:** If key size cannot be determined, set to 0 (existing convention for unknown).

### 3.5 CLI flag + BuildConfig wiring

New flag on `cmd/root.go`:

```go
rootCmd.PersistentFlags().StringSliceVar(&oidcEndpoints, "oidc-endpoint", nil,
    "OIDC identity provider URL to probe (repeatable, e.g. --oidc-endpoint https://auth.example.com)")
```

`BuildOptions` gains `OIDCEndpoints []string`. `BuildConfig` injects:
- `oidc_probe` into `cfg.Modules` (if not already present)
- One `model.ScanTarget{Type: model.TargetNetwork, Value: url}` per endpoint

**Key difference from `--image`:** OIDC endpoint probing does NOT suppress filesystem defaults. Users often want to scan their host AND probe their IdP in a single run.

### 3.6 Licence tier

`oidc_probe` added to `proModules()` in `internal/license/tier.go`. Free tier users get the module filtered out and the target dropped (same pattern as `oci_image`).

### 3.7 Finding source fields

```go
FindingSource{
    Type:            "network",
    Endpoint:        "https://auth.example.com/.well-known/openid-configuration",
    DetectionMethod: "network-probe", // or "configuration" for advertised-only
}
```

---

## 4. Internal data structs

```go
type oidcDiscovery struct {
    JwksURI                       string   `json:"jwks_uri"`
    IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
    TokenEndpointAuthSigningAlg   []string `json:"token_endpoint_auth_signing_alg_values_supported"`
    UserinfoSigningAlgValues      []string `json:"userinfo_signing_alg_values_supported"`
    RequestObjectSigningAlgValues []string `json:"request_object_signing_alg_values_supported"`
}

type jwkKey struct {
    Kty string `json:"kty"` // RSA, EC, OKP
    Alg string `json:"alg"` // RS256, ES384, etc. (may be absent)
    Crv string `json:"crv"` // P-256, P-384, Ed25519
    Kid string `json:"kid"` // key ID
    Use string `json:"use"` // sig, enc
    N   string `json:"n"`   // RSA modulus (base64url)
    X   string `json:"x"`   // EC x coordinate (unused for size, but present)
}

type jwkSet struct {
    Keys []jwkKey `json:"keys"`
}
```

No private key fields (`d`, `p`, `q`) are ever parsed or stored. Only the public-key metadata needed for algorithm classification.

---

## 5. Testing strategy

### 5.1 Unit tests — `httptest.Server` fakes

All tests use `httptest.NewServer` returning pre-baked JSON responses. No network access.

| Test | What it verifies |
|---|---|
| `TestOIDCProbe_HappyPath` | Discovery → JWKS → 2 JWK findings (RSA-2048 + ES256), confidence 0.90, endpoint annotated |
| `TestOIDCProbe_AdvertisedNotInUse` | Advertises RS256+ES256+ES384, JWKS has only ES256 → RS256+ES384 at confidence 0.60 |
| `TestOIDCProbe_AlgoNormalization` | RS256→RSA, ES384→ECDSA-P384, PS256→RSA-PSS, EdDSA→Ed25519 via oidcAlgoTokenMap |
| `TestOIDCProbe_RSAKeySizeFromModulus` | Known `n` modulus → KeySize=2048 correctly derived |
| `TestOIDCProbe_DiscoveryNotFound` | 404 → no findings, no error |
| `TestOIDCProbe_JWKSFetchFails` | Discovery OK, JWKS 500 → advertised findings emitted, JWK findings absent |
| `TestOIDCProbe_MalformedJSON` | Invalid JSON → no findings, no panic |
| `TestOIDCProbe_Timeout` | Context cancelled → clean termination |
| `TestOIDCProbe_NoAlgOnKey` | Missing `alg` → infer from `kty`+`crv` (EC+P-256→ECDSA-P256) |
| `TestOIDCProbe_SkipsEncryptionKeys` | `use: "enc"` → skip |
| `TestOIDCProbe_RedactionNoCredsInFindings` | No HTTP auth headers leak into findings |

### 5.2 BuildConfig tests

| Test | What it verifies |
|---|---|
| `TestBuildConfig_OIDCEndpointInjectsModule` | `--oidc-endpoint` → `oidc_probe` in modules |
| `TestBuildConfig_OIDCEndpointAddsTarget` | URL → `TargetNetwork` entry |
| `TestBuildConfig_OIDCDoesNotSuppressFilesystem` | Filesystem defaults preserved alongside OIDC targets |

### 5.3 Coverage target

`oidc_probe.go` ≥ 85% line coverage.

---

## 6. Edge cases

- **No `alg` on JWK key:** Infer from `kty`+`crv`. `RSA`→`RSA`, `EC`+`P-256`→`ECDSA-P256`, `OKP`+`Ed25519`→`Ed25519`. If inference fails → `Algorithm: "UNKNOWN"`.
- **Duplicate algorithms across fields:** Deduplicate before emitting. One finding per unique advertised algorithm.
- **`alg: "none"`:** Skip entirely. Not a crypto asset.
- **`use: "enc"`:** Skip. Encryption keys are not PQC-relevant for auth signing.
- **HTTP endpoint:** Probe succeeds but emit a warning finding noting insecure transport.
- **Response > 1 MB:** Read capped via `io.LimitReader`. Truncated response → parse fails → no findings.
- **Redirect loops:** `http.Client` follows up to 3 redirects (configurable via `CheckRedirect`).
- **Empty JWKS:** Valid response with `{"keys": []}` → only advertised-algorithm findings emitted.
- **Non-OIDC target:** `Scan()` skips any `TargetNetwork` entry without `https://` or `http://` prefix — protocol scanner's `host:port` targets pass through silently.

---

## 7. Dependencies

Zero new Go module dependencies. Uses only:
- `net/http` — HTTP client
- `encoding/json` — JSON parsing
- `encoding/base64` — RSA modulus decoding
- `crypto/tls` — TLS config for HTTPS (stdlib)
- `io` — `LimitReader` for response cap

---

## 8. Migration / compatibility

- **No schema migration:** Findings use existing columns (`algorithm`, `key_size`, `module`, `file_path` → empty for network findings). The `FindingSource.Endpoint` field already exists in the model.
- **No profile changes:** `oidc_probe` is not added to any default profile. Only runs when `--oidc-endpoint` is explicitly set.
- **Backward compatible:** existing scans unaffected. New flag is opt-in.

---

## 9. Documentation updates

- **README.md** — add "Probing OIDC identity providers" subsection under Usage with `--oidc-endpoint` example
- **docs/SYSTEM_ARCHITECTURE.md** — add subsection describing OIDC probe flow + oidcAlgoTokenMap
- **MEMORY.md** — completion marker for Wave 2 §6.2

---

## 10. Estimated effort

~3 days:
- Day 1: Module skeleton + oidcAlgoTokenMap + happy-path test (TDD)
- Day 2: Discovery/JWKS fetch + all unit tests + edge cases
- Day 3: CLI flag + BuildConfig wiring + docs + code review

---

## 11. Success criteria

- All unit tests pass (`make test`)
- `go build ./...` and `go vet ./...` clean
- `oidc_probe.go` ≥ 85% coverage
- Manual smoke: `triton --oidc-endpoint <real-idp-url>` emits JWK key findings with correct algorithm + key size
- Licence tier test: free tier + `--oidc-endpoint` → target dropped with warning
- Code review signed off
- PR merged via CI
