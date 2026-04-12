# Live Kubernetes Cluster Scanner — Design Spec

**Date:** 2026-04-12
**Parent roadmap:** `docs/plans/2026-04-11-scanner-gaps-roadmap.md` (Wave 1 §5.2)
**Status:** Design approved, pending spec review before implementation plan.

> **For Claude:** After this spec is approved by the user, invoke `superpowers:writing-plans` to produce the step-by-step implementation plan. Do NOT invoke any other skill.

---

## 1. Goal

Add a live Kubernetes cluster scanner that connects to a cluster via kubeconfig (or in-cluster SA), enumerates crypto-relevant resources (TLS secrets, ingress TLS bindings, webhook CA bundles, cluster CA, cert-manager CRDs), and emits PQC-classified findings. This is the second consumer of the Wave 0 `TargetKubernetesCluster` infrastructure and closes the largest remaining cloud-native blind spot.

**Success looks like:** `triton --kubeconfig ~/.kube/config --k8s-context prod` connects to the cluster, enumerates TLS secrets, ingresses, webhooks, cluster CA, and cert-manager resources (if installed), emitting one finding per crypto asset with algorithm, key size, and resource location, all routed through the existing policy engine and CycloneDX CBOM output.

**Effort:** ~2 weeks focused work. One new scanner module, one new CLI flag (`--k8s-namespace`), one new Go dependency (`k8s.io/client-go`).

---

## 2. Scope

### In scope

- New scanner module `pkg/scanner/k8s_live.go` implementing `Module` interface
- `k8sClientFactory` + `k8sClient` interfaces for testability (production: `kubernetes.Clientset` + dynamic client; tests: fake struct)
- Intermediate types decoupling k8s API responses from finding emission
- Resource enumeration:
  - `Secret` where `type: kubernetes.io/tls` — decode `tls.crt` and parse `tls.key` for algorithm + key size
  - `Ingress.spec.tls` — cross-reference to Secret, record hostname→cert binding
  - `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` — decode `caBundle` inline PEM
  - `ConfigMap` named `kube-root-ca.crt` — decode cluster CA cert
  - cert-manager `Certificate` / `Issuer` / `ClusterIssuer` CRDs — extract `spec.privateKey.algorithm` + size, issuer ref
- cert-manager detection via `discovery.ServerGroups()` — skip gracefully if API group absent
- Namespace scoping: all namespaces by default, optional `--k8s-namespace` filter
- Pagination via `ListOptions{Limit: 500}` for large clusters
- Security: never serialize raw Secret.data; parse key material in memory for algo identification, discard immediately
- New CLI flag `--k8s-namespace` (String)
- `BuildConfig` injects `k8s_live` module when `--kubeconfig` is set (extend existing k8sMode logic)
- Licence tier: Enterprise-only (already wired in Wave 0)
- Register module in `engine.go::RegisterDefaultModules`
- Unit tests with fake k8sClient (14 test cases)
- BuildConfig tests (3 test cases)
- RBAC ClusterRole YAML in deployment guide
- Documentation updates

### Out of scope

- ServiceAccount token inspection (already in `container_signatures.go`)
- Kubelet cert paths / node-level scanning (requires elevated node access)
- Pod-mounted secret enumeration (requires `pods` list RBAC)
- Helm release secret decryption
- etcd direct access (already in `container_signatures.go` for static config)
- Real-cluster integration test in CI (deferred — needs KinD/k3s infra)
- Server-mode k8s scanning (API handler changes deferred)
- Multi-cluster federation
- mTLS-based kubelet scanning
- Custom CRDs beyond cert-manager

---

## 3. Architecture

### 3.1 Module interface

```go
type K8sLiveModule struct {
    config        *scannerconfig.Config
    clientFactory k8sClientFactory
    lastScanned   int64
    lastMatched   int64
}

func (m *K8sLiveModule) Name() string                         { return "k8s_live" }
func (m *K8sLiveModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *K8sLiveModule) ScanTargetType() model.ScanTargetType { return model.TargetKubernetesCluster }
```

Uses `TargetKubernetesCluster` (enum value 7, defined in Wave 0). Category is `CategoryActiveNetwork` since it makes outbound API calls to a live cluster.

### 3.2 Testability interfaces

```go
type k8sClientFactory interface {
    NewClient(kubeconfig, context string) (k8sClient, error)
}

type k8sClient interface {
    ListTLSSecrets(ctx context.Context, namespace string) ([]k8sTLSSecret, error)
    ListIngresses(ctx context.Context, namespace string) ([]k8sIngress, error)
    ListWebhookConfigs(ctx context.Context) ([]k8sWebhookConfig, error)
    ListConfigMaps(ctx context.Context, namespace, name string) ([]k8sConfigMap, error)
    ListCertManagerCertificates(ctx context.Context, namespace string) ([]k8sCertManagerCert, error)
    ListCertManagerIssuers(ctx context.Context, namespace string) ([]k8sCertManagerIssuer, error)
    ListCertManagerClusterIssuers(ctx context.Context) ([]k8sCertManagerIssuer, error)
    HasAPIGroup(group string) (bool, error)
}
```

Production implementation wraps `kubernetes.Clientset` for core resources + dynamic client for cert-manager CRDs. Tests inject a `fakeK8sClient` returning pre-built structs.

### 3.3 Scan flow

```
1. Construct k8s client from kubeconfig + context (or in-cluster config)
2. Resolve namespace: "" (all) or the --k8s-namespace value
3. Enumerate core resources (parallel-safe, sequential for v1):
   a. ListTLSSecrets(namespace) → parse each tls.crt + tls.key → emit cert + key findings
   b. ListIngresses(namespace) → emit hostname→secret binding findings
   c. ListWebhookConfigs() → decode caBundle PEM → emit cert findings
   d. ListConfigMaps(namespace, "kube-root-ca.crt") → decode ca.crt → emit cert finding
4. Discovery check: HasAPIGroup("cert-manager.io")
   If true:
   e. ListCertManagerCertificates(namespace) → emit algorithm + key size findings
   f. ListCertManagerIssuers(namespace) → emit issuer findings
   g. ListCertManagerClusterIssuers() → emit issuer findings
5. Each resource error is logged and skipped — one failing list does not abort the scan
```

### 3.4 Intermediate types

```go
type k8sTLSSecret struct {
    Namespace string
    Name      string
    CertPEM   []byte
    KeyPEM    []byte
}

type k8sIngress struct {
    Namespace string
    Name      string
    TLSHosts  []k8sIngressTLS
}

type k8sIngressTLS struct {
    Hosts      []string
    SecretName string
}

type k8sWebhookConfig struct {
    Name     string
    Kind     string // ValidatingWebhookConfiguration or MutatingWebhookConfiguration
    CABundle []byte
}

type k8sConfigMap struct {
    Namespace string
    Name      string
    CACertPEM []byte
}

type k8sCertManagerCert struct {
    Namespace  string
    Name       string
    SecretName string
    Algorithm  string
    KeySize    int
    IssuerRef  string
}

type k8sCertManagerIssuer struct {
    Namespace string
    Name      string
    Kind      string // Issuer or ClusterIssuer
    CASecret  string
}
```

These decouple k8s API response parsing from finding emission. The `k8sClient` implementation translates raw API objects to these types; `Scan()` only works with these.

### 3.5 Cert/key parsing

TLS cert PEM from secrets and webhook `caBundle` are parsed using `crypto/x509.ParseCertificate` directly (same approach as `container_signatures.go`). Private key PEM is parsed via `crypto/x509.ParsePKCS8PrivateKey` / `ParseECPrivateKey` / `ParsePKCS1PrivateKey` to identify algorithm and key size — the parsed key object is immediately discarded after extracting metadata. Raw bytes are never stored in findings.

### 3.6 Finding emission

| Resource | Category | Confidence | DetectionMethod | Source.Endpoint format |
|---|---|---|---|---|
| TLS Secret cert | 5 (PKI) | 0.95 | `"kubernetes-api"` | `<context>/<ns>/Secret/<name>` |
| TLS Secret key | 5 (PKI) | 0.95 | `"kubernetes-api"` | `<context>/<ns>/Secret/<name>` |
| Ingress TLS binding | 8 (network) | 0.80 | `"kubernetes-api"` | `<context>/<ns>/Ingress/<name>` |
| Webhook caBundle | 5 (PKI) | 0.90 | `"kubernetes-api"` | `<context>/<kind>/<name>` |
| kube-root-ca.crt | 5 (PKI) | 0.95 | `"kubernetes-api"` | `<context>/<ns>/ConfigMap/kube-root-ca.crt` |
| cert-manager Certificate | 5 (PKI) | 0.85 | `"kubernetes-api"` | `<context>/<ns>/Certificate/<name>` |
| cert-manager Issuer | 5 (PKI) | 0.80 | `"kubernetes-api"` | `<context>/<ns>/Issuer/<name>` |

`FindingSource.Type` is `"kubernetes"` for all k8s-live findings.

### 3.7 Namespace resolution

- `--k8s-namespace prod` → pass `"prod"` to all namespaced list calls
- No `--k8s-namespace` → pass `""` to list calls (client-go treats `""` as all namespaces)
- Cluster-scoped resources (`ClusterIssuer`, webhook configs) always enumerate regardless of namespace filter

### 3.8 Pagination

All list calls use `ListOptions{Limit: 500}` with client-go's built-in pager (`pager.New(pager.SimplePageFunc(...))`) to handle clusters with 10k+ secrets without OOM.

### 3.9 CLI flag + BuildConfig wiring

New flag on `cmd/root.go`:

```go
rootCmd.PersistentFlags().StringVar(&k8sNamespace, "k8s-namespace", "",
    "Kubernetes namespace to scan (default: all namespaces)")
```

`BuildOptions` gains `K8sNamespace string`. `BuildConfig` passes it through to `Config`. The existing k8sMode block already injects `TargetKubernetesCluster` and strips filesystem defaults.

`BuildConfig` must also inject `k8s_live` into `cfg.Modules` when k8sMode is true (same pattern as `oci_image` injection for imageMode). This was NOT implemented in Wave 0 — the OCI image fix (commit 4e1bb0d) only handled `oci_image`. Must be added now.

### 3.10 Licence tier

`k8s_live` is already Enterprise-only in `internal/license/tier.go` (not in `proModules()`). `FilterConfig` already drops `TargetKubernetesCluster` targets for non-Enterprise tiers with a warning log. No tier changes needed.

---

## 4. Dependencies

```
k8s.io/client-go    // Kubernetes API client
k8s.io/apimachinery  // API object types, runtime, schema
k8s.io/api           // Core API types (corev1, networkingv1, etc.)
```

Heavy transitive tree (~200 deps). All Apache 2.0 licensed, standard for Go Kubernetes tooling. Same libraries used by kubectl, Helm, ArgoCD, Flux.

---

## 5. Testing strategy

### 5.1 Unit tests with fake k8sClient

All tests inject a `fakeK8sClient` implementing the `k8sClient` interface. No real cluster, no `k8s.io/client-go/fake`.

| Test | What it verifies |
|---|---|
| `TestK8sLive_ModuleInterface` | Name, Category, ScanTargetType |
| `TestK8sLive_TLSSecretFindings` | 2 secrets → cert + key findings with correct algo + size |
| `TestK8sLive_IngressTLSBinding` | Ingress with TLS hosts → finding with hostname |
| `TestK8sLive_WebhookCABundle` | Webhook with RSA-2048 CA → finding |
| `TestK8sLive_KubeRootCA` | kube-root-ca.crt → cluster CA finding |
| `TestK8sLive_CertManagerCertificate` | Certificate with ECDSA-P384 → finding |
| `TestK8sLive_CertManagerIssuer` | Issuer with CA ref → finding |
| `TestK8sLive_CertManagerNotInstalled` | HasAPIGroup returns false → zero cert-manager findings |
| `TestK8sLive_NamespaceFilter` | K8sNamespace="prod" → only prod resources |
| `TestK8sLive_AllNamespaces` | No filter → "" passed to list calls |
| `TestK8sLive_EmptyCluster` | All lists empty → zero findings |
| `TestK8sLive_APIError` | One list fails → others still run |
| `TestK8sLive_NeverSerializesSecretData` | No raw PEM in marshalled findings |
| `TestK8sLive_SkipsNonK8sTarget` | TargetNetwork target → nil, zero findings |

### 5.2 BuildConfig tests

| Test | What it verifies |
|---|---|
| `TestBuildConfig_KubeconfigInjectsK8sLiveModule` | k8sMode → `k8s_live` in Modules |
| `TestBuildConfig_K8sNamespacePassedThrough` | Namespace value propagated to Config |
| `TestBuildConfig_K8sAndImageMixingError` | Already tested, verify still holds |

### 5.3 Integration test

Deferred. Requires KinD/k3s cluster in CI with pre-seeded secrets. Track for follow-up when CI infrastructure supports ephemeral clusters.

### 5.4 Coverage target

`k8s_live.go` ≥ 85% line coverage. 14 unit tests + 3 BuildConfig tests.

---

## 6. Edge cases

- **Invalid kubeconfig path:** `NewClient()` returns error → `Scan()` returns error (user explicitly asked for k8s scan, silent skip would be confusing)
- **Unauthorized (403):** per-resource list returns forbidden → skip that resource, continue others, emit warning finding noting inaccessible resources
- **Malformed PEM in Secret:** `x509.ParseCertificate` fails → skip, emit warning finding with Secret name
- **Secret with no `tls.crt` key:** skip (not a valid TLS secret despite type label)
- **Webhook with empty caBundle:** skip (some webhooks use `url` instead of `service` + `caBundle`)
- **cert-manager CRDs exist but no resources:** valid empty result → zero findings
- **Large cluster (10k+ secrets):** pagination via `ListOptions{Limit: 500}`
- **In-cluster SA detection:** when kubeconfig is empty, `rest.InClusterConfig()` is used (for scanning from inside a pod)
- **Context cancellation:** all list calls use `ctx` from `Scan()` — cancellation propagates cleanly

---

## 7. RBAC documentation

Deployment guide section with recommended ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: triton-scanner
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["list", "get"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["list"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
  verbs: ["list"]
- apiGroups: ["cert-manager.io"]
  resources: ["certificates", "issuers", "clusterissuers"]
  verbs: ["list"]
```

Security note: "Triton extracts algorithm, key size, and subject metadata from TLS secrets. Raw private key material is parsed in memory for algorithm identification and immediately discarded — it is never written to disk, logs, findings, or reports."

---

## 8. Migration / compatibility

- **No schema migration:** findings use existing columns. `FindingSource.Endpoint` carries the `<context>/<ns>/<kind>/<name>` path.
- **No profile changes:** `k8s_live` not in any default profile. Only runs when `--kubeconfig` is set.
- **Backward compatible:** existing scans unaffected. New flag is opt-in.
- **BuildConfig k8s_live injection:** must be added (Wave 0 wired the target type and filesystem suppression, but did not inject the module into cfg.Modules — same bug pattern as oci_image, fixed in 4e1bb0d).

---

## 9. Documentation updates

- **README.md** — "Scanning Kubernetes clusters" usage subsection with examples
- **docs/SYSTEM_ARCHITECTURE.md** — K8s live scanner subsection describing scan flow + resource types
- **docs/DEPLOYMENT_GUIDE.md** — ClusterRole YAML, ServiceAccount binding example, security note
- **MEMORY.md** — completion marker for Wave 1 §5.2
- **scanner-coverage-gaps.md** — mark Wave 1 §5.2 ✅, module count 30→31

---

## 10. Estimated effort

~2 weeks:
- Days 1–3: k8sClient interface + fake + intermediate types + TLS secret parsing (TDD)
- Days 4–6: Ingress, webhook, configmap, cert-manager enumeration + tests
- Days 7–8: Production clientFactory (real client-go wiring) + in-cluster detection
- Days 9–10: CLI flag + BuildConfig + engine registration + RBAC docs + code review
