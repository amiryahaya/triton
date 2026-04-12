# Live Kubernetes Cluster Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a live Kubernetes cluster scanner that connects via kubeconfig, enumerates TLS secrets, ingresses, webhook CA bundles, cluster CA, and cert-manager CRDs, and emits PQC-classified findings.

**Architecture:** Single new module `pkg/scanner/k8s_live.go` implementing `Module` with `TargetKubernetesCluster`. Testability via `k8sClient` interface (fake in tests, real `kubernetes.Clientset` in production). Real client-go code isolated in `pkg/scanner/k8s_live_client.go`. Cert/key PEM parsing uses stdlib `crypto/x509` directly. Resource enumeration is sequential with per-resource error resilience.

**Tech Stack:** Go 1.25, `k8s.io/client-go` + `k8s.io/apimachinery` + `k8s.io/api` (new deps), `crypto/x509` (stdlib).

**Spec:** `docs/plans/2026-04-12-k8s-live-scanner-design.md`

---

## File Structure

### Created

| File | Responsibility |
|---|---|
| `pkg/scanner/k8s_live.go` | `K8sLiveModule` + `k8sClient` interface + intermediate types + PEM parsing helpers + finding emission |
| `pkg/scanner/k8s_live_test.go` | Unit tests with `fakeK8sClient` |
| `pkg/scanner/k8s_live_client.go` | Production `realK8sClientFactory` + `realK8sClient` wrapping `kubernetes.Clientset` — only file importing `k8s.io/*` |

### Modified

| File | Change |
|---|---|
| `internal/scannerconfig/config.go` | +`K8sNamespace` field on `BuildOptions` + `Config`; `BuildConfig` injects `k8s_live` module when k8sMode |
| `internal/scannerconfig/config_test.go` | +3 BuildConfig k8s tests |
| `cmd/root.go` | +`--k8s-namespace` flag; wire into `BuildOptions` |
| `pkg/scanner/engine.go` | +`RegisterModule(NewK8sLiveModule)` |
| `go.mod` / `go.sum` | +`k8s.io/client-go`, `k8s.io/apimachinery`, `k8s.io/api` |
| `README.md` | +"Scanning Kubernetes clusters" usage subsection |
| `docs/SYSTEM_ARCHITECTURE.md` | +K8s live scanner subsection |
| `docs/DEPLOYMENT_GUIDE.md` | +ClusterRole YAML + security note |

### Boundaries

- `k8s_live.go` owns the module interface, intermediate types, PEM parsing, finding emission, and scan orchestration. It does NOT import `k8s.io/*` — it only works with the `k8sClient` interface and intermediate types.
- `k8s_live_client.go` is the ONLY file importing `k8s.io/*`. It translates raw k8s API objects to intermediate types. If client-go is ever swapped, the blast radius is one file.
- `k8s_live_test.go` uses a `fakeK8sClient` — no real cluster, no `k8s.io/client-go/fake`.

---

## Task 1: `k8sClient` interface + intermediate types + `fakeK8sClient`

**Files:**
- Create: `pkg/scanner/k8s_live.go`
- Create: `pkg/scanner/k8s_live_test.go`

- [ ] **Step 1: Write failing test that uses the interface**

Create `pkg/scanner/k8s_live_test.go`:

```go
package scanner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeK8sClient struct {
	tlsSecrets        []k8sTLSSecret
	ingresses         []k8sIngress
	webhookConfigs    []k8sWebhookConfig
	configMaps        []k8sConfigMap
	certManagerCerts  []k8sCertManagerCert
	certManagerIssuers []k8sCertManagerIssuer
	clusterIssuers    []k8sCertManagerIssuer
	hasAPIGroups      map[string]bool
	listErrors        map[string]error // keyed by resource name for selective failure
}

func (f *fakeK8sClient) ListTLSSecrets(ctx context.Context, namespace string) ([]k8sTLSSecret, error) {
	if err, ok := f.listErrors["secrets"]; ok {
		return nil, err
	}
	if namespace == "" {
		return f.tlsSecrets, nil
	}
	var filtered []k8sTLSSecret
	for _, s := range f.tlsSecrets {
		if s.Namespace == namespace {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

func (f *fakeK8sClient) ListIngresses(ctx context.Context, namespace string) ([]k8sIngress, error) {
	if err, ok := f.listErrors["ingresses"]; ok {
		return nil, err
	}
	if namespace == "" {
		return f.ingresses, nil
	}
	var filtered []k8sIngress
	for _, ing := range f.ingresses {
		if ing.Namespace == namespace {
			filtered = append(filtered, ing)
		}
	}
	return filtered, nil
}

func (f *fakeK8sClient) ListWebhookConfigs(ctx context.Context) ([]k8sWebhookConfig, error) {
	if err, ok := f.listErrors["webhooks"]; ok {
		return nil, err
	}
	return f.webhookConfigs, nil
}

func (f *fakeK8sClient) ListConfigMaps(ctx context.Context, namespace, name string) ([]k8sConfigMap, error) {
	if err, ok := f.listErrors["configmaps"]; ok {
		return nil, err
	}
	var filtered []k8sConfigMap
	for _, cm := range f.configMaps {
		if (namespace == "" || cm.Namespace == namespace) && cm.Name == name {
			filtered = append(filtered, cm)
		}
	}
	return filtered, nil
}

func (f *fakeK8sClient) ListCertManagerCertificates(ctx context.Context, namespace string) ([]k8sCertManagerCert, error) {
	if err, ok := f.listErrors["certificates"]; ok {
		return nil, err
	}
	if namespace == "" {
		return f.certManagerCerts, nil
	}
	var filtered []k8sCertManagerCert
	for _, c := range f.certManagerCerts {
		if c.Namespace == namespace {
			filtered = append(filtered, c)
		}
	}
	return filtered, nil
}

func (f *fakeK8sClient) ListCertManagerIssuers(ctx context.Context, namespace string) ([]k8sCertManagerIssuer, error) {
	if err, ok := f.listErrors["issuers"]; ok {
		return nil, err
	}
	if namespace == "" {
		return f.certManagerIssuers, nil
	}
	var filtered []k8sCertManagerIssuer
	for _, iss := range f.certManagerIssuers {
		if iss.Namespace == namespace {
			filtered = append(filtered, iss)
		}
	}
	return filtered, nil
}

func (f *fakeK8sClient) ListCertManagerClusterIssuers(ctx context.Context) ([]k8sCertManagerIssuer, error) {
	if err, ok := f.listErrors["clusterissuers"]; ok {
		return nil, err
	}
	return f.clusterIssuers, nil
}

func (f *fakeK8sClient) HasAPIGroup(group string) (bool, error) {
	if f.hasAPIGroups == nil {
		return false, nil
	}
	return f.hasAPIGroups[group], nil
}

func TestK8sLive_FakeClientWorks(t *testing.T) {
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "default", Name: "my-tls", CertPEM: []byte("cert"), KeyPEM: []byte("key")},
		},
		hasAPIGroups: map[string]bool{"cert-manager.io": true},
	}
	secrets, err := fc.ListTLSSecrets(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
	assert.Equal(t, "my-tls", secrets[0].Name)

	has, err := fc.HasAPIGroup("cert-manager.io")
	require.NoError(t, err)
	assert.True(t, has)
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `go test -v -run TestK8sLive_FakeClient ./pkg/scanner/`
Expected: FAIL — `undefined: k8sTLSSecret`, `undefined: k8sClient`, etc.

- [ ] **Step 3: Create k8s_live.go with interface + types**

Create `pkg/scanner/k8s_live.go`:

```go
package scanner

import "context"

// k8sClientFactory creates k8sClient instances from kubeconfig.
type k8sClientFactory interface {
	NewClient(kubeconfig, context string) (k8sClient, error)
}

// k8sClient abstracts Kubernetes API calls for testability.
// Production implementation wraps kubernetes.Clientset and lives
// in k8s_live_client.go. Tests use fakeK8sClient in k8s_live_test.go.
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

- [ ] **Step 4: Run test — expect PASS**

Run: `go test -v -run TestK8sLive_FakeClient ./pkg/scanner/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/k8s_live.go pkg/scanner/k8s_live_test.go
git commit -m "feat(scanner): k8sClient interface + intermediate types + fakeK8sClient"
```

---

## Task 2: Module skeleton + TLS secret scanning

**Files:**
- Modify: `pkg/scanner/k8s_live.go`
- Modify: `pkg/scanner/k8s_live_test.go`

- [ ] **Step 1: Write failing module interface + TLS secret tests**

Append to `k8s_live_test.go`:

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// testCertPEM generates a self-signed ECDSA-P256 cert + key PEM for tests.
func testCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestK8sLive_ModuleInterface(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, nil)
	assert.Equal(t, "k8s_live", m.Name())
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
	assert.Equal(t, model.TargetKubernetesCluster, m.ScanTargetType())
}

func TestK8sLive_TLSSecretFindings(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)

	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "default", Name: "my-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	err := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetKubernetesCluster,
		Value: "/fake/kubeconfig",
	}, findings)
	close(findings)
	<-done

	require.NoError(t, err)
	require.GreaterOrEqual(t, len(collected), 2, "expected cert + key findings")

	var hasCert, hasKey bool
	for _, f := range collected {
		require.NotNil(t, f.CryptoAsset)
		assert.Equal(t, "kubernetes-api", f.Source.DetectionMethod)
		assert.Equal(t, "kubernetes", f.Source.Type)
		assert.Contains(t, f.Source.Endpoint, "default/Secret/my-tls")
		if f.CryptoAsset.Function == "TLS certificate" {
			hasCert = true
			assert.Equal(t, "ECDSA-P256", f.CryptoAsset.Algorithm)
		}
		if f.CryptoAsset.Function == "TLS private key" {
			hasKey = true
			assert.Equal(t, "ECDSA-P256", f.CryptoAsset.Algorithm)
		}
	}
	assert.True(t, hasCert, "expected cert finding")
	assert.True(t, hasKey, "expected key finding")
}
```

Also add the fake factory:

```go
type fakeK8sClientFactory struct {
	client k8sClient
	err    error
}

func (f *fakeK8sClientFactory) NewClient(kubeconfig, ctx string) (k8sClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}
```

Merge all imports into a single block at the top. Ensure `"github.com/google/uuid"` is NOT imported in the test — the module code imports it, not the test.

- [ ] **Step 2: Run tests — expect FAIL**

Run: `go test -v -run "TestK8sLive_Module|TestK8sLive_TLSSecret" ./pkg/scanner/`
Expected: FAIL — `undefined: newK8sLiveModuleWithFactory`, `undefined: K8sLiveModule`

- [ ] **Step 3: Implement module skeleton + TLS secret scanning**

Append to `pkg/scanner/k8s_live.go`:

```go
import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// K8sLiveModule scans a live Kubernetes cluster by enumerating
// crypto-relevant resources via the Kubernetes API.
type K8sLiveModule struct {
	config        *scannerconfig.Config
	clientFactory k8sClientFactory
	lastScanned   int64
	lastMatched   int64
}

// NewK8sLiveModule returns a module with the production client factory.
func NewK8sLiveModule(cfg *scannerconfig.Config) *K8sLiveModule {
	return &K8sLiveModule{
		config:        cfg,
		clientFactory: newRealK8sClientFactory(),
	}
}

// newK8sLiveModuleWithFactory is the test-friendly constructor.
func newK8sLiveModuleWithFactory(cfg *scannerconfig.Config, factory k8sClientFactory) *K8sLiveModule {
	return &K8sLiveModule{
		config:        cfg,
		clientFactory: factory,
	}
}

func (m *K8sLiveModule) Name() string                         { return "k8s_live" }
func (m *K8sLiveModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *K8sLiveModule) ScanTargetType() model.ScanTargetType { return model.TargetKubernetesCluster }

func (m *K8sLiveModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *K8sLiveModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Type != model.TargetKubernetesCluster {
		return nil
	}

	atomic.AddInt64(&m.lastScanned, 1)

	client, err := m.clientFactory.NewClient(
		m.config.Credentials.Kubeconfig,
		m.config.Credentials.K8sContext,
	)
	if err != nil {
		return fmt.Errorf("k8s_live: connect: %w", err)
	}

	k8sCtx := m.config.Credentials.K8sContext
	if k8sCtx == "" {
		k8sCtx = "default"
	}
	namespace := m.config.K8sNamespace

	// TLS Secrets
	m.scanTLSSecrets(ctx, client, k8sCtx, namespace, findings)

	// Ingresses
	m.scanIngresses(ctx, client, k8sCtx, namespace, findings)

	// Webhook configurations
	m.scanWebhookConfigs(ctx, client, k8sCtx, findings)

	// kube-root-ca.crt ConfigMap
	m.scanRootCA(ctx, client, k8sCtx, namespace, findings)

	// cert-manager CRDs (if installed)
	m.scanCertManager(ctx, client, k8sCtx, namespace, findings)

	return nil
}

func (m *K8sLiveModule) scanTLSSecrets(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	secrets, err := client.ListTLSSecrets(ctx, namespace)
	if err != nil {
		log.Printf("k8s_live: list TLS secrets: %v", err)
		return
	}
	for _, s := range secrets {
		endpoint := fmt.Sprintf("%s/%s/Secret/%s", k8sCtx, s.Namespace, s.Name)
		m.parseCertPEM(ctx, s.CertPEM, endpoint, "TLS certificate", findings)
		m.parseKeyPEM(ctx, s.KeyPEM, endpoint, "TLS private key", findings)
	}
}

func (m *K8sLiveModule) parseCertPEM(ctx context.Context, pemData []byte, endpoint, function string, findings chan<- *model.Finding) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	algo, keySize := classifyCertKey(cert)
	asset := &model.CryptoAsset{
		Algorithm: algo,
		KeySize:   keySize,
		Purpose:   "authentication",
		Function:  function,
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: &cert.NotBefore,
		NotAfter:  &cert.NotAfter,
		IsCA:      cert.IsCA,
	}
	crypto.ClassifyCryptoAsset(asset)
	m.emitFinding(ctx, endpoint, asset, 0.95, findings)
}

func (m *K8sLiveModule) parseKeyPEM(ctx context.Context, pemData []byte, endpoint, function string, findings chan<- *model.Finding) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return
	}
	algo, keySize := classifyKeyDER(block.Bytes)
	if algo == "" {
		return
	}
	asset := &model.CryptoAsset{
		Algorithm: algo,
		KeySize:   keySize,
		Purpose:   "authentication",
		Function:  function,
	}
	crypto.ClassifyCryptoAsset(asset)
	m.emitFinding(ctx, endpoint, asset, 0.95, findings)
}

func classifyCertKey(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-P%d", pub.Curve.Params().BitSize), pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "UNKNOWN", 0
}

func classifyKeyDER(der []byte) (string, int) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return "RSA", k.N.BitLen()
		case *ecdsa.PrivateKey:
			return fmt.Sprintf("ECDSA-P%d", k.Curve.Params().BitSize), k.Curve.Params().BitSize
		case ed25519.PrivateKey:
			return "Ed25519", 256
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return fmt.Sprintf("ECDSA-P%d", key.Curve.Params().BitSize), key.Curve.Params().BitSize
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return "RSA", key.N.BitLen()
	}
	return "", 0
}

func (m *K8sLiveModule) emitFinding(ctx context.Context, endpoint string, asset *model.CryptoAsset, confidence float64, findings chan<- *model.Finding) {
	atomic.AddInt64(&m.lastMatched, 1)
	select {
	case findings <- &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type:            "kubernetes",
			Endpoint:        endpoint,
			DetectionMethod: "kubernetes-api",
		},
		CryptoAsset: asset,
		Confidence:  confidence,
		Module:      "k8s_live",
		Timestamp:   time.Now(),
	}:
	case <-ctx.Done():
	}
}
```

Also add stubs for the remaining scan methods so it compiles:

```go
func (m *K8sLiveModule) scanIngresses(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

func (m *K8sLiveModule) scanWebhookConfigs(ctx context.Context, client k8sClient, k8sCtx string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

func (m *K8sLiveModule) scanRootCA(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

func (m *K8sLiveModule) scanCertManager(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 4
}
```

Also stub the production factory so it compiles (real impl in Task 6):

```go
func newRealK8sClientFactory() k8sClientFactory {
	return &stubK8sClientFactory{}
}

type stubK8sClientFactory struct{}

func (s *stubK8sClientFactory) NewClient(kubeconfig, ctx string) (k8sClient, error) {
	return nil, fmt.Errorf("k8s_live: real client factory not yet implemented (Task 6)")
}
```

Also add `K8sNamespace` field to `Config` if it doesn't exist yet. Check `internal/scannerconfig/config.go` — the `Config` struct needs:

```go
K8sNamespace string
```

Append this field at the end of the `Config` struct in `config.go`.

- [ ] **Step 4: Run tests — expect PASS**

Run: `go test -v -run "TestK8sLive" ./pkg/scanner/`
Expected: FakeClient, ModuleInterface, TLSSecretFindings — all PASS

Run: `go build ./...` — zero errors

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/k8s_live.go pkg/scanner/k8s_live_test.go internal/scannerconfig/config.go
git commit -m "feat(scanner): K8sLiveModule skeleton + TLS secret scanning"
```

---

## Task 3: Ingress + webhook + ConfigMap scanning

**Files:**
- Modify: `pkg/scanner/k8s_live.go`
- Modify: `pkg/scanner/k8s_live_test.go`

- [ ] **Step 1: Write failing tests**

Append to `k8s_live_test.go`:

```go
func TestK8sLive_IngressTLSBinding(t *testing.T) {
	fc := &fakeK8sClient{
		ingresses: []k8sIngress{
			{
				Namespace: "default",
				Name:      "my-ingress",
				TLSHosts: []k8sIngressTLS{
					{Hosts: []string{"app.example.com"}, SecretName: "app-tls"},
				},
			},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	require.Len(t, collected, 1)
	assert.Equal(t, 8, collected[0].Category)
	assert.Equal(t, 0.80, collected[0].Confidence)
	assert.Contains(t, collected[0].Source.Endpoint, "Ingress/my-ingress")
	assert.Contains(t, collected[0].CryptoAsset.Function, "app.example.com")
}

func TestK8sLive_WebhookCABundle(t *testing.T) {
	certPEM, _ := testCertPEM(t)
	fc := &fakeK8sClient{
		webhookConfigs: []k8sWebhookConfig{
			{Name: "my-webhook", Kind: "ValidatingWebhookConfiguration", CABundle: certPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	require.GreaterOrEqual(t, len(collected), 1)
	assert.Equal(t, 0.90, collected[0].Confidence)
	assert.Contains(t, collected[0].Source.Endpoint, "ValidatingWebhookConfiguration/my-webhook")
}

func TestK8sLive_KubeRootCA(t *testing.T) {
	certPEM, _ := testCertPEM(t)
	fc := &fakeK8sClient{
		configMaps: []k8sConfigMap{
			{Namespace: "kube-system", Name: "kube-root-ca.crt", CACertPEM: certPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	require.GreaterOrEqual(t, len(collected), 1)
	assert.Equal(t, 0.95, collected[0].Confidence)
	assert.Contains(t, collected[0].Source.Endpoint, "ConfigMap/kube-root-ca.crt")
}
```

- [ ] **Step 2: Run — expect FAIL** (stub methods emit no findings)

- [ ] **Step 3: Implement scanIngresses, scanWebhookConfigs, scanRootCA**

Replace the stubs in `k8s_live.go`:

```go
func (m *K8sLiveModule) scanIngresses(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	ingresses, err := client.ListIngresses(ctx, namespace)
	if err != nil {
		log.Printf("k8s_live: list ingresses: %v", err)
		return
	}
	for _, ing := range ingresses {
		for _, tls := range ing.TLSHosts {
			endpoint := fmt.Sprintf("%s/%s/Ingress/%s", k8sCtx, ing.Namespace, ing.Name)
			hosts := ""
			if len(tls.Hosts) > 0 {
				hosts = tls.Hosts[0]
				for _, h := range tls.Hosts[1:] {
					hosts += ", " + h
				}
			}
			asset := &model.CryptoAsset{
				Purpose:  "transport",
				Function: fmt.Sprintf("Ingress TLS binding (%s) → Secret/%s", hosts, tls.SecretName),
			}
			m.emitFinding(ctx, endpoint, asset, 0.80, findings)
		}
	}
}

func (m *K8sLiveModule) scanWebhookConfigs(ctx context.Context, client k8sClient, k8sCtx string, findings chan<- *model.Finding) {
	webhooks, err := client.ListWebhookConfigs(ctx)
	if err != nil {
		log.Printf("k8s_live: list webhooks: %v", err)
		return
	}
	for _, wh := range webhooks {
		if len(wh.CABundle) == 0 {
			continue
		}
		endpoint := fmt.Sprintf("%s/%s/%s", k8sCtx, wh.Kind, wh.Name)
		m.parseCertPEM(ctx, wh.CABundle, endpoint, "Webhook CA bundle", findings)
	}
}

func (m *K8sLiveModule) scanRootCA(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	cms, err := client.ListConfigMaps(ctx, namespace, "kube-root-ca.crt")
	if err != nil {
		log.Printf("k8s_live: list configmaps: %v", err)
		return
	}
	for _, cm := range cms {
		if len(cm.CACertPEM) == 0 {
			continue
		}
		endpoint := fmt.Sprintf("%s/%s/ConfigMap/%s", k8sCtx, cm.Namespace, cm.Name)
		m.parseCertPEM(ctx, cm.CACertPEM, endpoint, "Cluster root CA", findings)
	}
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test -v -run "TestK8sLive" ./pkg/scanner/`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/k8s_live.go pkg/scanner/k8s_live_test.go
git commit -m "feat(scanner): k8s ingress, webhook, and root CA scanning"
```

---

## Task 4: cert-manager CRD scanning

**Files:**
- Modify: `pkg/scanner/k8s_live.go`
- Modify: `pkg/scanner/k8s_live_test.go`

- [ ] **Step 1: Write failing tests**

Append to `k8s_live_test.go`:

```go
func TestK8sLive_CertManagerCertificate(t *testing.T) {
	fc := &fakeK8sClient{
		certManagerCerts: []k8sCertManagerCert{
			{Namespace: "default", Name: "my-cert", Algorithm: "ECDSA", KeySize: 384, IssuerRef: "letsencrypt"},
		},
		hasAPIGroups: map[string]bool{"cert-manager.io": true},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	require.GreaterOrEqual(t, len(collected), 1)
	var certFinding *model.Finding
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "cert-manager Certificate" {
			certFinding = f
		}
	}
	require.NotNil(t, certFinding)
	assert.Equal(t, "ECDSA-P384", certFinding.CryptoAsset.Algorithm)
	assert.Equal(t, 384, certFinding.CryptoAsset.KeySize)
	assert.Equal(t, 0.85, certFinding.Confidence)
	assert.Contains(t, certFinding.Source.Endpoint, "Certificate/my-cert")
}

func TestK8sLive_CertManagerIssuer(t *testing.T) {
	fc := &fakeK8sClient{
		certManagerIssuers: []k8sCertManagerIssuer{
			{Namespace: "default", Name: "letsencrypt", Kind: "Issuer", CASecret: "ca-secret"},
		},
		hasAPIGroups: map[string]bool{"cert-manager.io": true},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	var issuerFinding *model.Finding
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "cert-manager Issuer" {
			issuerFinding = f
		}
	}
	require.NotNil(t, issuerFinding)
	assert.Equal(t, 0.80, issuerFinding.Confidence)
	assert.Contains(t, issuerFinding.Source.Endpoint, "Issuer/letsencrypt")
}

func TestK8sLive_CertManagerNotInstalled(t *testing.T) {
	fc := &fakeK8sClient{
		hasAPIGroups: map[string]bool{"cert-manager.io": false},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	assert.Empty(t, collected, "no cert-manager findings when API group absent")
}
```

- [ ] **Step 2: Run — expect FAIL** (scanCertManager is still a stub)

- [ ] **Step 3: Implement scanCertManager**

Replace the stub in `k8s_live.go`:

```go
// certManagerAlgoMap normalizes cert-manager spec.privateKey.algorithm
// values to canonical crypto registry names.
var certManagerAlgoMap = map[string]string{
	"RSA":     "RSA",
	"ECDSA":   "ECDSA",
	"Ed25519": "Ed25519",
}

func (m *K8sLiveModule) scanCertManager(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	has, err := client.HasAPIGroup("cert-manager.io")
	if err != nil {
		log.Printf("k8s_live: check cert-manager API group: %v", err)
		return
	}
	if !has {
		return
	}

	certs, err := client.ListCertManagerCertificates(ctx, namespace)
	if err != nil {
		log.Printf("k8s_live: list cert-manager certificates: %v", err)
	} else {
		for _, c := range certs {
			endpoint := fmt.Sprintf("%s/%s/Certificate/%s", k8sCtx, c.Namespace, c.Name)
			algo := c.Algorithm
			if canonical, ok := certManagerAlgoMap[algo]; ok {
				if canonical == "ECDSA" && c.KeySize > 0 {
					algo = fmt.Sprintf("ECDSA-P%d", c.KeySize)
				} else {
					algo = canonical
				}
			}
			asset := &model.CryptoAsset{
				Algorithm: algo,
				KeySize:   c.KeySize,
				Purpose:   "authentication",
				Function:  "cert-manager Certificate",
			}
			crypto.ClassifyCryptoAsset(asset)
			m.emitFinding(ctx, endpoint, asset, 0.85, findings)
		}
	}

	issuers, err := client.ListCertManagerIssuers(ctx, namespace)
	if err != nil {
		log.Printf("k8s_live: list cert-manager issuers: %v", err)
	} else {
		for _, iss := range issuers {
			endpoint := fmt.Sprintf("%s/%s/%s/%s", k8sCtx, iss.Namespace, iss.Kind, iss.Name)
			asset := &model.CryptoAsset{
				Purpose:  "certificate-management",
				Function: fmt.Sprintf("cert-manager %s", iss.Kind),
			}
			if iss.CASecret != "" {
				asset.Function += fmt.Sprintf(" (CA secret: %s)", iss.CASecret)
			}
			m.emitFinding(ctx, endpoint, asset, 0.80, findings)
		}
	}

	clusterIssuers, err := client.ListCertManagerClusterIssuers(ctx)
	if err != nil {
		log.Printf("k8s_live: list cert-manager cluster issuers: %v", err)
	} else {
		for _, iss := range clusterIssuers {
			endpoint := fmt.Sprintf("%s/ClusterIssuer/%s", k8sCtx, iss.Name)
			asset := &model.CryptoAsset{
				Purpose:  "certificate-management",
				Function: "cert-manager ClusterIssuer",
			}
			if iss.CASecret != "" {
				asset.Function += fmt.Sprintf(" (CA secret: %s)", iss.CASecret)
			}
			m.emitFinding(ctx, endpoint, asset, 0.80, findings)
		}
	}
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test -v -run "TestK8sLive" ./pkg/scanner/`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/k8s_live.go pkg/scanner/k8s_live_test.go
git commit -m "feat(scanner): cert-manager CRD scanning with API group detection"
```

---

## Task 5: Edge case tests

**Files:**
- Modify: `pkg/scanner/k8s_live_test.go`

- [ ] **Step 1: Write all edge case tests**

Append to `k8s_live_test.go`:

```go
func TestK8sLive_NamespaceFilter(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "prod", Name: "prod-tls", CertPEM: certPEM, KeyPEM: keyPEM},
			{Namespace: "dev", Name: "dev-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive", K8sNamespace: "prod"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	for _, f := range collected {
		assert.Contains(t, f.Source.Endpoint, "/prod/", "all findings must be from prod namespace")
		assert.NotContains(t, f.Source.Endpoint, "/dev/")
	}
}

func TestK8sLive_AllNamespaces(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "prod", Name: "prod-tls", CertPEM: certPEM, KeyPEM: keyPEM},
			{Namespace: "dev", Name: "dev-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	require.GreaterOrEqual(t, len(collected), 4, "expected findings from both namespaces")
}

func TestK8sLive_EmptyCluster(t *testing.T) {
	fc := &fakeK8sClient{hasAPIGroups: map[string]bool{}}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 16)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)

	assert.NoError(t, err)
	var count int
	for range findings { count++ }
	assert.Equal(t, 0, count)
}

func TestK8sLive_APIError(t *testing.T) {
	certPEM, _ := testCertPEM(t)
	fc := &fakeK8sClient{
		webhookConfigs: []k8sWebhookConfig{
			{Name: "good-webhook", Kind: "ValidatingWebhookConfiguration", CABundle: certPEM},
		},
		listErrors:   map[string]error{"secrets": fmt.Errorf("forbidden")},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	err := m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	assert.NoError(t, err, "scan should not fail even if one list errors")
	require.NotEmpty(t, collected, "webhook findings should still emit despite secret list error")
}

func TestK8sLive_NeverSerializesSecretData(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "default", Name: "my-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	fakeFactory := &fakeK8sClientFactory{client: fc}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, fakeFactory)

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings { collected = append(collected, f) }
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	for _, f := range collected {
		b, _ := json.Marshal(f)
		body := string(b)
		assert.NotContains(t, body, "BEGIN CERTIFICATE")
		assert.NotContains(t, body, "BEGIN EC PRIVATE KEY")
		assert.NotContains(t, body, "BEGIN RSA PRIVATE KEY")
	}
}

func TestK8sLive_SkipsNonK8sTarget(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, nil)
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetNetwork, Value: "192.168.1.1:443",
	}, findings)
	close(findings)

	assert.NoError(t, err)
	var count int
	for range findings { count++ }
	assert.Equal(t, 0, count)
}
```

Add `"encoding/json"` and `"fmt"` to imports if needed.

- [ ] **Step 2: Run all tests**

Run: `go test -v -run "TestK8sLive" ./pkg/scanner/`
Expected: all 14 tests PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/k8s_live_test.go
git commit -m "test(scanner): k8s edge cases — namespace filter, API errors, empty cluster, redaction"
```

---

## Task 6: Production `realK8sClientFactory` with client-go

**Files:**
- Create: `pkg/scanner/k8s_live_client.go`
- Modify: `pkg/scanner/k8s_live.go` (remove stub factory)
- Modify: `go.mod` / `go.sum`

- [ ] **Step 1: Add client-go dependency**

```bash
cd /Users/amirrudinyahaya/Workspace/triton
go get k8s.io/client-go@latest k8s.io/apimachinery@latest k8s.io/api@latest
go mod tidy
```

- [ ] **Step 2: Remove stub factory from k8s_live.go**

Delete `stubK8sClientFactory` struct, its `NewClient` method, and the `newRealK8sClientFactory()` function. Keep the declaration `func newRealK8sClientFactory() k8sClientFactory` — it will now live in `k8s_live_client.go`.

- [ ] **Step 3: Create k8s_live_client.go**

Create `pkg/scanner/k8s_live_client.go` with the real implementation. This is the ONLY file importing `k8s.io/*`. It translates raw k8s API objects to the intermediate types defined in `k8s_live.go`.

The implementer should:
1. Read the `k8sClient` interface in `k8s_live.go` to know all methods needed
2. Implement `realK8sClientFactory.NewClient(kubeconfig, context)` using `clientcmd.BuildConfigFromFlags` for kubeconfig and `rest.InClusterConfig()` as fallback
3. Implement each `k8sClient` method wrapping the real Kubernetes API calls:
   - `ListTLSSecrets`: `clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{FieldSelector: "type=kubernetes.io/tls"})` → convert to `[]k8sTLSSecret`
   - `ListIngresses`: `clientset.NetworkingV1().Ingresses(ns).List(...)` → convert to `[]k8sIngress`
   - `ListWebhookConfigs`: `clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(...)` + `...MutatingWebhookConfigurations().List(...)` → convert to `[]k8sWebhookConfig`
   - `ListConfigMaps`: `clientset.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{FieldSelector: "metadata.name="+name})` → convert to `[]k8sConfigMap`
   - `ListCertManagerCertificates`, `ListCertManagerIssuers`, `ListCertManagerClusterIssuers`: use dynamic client with `schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}` etc. Parse unstructured objects to extract `spec.privateKey.algorithm`, `spec.privateKey.size`, `spec.issuerRef.name`, `spec.ca.secretName`
   - `HasAPIGroup`: `clientset.Discovery().ServerGroups()` → check for `cert-manager.io`
4. Use `Limit: 500` in all `ListOptions` for pagination

This is the most complex file. The implementer should reference how go-containerregistry was isolated in `oci_image_remote.go` as the pattern.

- [ ] **Step 4: Build + test**

```bash
go build ./...
go test ./pkg/scanner/...
go vet ./...
```

Expected: all pass. Unit tests still use fakeK8sClient, not the real implementation.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/k8s_live.go pkg/scanner/k8s_live_client.go go.mod go.sum
git commit -m "feat(scanner): realK8sClientFactory using client-go"
```

---

## Task 7: CLI flag + BuildConfig + k8s_live module injection

**Files:**
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/scannerconfig/config_test.go`
- Modify: `cmd/root.go`

- [ ] **Step 1: Write failing BuildConfig tests**

Append to `internal/scannerconfig/config_test.go`:

```go
func TestBuildConfig_KubeconfigInjectsK8sLiveModule(t *testing.T) {
	opts := BuildOptions{
		Profile:    "standard",
		Kubeconfig: "/home/alice/.kube/config",
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules, "k8s_live")
}

func TestBuildConfig_K8sNamespacePassedThrough(t *testing.T) {
	opts := BuildOptions{
		Profile:      "standard",
		Kubeconfig:   "/home/alice/.kube/config",
		K8sNamespace: "prod",
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.K8sNamespace)
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test -v -run "TestBuildConfig_Kubeconfig|TestBuildConfig_K8sNamespace" ./internal/scannerconfig/`
Expected: FAIL — `BuildOptions` has no `K8sNamespace` field, `Config` has no `K8sNamespace` field, `k8s_live` not injected

- [ ] **Step 3: Extend BuildOptions + BuildConfig + Config**

In `internal/scannerconfig/config.go`:

Add `K8sNamespace string` to `BuildOptions`:
```go
type BuildOptions struct {
	// ...existing fields...
	OIDCEndpoints []string
	K8sNamespace  string // NEW
}
```

In `BuildConfig`, after the `oci_image` injection block, add:
```go
	if k8sMode && !containsModule(cfg.Modules, "k8s_live") {
		cfg.Modules = append(cfg.Modules, "k8s_live")
	}
	cfg.K8sNamespace = opts.K8sNamespace
```

Verify `K8sNamespace` field exists on `Config` struct (added in Task 2).

- [ ] **Step 4: Add CLI flag**

In `cmd/root.go`, add variable:
```go
var k8sNamespace string
```

Register flag:
```go
rootCmd.PersistentFlags().StringVar(&k8sNamespace, "k8s-namespace", "",
	"Kubernetes namespace to scan (default: all namespaces)")
```

Wire into BuildOptions:
```go
K8sNamespace: k8sNamespace,
```

- [ ] **Step 5: Verify**

```bash
go test -v -run "TestBuildConfig_Kubeconfig|TestBuildConfig_K8sNamespace" ./internal/scannerconfig/
go build ./...
go run . --help | grep k8s-namespace
```

Expected: 2 tests pass, build clean, flag visible.

- [ ] **Step 6: Commit**

```bash
git add internal/scannerconfig/config.go internal/scannerconfig/config_test.go cmd/root.go
git commit -m "feat(cli): add --k8s-namespace flag + BuildConfig k8s_live injection"
```

---

## Task 8: Engine registration

**Files:**
- Modify: `pkg/scanner/engine.go`
- Modify: `pkg/scanner/engine_test.go`

- [ ] **Step 1: Register module**

In `pkg/scanner/engine.go::RegisterDefaultModules()`, after the `NewOIDCProbeModule` line, append:

```go
	// Sprint 1b — live Kubernetes cluster scanner. Enterprise-only.
	// Only runs when --kubeconfig is supplied.
	e.RegisterModule(NewK8sLiveModule(e.config))
```

- [ ] **Step 2: Update engine test**

Bump module count assertion (30→31). Add `assert.True(t, names["k8s_live"])`.

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./pkg/scanner/...
go run . --profile quick --format json -o /tmp/smoke.json 2>&1 | head -5
```

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/engine.go pkg/scanner/engine_test.go
git commit -m "feat(engine): register K8sLiveModule in default module list"
```

---

## Task 9: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/SYSTEM_ARCHITECTURE.md`
- Modify: `docs/DEPLOYMENT_GUIDE.md`

- [ ] **Step 1: README — Kubernetes scanning section**

Add after the OIDC probing section:

```markdown
### Scanning Kubernetes clusters

Triton can connect to a live Kubernetes cluster and inventory TLS
secrets, ingress bindings, webhook CA bundles, cluster CA, and
cert-manager resources.

\`\`\`bash
# Scan all namespaces
triton --kubeconfig ~/.kube/config --k8s-context prod

# Scan a specific namespace
triton --kubeconfig ~/.kube/config --k8s-context prod --k8s-namespace default

# In-cluster scanning (from a pod with a ServiceAccount)
triton
\`\`\`

Live Kubernetes scanning is an **Enterprise tier** feature. The host
filesystem is **not** scanned when \`--kubeconfig\` is set.
```

- [ ] **Step 2: SYSTEM_ARCHITECTURE — K8s scanner subsection**

Add after the OIDC subsection:

```markdown
### Live Kubernetes Cluster Scanner

The `k8s_live` module connects to a Kubernetes cluster via kubeconfig
(or in-cluster SA detection) and enumerates crypto-relevant resources.

**Resources scanned:**
- `Secret` (type `kubernetes.io/tls`) — certificate + private key
- `Ingress.spec.tls` — hostname→secret binding
- `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` — caBundle PEM
- `ConfigMap` `kube-root-ca.crt` — cluster CA certificate
- cert-manager `Certificate` / `Issuer` / `ClusterIssuer` (if installed)

cert-manager detection uses `discovery.ServerGroups()` — graceful skip
when the API group is absent. All list calls use `Limit: 500` pagination.

Raw private key material is parsed in memory for algorithm identification
and immediately discarded. Never written to findings, logs, or reports.
```

- [ ] **Step 3: DEPLOYMENT_GUIDE — RBAC section**

Append to the security configuration section:

```markdown
### Kubernetes Scanner RBAC

Deploy the following ClusterRole and bind it to a ServiceAccount for
Triton to use when scanning clusters:

\`\`\`yaml
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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: triton-scanner
subjects:
- kind: ServiceAccount
  name: triton-scanner
  namespace: triton-system
roleRef:
  kind: ClusterRole
  name: triton-scanner
  apiGroup: rbac.authorization.k8s.io
\`\`\`

**Security note:** Triton extracts algorithm, key size, and subject
metadata from TLS secrets. Raw private key material is parsed in memory
for algorithm identification and immediately discarded — it is never
written to disk, logs, findings, or reports.
```

- [ ] **Step 4: Update module count**

In `README.md`, change "30 scanner modules" to "31 scanner modules".

- [ ] **Step 5: Commit**

```bash
git add README.md docs/SYSTEM_ARCHITECTURE.md docs/DEPLOYMENT_GUIDE.md
git commit -m "docs: Kubernetes scanner usage, architecture, RBAC, and module count"
```

---

## Task 10: Final verification

- [ ] **Step 1: Full test suite**

```bash
go test -count=1 ./...
```

Expected: all packages pass.

- [ ] **Step 2: Lint**

```bash
make lint
```

Expected: 0 issues.

- [ ] **Step 3: Smoke test**

```bash
go run . --profile quick --format json -o /tmp/smoke.json
test -s /tmp/smoke.json
go run . --help | grep -E "kubeconfig|k8s-context|k8s-namespace"
```

Expected: default scan works, all 3 k8s flags visible.

- [ ] **Step 4: Coverage check**

```bash
go test -cover ./pkg/scanner/... | grep k8s_live
```

Expected: ≥ 85% on k8s_live.go.

- [ ] **Step 5: Push + PR**

```bash
git push -u origin feat/k8s-live-scanner
gh pr create --title "feat: live Kubernetes cluster scanner" --body "..."
```

---

## Self-review notes

- **Spec coverage:** §3.1 module interface → Task 2. §3.2 testability → Task 1. §3.3 scan flow → Tasks 2-4. §3.4 intermediate types → Task 1. §3.5 cert/key parsing → Task 2. §3.6 finding emission → Tasks 2-4. §3.7 namespace → Task 5+7. §3.8 pagination → Task 6. §3.9 CLI → Task 7. §3.10 licence → already wired, no task needed. §4 deps → Task 6. §5 testing → Tasks 1-5. §6 edge cases → Task 5. §7 RBAC → Task 9. §8 migration → no task needed (no schema change). §9 docs → Task 9.
- **Placeholder scan:** All stubs (scanIngresses, scanWebhookConfigs, scanRootCA, scanCertManager) are explicitly replaced in their respective tasks. `stubK8sClientFactory` is removed in Task 6.
- **Type consistency:** `k8sClient` interface methods, intermediate types, `fakeK8sClient` fields — all consistent across Tasks 1-5. `K8sNamespace` field added to Config in Task 2, wired in BuildOptions in Task 7.
- **Gap found:** The spec §3.9 says "BuildConfig must inject k8s_live into cfg.Modules when k8sMode is true." Task 7 adds this injection. The ingress finding uses category 8 (network) per the spec's finding emission table. All other k8s findings use category 5 (PKI). Verified consistent.
