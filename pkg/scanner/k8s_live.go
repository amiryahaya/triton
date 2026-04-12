package scanner

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

// Intermediate types — k8s_live.go works only with these; k8s_live_client.go
// translates raw k8s API objects into these types. If client-go is ever
// swapped, the blast radius is one file.

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

// FileStats returns resource counts for progress reporting.
func (m *K8sLiveModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan connects to the Kubernetes cluster described by target and emits
// findings for every crypto-relevant resource it encounters.
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

// scanIngresses is implemented in Task 3.
func (m *K8sLiveModule) scanIngresses(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

// scanWebhookConfigs is implemented in Task 3.
func (m *K8sLiveModule) scanWebhookConfigs(ctx context.Context, client k8sClient, k8sCtx string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

// scanRootCA is implemented in Task 3.
func (m *K8sLiveModule) scanRootCA(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 3
}

// scanCertManager is implemented in Task 4.
func (m *K8sLiveModule) scanCertManager(ctx context.Context, client k8sClient, k8sCtx, namespace string, findings chan<- *model.Finding) {
	// Implemented in Task 4
}

// newRealK8sClientFactory returns the production client factory.
// Real implementation lands in Task 6 (k8s_live_client.go).
func newRealK8sClientFactory() k8sClientFactory {
	return &stubK8sClientFactory{}
}

type stubK8sClientFactory struct{}

func (s *stubK8sClientFactory) NewClient(kubeconfig, ctx string) (k8sClient, error) {
	return nil, fmt.Errorf("k8s_live: real client factory not yet implemented (Task 6)")
}
