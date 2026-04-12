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
		m.parseCertPEM(ctx, s.CertPEM, endpoint, "TLS certificate", 0.95, findings)
		m.parseKeyPEM(ctx, s.KeyPEM, endpoint, "TLS private key", findings)
	}
}

func (m *K8sLiveModule) parseCertPEM(ctx context.Context, pemData []byte, endpoint, function string, confidence float64, findings chan<- *model.Finding) {
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
	m.emitFinding(ctx, endpoint, asset, 5, confidence, findings)
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
	m.emitFinding(ctx, endpoint, asset, 5, 0.95, findings)
}

func classifyCertKey(cert *x509.Certificate) (algo string, keySize int) {
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

func classifyKeyDER(der []byte) (algo string, keySize int) {
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

func (m *K8sLiveModule) emitFinding(ctx context.Context, endpoint string, asset *model.CryptoAsset, category int, confidence float64, findings chan<- *model.Finding) {
	atomic.AddInt64(&m.lastMatched, 1)
	select {
	case findings <- &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: category,
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
			// Ingress findings use category 8 (network) + lower confidence since
			// we're recording TLS binding metadata, not parsing actual crypto.
			m.emitFinding(ctx, endpoint, asset, 8, 0.80, findings)
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
		m.parseCertPEM(ctx, wh.CABundle, endpoint, "Webhook CA bundle", 0.90, findings)
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
		m.parseCertPEM(ctx, cm.CACertPEM, endpoint, "Cluster root CA", 0.95, findings)
	}
}

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
			m.emitFinding(ctx, endpoint, asset, 5, 0.85, findings)
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
			m.emitFinding(ctx, endpoint, asset, 5, 0.80, findings)
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
			m.emitFinding(ctx, endpoint, asset, 5, 0.80, findings)
		}
	}
}

// newRealK8sClientFactory returns the production client factory.
// Implementation lives in k8s_live_client.go — the only file importing k8s.io/*.
func newRealK8sClientFactory() k8sClientFactory {
	return newRealK8sClient()
}
