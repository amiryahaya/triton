package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// fakeK8sClient is a test double for k8sClient.
// It supports namespace filtering and selective error injection via listErrors.
type fakeK8sClient struct {
	tlsSecrets         []k8sTLSSecret
	ingresses          []k8sIngress
	webhookConfigs     []k8sWebhookConfig
	configMaps         []k8sConfigMap
	certManagerCerts   []k8sCertManagerCert
	certManagerIssuers []k8sCertManagerIssuer
	clusterIssuers     []k8sCertManagerIssuer
	hasAPIGroups       map[string]bool
	listErrors         map[string]error // keyed by resource name for selective failure
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

// fakeK8sClientFactory is a test double for k8sClientFactory.
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
		for f := range findings {
			collected = append(collected, f)
		}
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
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	var issuerFinding *model.Finding
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "cert-manager Issuer (CA secret: ca-secret)" {
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
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetKubernetesCluster, Value: "/fake",
	}, findings)
	close(findings)
	<-done

	assert.Empty(t, collected, "no cert-manager findings when API group absent")
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

func TestK8sLive_ModuleInterface(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, nil)
	assert.Equal(t, "k8s_live", m.Name())
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
	assert.Equal(t, model.TargetKubernetesCluster, m.ScanTargetType())
}

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
		for f := range findings {
			collected = append(collected, f)
		}
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
		for f := range findings {
			collected = append(collected, f)
		}
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
		for f := range findings {
			collected = append(collected, f)
		}
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

// runK8sScan runs a scan and returns all findings plus the error.
func runK8sScan(t *testing.T, m *K8sLiveModule, target model.ScanTarget) ([]*model.Finding, error) {
	t.Helper()
	findings := make(chan *model.Finding, 128)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()
	err := m.Scan(context.Background(), target, findings)
	close(findings)
	<-done
	return collected, err
}

func TestK8sLive_NamespaceFilter(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "prod", Name: "prod-tls", CertPEM: certPEM, KeyPEM: keyPEM},
			{Namespace: "dev", Name: "dev-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	cfg := &scannerconfig.Config{Profile: "comprehensive", K8sNamespace: "prod"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetKubernetesCluster, Value: "/fake"})
	require.NoError(t, err)
	require.NotEmpty(t, collected)
	for _, f := range collected {
		assert.Contains(t, f.Source.Endpoint, "prod/", "finding should be from prod namespace, got: %s", f.Source.Endpoint)
		assert.NotContains(t, f.Source.Endpoint, "dev/", "dev namespace finding leaked through filter")
	}
}

func TestK8sLive_AllNamespaces(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "ns-a", Name: "tls-a", CertPEM: certPEM, KeyPEM: keyPEM},
			{Namespace: "ns-b", Name: "tls-b", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	// No K8sNamespace set → scan all namespaces.
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetKubernetesCluster, Value: "/fake"})
	require.NoError(t, err)

	var hasNsA, hasNsB bool
	for _, f := range collected {
		if containsStr(f.Source.Endpoint, "ns-a/") {
			hasNsA = true
		}
		if containsStr(f.Source.Endpoint, "ns-b/") {
			hasNsB = true
		}
	}
	assert.True(t, hasNsA, "expected findings from ns-a")
	assert.True(t, hasNsB, "expected findings from ns-b")
}

// containsStr is a simple substring check used in k8s_live tests.
func containsStr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestK8sLive_EmptyCluster(t *testing.T) {
	fc := &fakeK8sClient{
		hasAPIGroups: map[string]bool{},
	}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetKubernetesCluster, Value: "/fake"})
	require.NoError(t, err, "empty cluster should not return an error")
	assert.Empty(t, collected, "expected zero findings on empty cluster")
}

func TestK8sLive_APIError(t *testing.T) {
	certPEM, _ := testCertPEM(t)
	fc := &fakeK8sClient{
		listErrors: map[string]error{
			"secrets": fmt.Errorf("forbidden"),
		},
		webhookConfigs: []k8sWebhookConfig{
			{Name: "my-webhook", Kind: "ValidatingWebhookConfiguration", CABundle: certPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetKubernetesCluster, Value: "/fake"})
	require.NoError(t, err, "scan must not return error when individual resource list fails")
	require.NotEmpty(t, collected, "webhook findings must still be emitted despite secrets error")

	var webhookFound bool
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "Webhook CA bundle" {
			webhookFound = true
		}
	}
	assert.True(t, webhookFound, "webhook CA bundle finding expected")
}

func TestK8sLive_NeverSerializesSecretData(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "default", Name: "my-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetKubernetesCluster, Value: "/fake"})
	require.NoError(t, err)
	require.NotEmpty(t, collected)

	forbidden := []string{
		"BEGIN CERTIFICATE",
		"BEGIN EC PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
	}
	for _, f := range collected {
		data, marshalErr := json.Marshal(f)
		require.NoError(t, marshalErr)
		jsonStr := string(data)
		for _, marker := range forbidden {
			assert.NotContains(t, jsonStr, marker,
				"finding JSON must not contain raw PEM data (%q leaked)", marker)
		}
	}
}

func TestK8sLive_SkipsNonK8sTarget(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	fc := &fakeK8sClient{
		tlsSecrets: []k8sTLSSecret{
			{Namespace: "default", Name: "my-tls", CertPEM: certPEM, KeyPEM: keyPEM},
		},
		hasAPIGroups: map[string]bool{},
	}
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	m := newK8sLiveModuleWithFactory(cfg, &fakeK8sClientFactory{client: fc})

	// Pass a TargetNetwork target — module should ignore it.
	collected, err := runK8sScan(t, m, model.ScanTarget{Type: model.TargetNetwork, Value: "192.168.1.0/24"})
	require.NoError(t, err)
	assert.Empty(t, collected, "k8s_live module must not emit findings for non-Kubernetes targets")
}
