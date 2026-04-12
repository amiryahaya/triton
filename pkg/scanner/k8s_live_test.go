package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
