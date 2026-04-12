package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsHelmChartFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		{"/repo/charts/myapp/Chart.yaml", true},
		{"/repo/helm/Chart.yaml", true},
		{"/repo/charts/myapp/values.yaml", true},
		{"/repo/charts/myapp/values.yml", true},
		{"/home/user/.helm/cache/repo/charts/cert-manager/Chart.yaml", true},

		// Not Helm
		{"/repo/Chart.yaml", false}, // no charts/ or helm/ context
		{"/repo/values.yaml", false},
		{"/etc/nginx/nginx.conf", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isHelmChartFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- Chart.yaml parser tests ---

func TestParseChartYAML(t *testing.T) {
	chart := `apiVersion: v2
name: cert-manager
description: A Helm chart for cert-manager
version: 1.14.0
appVersion: "1.14.0"
`
	m := &HelmChartModule{}
	findings := m.parseChartYAML("/repo/charts/cert-manager/Chart.yaml", []byte(chart))
	require.NotEmpty(t, findings)
	assert.Equal(t, "Helm chart", findings[0].CryptoAsset.Function)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "cert-manager")
}

func TestParseChartYAML_NotChart(t *testing.T) {
	m := &HelmChartModule{}
	findings := m.parseChartYAML("/repo/charts/myapp/Chart.yaml", []byte("random: content"))
	assert.Empty(t, findings)
}

// --- values.yaml parser tests ---

func TestParseValuesYAML_TLSConfig(t *testing.T) {
	values := `replicaCount: 1
image:
  repository: nginx
  tag: latest
tls:
  enabled: true
  secretName: my-tls-secret
  cipherSuites:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  minVersion: VersionTLS12
ingress:
  annotations:
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES256-GCM-SHA384"
`
	m := &HelmChartModule{}
	findings := m.parseValuesYAML("/repo/charts/myapp/values.yaml", []byte(values))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["Helm TLS configuration"])
}

func TestParseValuesYAML_CertManager(t *testing.T) {
	values := `certManager:
  enabled: true
  issuer:
    kind: ClusterIssuer
    name: letsencrypt-prod
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod
`
	m := &HelmChartModule{}
	findings := m.parseValuesYAML("/repo/charts/myapp/values.yaml", []byte(values))
	require.NotEmpty(t, findings)

	found := false
	for _, f := range findings {
		if f.CryptoAsset.Function == "Helm ACME/cert-manager reference" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestParseValuesYAML_NoTLS(t *testing.T) {
	values := `replicaCount: 3
image:
  repository: busybox
  tag: latest
`
	m := &HelmChartModule{}
	findings := m.parseValuesYAML("/repo/charts/myapp/values.yaml", []byte(values))
	assert.Empty(t, findings)
}

// --- module interface ---

func TestHelmChartModuleInterface(t *testing.T) {
	m := NewHelmChartModule(nil)
	assert.Equal(t, "helm_chart", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
