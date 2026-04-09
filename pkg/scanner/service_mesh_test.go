package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*ServiceMeshModule)(nil)

func TestServiceMeshModule_Interface(t *testing.T) {
	m := NewServiceMeshModule(&config.Config{})
	assert.Equal(t, "service_mesh", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestIsServiceMeshCertFile(t *testing.T) {
	cases := map[string]bool{
		// Istio
		"/etc/certs/cert-chain.pem": true,
		"/etc/certs/key.pem":        true,
		"/etc/certs/root-cert.pem":  true,
		"/var/run/secrets/workload-spiffe-credentials/cert-chain.pem": true,
		// Linkerd
		"/var/run/linkerd/identity/end-entity/crt.pem": true,
		"/var/run/linkerd/identity/end-entity/key.pem": true,
		// Consul Connect
		"/opt/consul/tls/connect-ca.pem": true,
		"/opt/consul/tls/leaf-cert.pem":  true,
		// Not in scope
		"/etc/ssl/certs/ca-certificates.crt": false,
		"/etc/nginx/nginx.conf":              false,
	}
	for path, want := range cases {
		got := isServiceMeshCertFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

func TestServiceMesh_ClassifyVendor(t *testing.T) {
	assert.Equal(t, "istio", serviceMeshVendor("/etc/certs/cert-chain.pem"))
	assert.Equal(t, "istio", serviceMeshVendor("/var/run/secrets/workload-spiffe-credentials/cert-chain.pem"))
	assert.Equal(t, "linkerd", serviceMeshVendor("/var/run/linkerd/identity/end-entity/crt.pem"))
	assert.Equal(t, "consul", serviceMeshVendor("/opt/consul/tls/leaf-cert.pem"))
}

func TestServiceMeshModule_ScanWalk(t *testing.T) {
	tmp := t.TempDir()
	// Simulate an Istio sidecar: /etc/certs/cert-chain.pem
	istioDir := filepath.Join(tmp, "etc", "certs")
	require.NoError(t, os.MkdirAll(istioDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(istioDir, "cert-chain.pem"), []byte(testPEMCert), 0o644))

	m := NewServiceMeshModule(&config.Config{MaxDepth: 10, MaxFileSize: 1024 * 1024})

	findings := make(chan *model.Finding, 32)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: tmp, Depth: 10}, findings)
	require.NoError(t, err)
	close(findings)
	<-done

	require.NotEmpty(t, collected)
	for _, f := range collected {
		assert.Equal(t, "service_mesh", f.Module)
		require.NotNil(t, f.CryptoAsset)
		assert.Contains(t, strings.ToLower(f.CryptoAsset.Purpose), "istio")
	}
}
