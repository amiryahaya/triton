package scanner

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// ServiceMeshModule inventories the workload identity certificates
// that Istio, Linkerd, and Consul Connect drop on every sidecar
// pod. These certs are short-lived (Istio defaults to 24h,
// Linkerd to 24h, Consul to 72h) and are signed by each mesh's
// own CA — they're NOT in the OS trust store, don't appear in
// certificate.go's file patterns, and have no hint beyond their
// canonical path that they're even crypto material.
//
// This module recognizes the canonical paths, parses the PEM,
// and tags the finding with the detected vendor so the report
// shows "Istio workload identity certs: 47 endpoints" or
// "Linkerd identity certs expiring in <1h: 3". The mesh
// vendor is attached to asset.Purpose so the existing
// aggregation pipeline groups them naturally.
type ServiceMeshModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewServiceMeshModule wires a ServiceMeshModule with the engine config.
func NewServiceMeshModule(cfg *scannerconfig.Config) *ServiceMeshModule {
	return &ServiceMeshModule{config: cfg}
}

func (m *ServiceMeshModule) Name() string                         { return "service_mesh" }
func (m *ServiceMeshModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *ServiceMeshModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *ServiceMeshModule) SetStore(s store.Store)               { m.store = s }

func (m *ServiceMeshModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *ServiceMeshModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if ctx == nil {
		ctx = context.Background()
	}
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isServiceMeshCertFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, f := range m.parseMeshCert(path, data) {
				if f == nil {
					continue
				}
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isServiceMeshCertFile matches canonical mesh cert paths. Path
// segments (not just basenames) are used because the same
// filename (`cert.pem`, `key.pem`) is used by many unrelated
// systems; the containing directory is the distinguishing signal.
func isServiceMeshCertFile(path string) bool {
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))

	// Istio sidecar-injector default paths.
	if strings.Contains(lower, "/etc/certs/") && strings.HasSuffix(base, ".pem") {
		return true
	}
	if strings.Contains(lower, "/workload-spiffe-credentials/") && strings.HasSuffix(base, ".pem") {
		return true
	}
	// Linkerd identity controller paths.
	if strings.Contains(lower, "/var/run/linkerd/identity/") && strings.HasSuffix(base, ".pem") {
		return true
	}
	// Consul Connect leaf cert path.
	if strings.Contains(lower, "/consul/tls/") && strings.HasSuffix(base, ".pem") {
		return true
	}
	return false
}

// serviceMeshVendor returns the mesh name for a given cert path.
// Tagged onto the finding's Purpose so the report aggregates
// by mesh.
func serviceMeshVendor(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/etc/certs/"),
		strings.Contains(lower, "/workload-spiffe-credentials/"):
		return "istio"
	case strings.Contains(lower, "/var/run/linkerd/"):
		return "linkerd"
	case strings.Contains(lower, "/consul/tls/"):
		return "consul"
	}
	return "unknown-mesh"
}

// parseMeshCert decodes PEM blocks and emits one finding per
// CERTIFICATE block. Private key blocks are SILENTLY SKIPPED —
// we don't want to read workload private keys into the report.
func (m *ServiceMeshModule) parseMeshCert(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	rest := data
	vendor := serviceMeshVendor(path)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		algo, keySize := certPublicKeyInfo(cert)
		notBefore := cert.NotBefore
		notAfter := cert.NotAfter
		asset := &model.CryptoAsset{
			ID:           uuid.Must(uuid.NewV7()).String(),
			Function:     "Service mesh workload identity",
			Algorithm:    algo,
			KeySize:      keySize,
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    &notBefore,
			NotAfter:     &notAfter,
			IsCA:         cert.IsCA,
			Purpose:      vendor + " sidecar workload cert",
		}
		crypto.ClassifyCryptoAsset(asset)
		out = append(out, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 2,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  ConfidenceDefinitive,
			Module:      "service_mesh",
			Timestamp:   time.Now(),
		})
	}
	return out
}
