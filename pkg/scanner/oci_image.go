package scanner

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// imageFetcher abstracts image pull + layer extraction so unit tests
// can substitute a fake that returns a pre-baked rootfs. The real
// implementation lives in oci_image_remote.go (Task 13) and uses
// github.com/google/go-containerregistry.
type imageFetcher interface {
	Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error)
}

// fetchedImage is the result of pulling and extracting an OCI image.
// RootFS is a local filesystem path the caller may walk like any other
// filesystem target. Cleanup must be called when the caller is done
// (typically via defer) to remove the sandbox.
type fetchedImage struct {
	RootFS    string // extracted rootfs path
	Ref       string // canonical image ref
	Digest    string // sha256:... manifest digest
	LayerN    int    // layer count after flatten
	SizeBytes int64  // total uncompressed size
	Cleanup   func() error
}

// OCIImageModule scans OCI container images by pulling them, extracting
// their rootfs into a temporary sandbox, and delegating to the file-based
// scanner modules (certificates, keys, binaries, deps, etc.). Each finding
// is annotated with the image reference and digest before being forwarded.
type OCIImageModule struct {
	config      *scannerconfig.Config
	fetcher     imageFetcher
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewOCIImageModule returns a new OCIImageModule using the remote fetcher
// (which lands in Task 13). For testing, construct the struct directly
// with a fakeFetcher.
func NewOCIImageModule(cfg *scannerconfig.Config) *OCIImageModule {
	return &OCIImageModule{
		config:  cfg,
		fetcher: newRemoteFetcher(),
	}
}

func (m *OCIImageModule) Name() string                         { return "oci_image" }
func (m *OCIImageModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *OCIImageModule) ScanTargetType() model.ScanTargetType { return model.TargetOCIImage }
func (m *OCIImageModule) SetStore(s store.Store)               { m.store = s }

// FileStats implements FileMetrics.
func (m *OCIImageModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

const (
	ociMaxUncompressedBytes int64 = 4 * 1024 * 1024 * 1024 // 4 GB
	ociMaxLayers            int   = 128
)

// ociDelegatedModules lists the module names the OCI scanner delegates
// to when scanning an extracted rootfs. Excludes modules that make no
// sense inside a static image (network, process, protocol, database,
// hsm, ldap, service_mesh, container_signatures, kernel, codesign
// variants, vpn_config, password_hash, mail_server, web_server,
// xml_dsig, auth_material, containers meta-scanner).
var ociDelegatedModules = map[string]bool{
	"certificates":    true,
	"keys":            true,
	"certstore":       true,
	"library":         true,
	"binaries":        true,
	"deps":            true,
	"deps_ecosystems": true,
	"configs":         true,
	"webapp":          true,
	"packages":        true,
}

// Scan pulls the OCI image, extracts its rootfs into a sandbox, and
// delegates scanning to file-based modules. Each finding is annotated
// with the image ref and digest before being forwarded to the caller's
// findings channel.
func (m *OCIImageModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Type != model.TargetOCIImage {
		return nil
	}

	img, err := m.fetcher.Fetch(ctx, target.Value, m.config.Credentials)
	if err != nil {
		return fmt.Errorf("oci_image: fetch %q: %w", target.Value, err)
	}
	defer func() {
		if img.Cleanup != nil {
			_ = img.Cleanup()
		}
	}()

	if img.SizeBytes > ociMaxUncompressedBytes {
		return fmt.Errorf("oci_image: image %q exceeds size cap (%d > %d bytes)",
			target.Value, img.SizeBytes, ociMaxUncompressedBytes)
	}
	if img.LayerN > ociMaxLayers {
		return fmt.Errorf("oci_image: image %q exceeds layer cap (%d > %d)",
			target.Value, img.LayerN, ociMaxLayers)
	}

	subCfg := *m.config
	subCfg.ScanTargets = []model.ScanTarget{{
		Type:  model.TargetFilesystem,
		Value: img.RootFS,
		Depth: -1,
	}}

	var delegates []Module
	if len(m.config.Modules) > 0 {
		for _, name := range m.config.Modules {
			if mod := constructDelegate(name, &subCfg); mod != nil {
				delegates = append(delegates, mod)
			}
		}
	} else {
		for name := range ociDelegatedModules {
			if mod := constructDelegate(name, &subCfg); mod != nil {
				delegates = append(delegates, mod)
			}
		}
	}

	annotated := make(chan *model.Finding, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range annotated {
			if f.CryptoAsset != nil {
				f.CryptoAsset.ImageRef = img.Ref
				f.CryptoAsset.ImageDigest = img.Digest
			}
			findings <- f
		}
	}()

	for _, d := range delegates {
		subTarget := model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: img.RootFS,
			Depth: -1,
		}
		if err := d.Scan(ctx, subTarget, annotated); err != nil {
			continue
		}
	}
	close(annotated)
	<-done

	atomic.AddInt64(&m.lastScanned, 1)
	return nil
}

// constructDelegate instantiates the named scanner module with the given
// config. Returns nil for unknown names so callers can skip gracefully.
func constructDelegate(name string, cfg *scannerconfig.Config) Module {
	switch name {
	case "certificates":
		return NewCertificateModule(cfg)
	case "keys":
		return NewKeyModule(cfg)
	case "certstore":
		return NewCertStoreModule(cfg)
	case "library":
		return NewLibraryModule(cfg)
	case "binaries":
		return NewBinaryModule(cfg)
	case "deps":
		return NewDepsModule(cfg)
	case "deps_ecosystems":
		return NewDepsEcosystemsModule(cfg)
	case "configs":
		return NewConfigModule(cfg)
	case "webapp":
		return NewWebAppModule(cfg)
	case "packages":
		return NewPackageModule(cfg)
	default:
		return nil
	}
}

// newRemoteFetcher returns the stub remote fetcher. The real implementation
// using go-containerregistry lands in Task 13.
func newRemoteFetcher() imageFetcher {
	return &stubRemoteFetcher{}
}

type stubRemoteFetcher struct{}

func (s *stubRemoteFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
	return nil, fmt.Errorf("oci_image: remote fetcher not implemented (lands in Task 13)")
}
