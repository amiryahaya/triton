package scanner

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// TPMModule scans /sys/class/tpm/ for TPM devices, classifies firmware
// against a CVE registry, parses the endorsement-key certificate, and
// audits the TCG measured-boot event log's hash-algorithm coverage.
// Linux-only; non-Linux builds emit a single skipped-finding.
type TPMModule struct {
	cfg   *scannerconfig.Config
	store store.Store
}

// NewTPMModule constructs the module.
func NewTPMModule(cfg *scannerconfig.Config) *TPMModule {
	return &TPMModule{cfg: cfg}
}

// Name returns the canonical module name.
func (m *TPMModule) Name() string { return "tpm" }

// Category returns the module category (passive file scanner).
func (m *TPMModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }

// ScanTargetType returns the target type.
func (m *TPMModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// SetStore wires the incremental-scan store.
func (m *TPMModule) SetStore(s store.Store) { m.store = s }

// Scan delegates to the OS-specific scan method.
func (m *TPMModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scan(ctx, target, findings)
}
