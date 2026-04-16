package scanner

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// UEFIModule scans /sys/firmware/efi/efivars/ for Secure Boot key
// variables (PK/KEK/db/dbx) and state (SecureBoot/SetupMode). Parses
// EFI_SIGNATURE_LIST format, classifies certs, checks dbx for missing
// CVE revocations. Linux-only; non-Linux emits a single skipped-finding.
type UEFIModule struct {
	cfg   *scannerconfig.Config
	store store.Store
}

func NewUEFIModule(cfg *scannerconfig.Config) *UEFIModule {
	return &UEFIModule{cfg: cfg}
}

func (m *UEFIModule) Name() string                         { return "uefi" }
func (m *UEFIModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *UEFIModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *UEFIModule) SetStore(s store.Store)               { m.store = s }

func (m *UEFIModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scan(ctx, target, findings)
}
