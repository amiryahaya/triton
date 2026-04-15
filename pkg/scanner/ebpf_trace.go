package scanner

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/ebpftrace"
	"github.com/amiryahaya/triton/pkg/store"
)

// ebpfRunner matches the signature of ebpftrace.Run; exposed as a field on
// EBPFTraceModule so tests can stub the loader and exercise the error and
// quiet-window paths without requiring a live kernel.
type ebpfRunner func(ctx context.Context, opts ebpftrace.Options) (*ebpftrace.Outcome, error)

// EBPFTraceModule observes live crypto calls via eBPF uprobes (OpenSSL/GnuTLS/NSS)
// and kprobes (kernel crypto API) inside a bounded time window. Linux-only; the
// non-Linux build emits a single "skipped" finding.
type EBPFTraceModule struct {
	cfg    *scannerconfig.Config
	store  store.Store
	runner ebpfRunner // nil → use real ebpftrace.Run
}

// NewEBPFTraceModule constructs the module.
func NewEBPFTraceModule(cfg *scannerconfig.Config) *EBPFTraceModule {
	return &EBPFTraceModule{cfg: cfg}
}

// Name returns the canonical module name.
func (m *EBPFTraceModule) Name() string { return "ebpf_trace" }

// Category returns the module category (active runtime observation).
func (m *EBPFTraceModule) Category() model.ModuleCategory { return model.CategoryActiveRuntime }

// ScanTargetType returns the target type.
func (m *EBPFTraceModule) ScanTargetType() model.ScanTargetType { return model.TargetProcess }

// SetStore wires the incremental-scan store.
func (m *EBPFTraceModule) SetStore(s store.Store) { m.store = s }

// Scan delegates to the OS-specific scan method.
func (m *EBPFTraceModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scan(ctx, target, findings)
}
