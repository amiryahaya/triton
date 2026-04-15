//go:build linux

package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/ebpftrace"
)

// scan is the Linux eBPF runtime tracer. It checks prereqs (root + BTF),
// delegates to the ebpftrace coordinator for the configured window, and
// emits one Finding per (binary, algorithm, source) aggregate. When prereqs
// are missing or no activity is observed, emits a single skipped-finding.
func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	if os.Geteuid() != 0 {
		return emitSkipped(ctx, findings, "not root; eBPF requires CAP_BPF or root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return emitSkipped(ctx, findings, "BTF not available at /sys/kernel/btf/vmlinux")
	}

	window := m.cfg.EBPFWindow
	if window <= 0 {
		window = 60 * time.Second
	}

	runner := m.runner
	if runner == nil {
		runner = ebpftrace.Run
	}
	outcome, err := runner(ctx, ebpftrace.Options{
		Window:      window,
		SkipUprobes: m.cfg.EBPFSkipUprobes,
		SkipKprobes: m.cfg.EBPFSkipKprobes,
	})
	if err != nil {
		return emitSkipped(ctx, findings, "ebpftrace.Run: "+err.Error())
	}

	emittedAny := false
	for _, agg := range outcome.Aggregates {
		f := buildEBPFFinding(agg, window, outcome)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case findings <- f:
			emittedAny = true
		}
	}
	if !emittedAny {
		reason := fmt.Sprintf("no crypto activity observed in %s window (probes: %d attached, %d failed, events: %d, decode errors: %d)",
			window, outcome.ProbesAttached, outcome.ProbesFailed, outcome.EventsObserved, outcome.DecodeErrors)
		return emitSkipped(ctx, findings, reason)
	}
	return nil
}

// buildEBPFFinding maps one ebpftrace.Aggregate into a model.Finding. The
// algorithm string is re-classified through the PQC registry so downstream
// consumers see a canonical name + status (SAFE/TRANSITIONAL/...).
func buildEBPFFinding(agg ebpftrace.Aggregate, window time.Duration, outcome *ebpftrace.Outcome) *model.Finding {
	info := crypto.ClassifyAlgorithm(agg.Algorithm, 0)
	detection := "ebpf-uprobe"
	if agg.Source == ebpftrace.SourceKprobe {
		detection = "ebpf-kprobe"
	}
	evidence := fmt.Sprintf("%d calls over %s from %d pids (probes: %d attached, %d failed)",
		agg.Count, window, len(agg.PIDs), outcome.ProbesAttached, outcome.ProbesFailed)
	var firstPID int
	if agg.FirstPID > 0 {
		firstPID = int(agg.FirstPID)
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: info.Name,
		Library:   agg.Library,
		Language:  "C",
		Function:  functionForFamily(info.Family),
		PQCStatus: string(info.Status),
	}
	return &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			Path:            agg.BinaryPath,
			PID:             firstPID,
			DetectionMethod: detection,
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.98,
		Module:      "ebpf_trace",
		Timestamp:   time.Now().UTC(),
	}
}

// emitSkipped emits the canonical "eBPF unavailable" finding. Uses the same
// shape as the Task-1 placeholder so report consumers can detect skip status
// uniformly regardless of reason (prereq miss, Run error, or quiet window).
func emitSkipped(ctx context.Context, findings chan<- *model.Finding, reason string) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: " + reason,
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "C",
		},
		Confidence: 0.0,
		Module:     "ebpf_trace",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
