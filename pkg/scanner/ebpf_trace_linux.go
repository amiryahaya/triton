//go:build linux

package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan is a temporary placeholder that emits a skipped-finding until Task 8
// wires up the real eBPF implementation. Replaced entirely in Task 8.
func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: implementation pending (Task 8)",
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
