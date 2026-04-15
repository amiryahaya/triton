//go:build !linux

package scanner

import (
	"context"
	"runtime"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan emits one skipped-finding on non-Linux builds.
func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: " + runtime.GOOS + " is not Linux",
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
