//go:build linux

package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan is a temporary placeholder that emits a skipped-finding until Task 6
// wires up the real tpmfs-based implementation. Replaced entirely in Task 6.
func (m *TPMModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "tpm-skipped",
			Evidence:        "tpm scanning unavailable: implementation pending (Task 6)",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "tpm",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
