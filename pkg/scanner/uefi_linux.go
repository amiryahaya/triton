//go:build linux

package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

func (m *UEFIModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "uefi-skipped",
			Evidence:        "uefi scanning: implementation pending (Task 6)",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "uefi",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
