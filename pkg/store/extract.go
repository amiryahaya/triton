package store

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ExtractFindings walks a ScanResult and produces one Finding row per
// model.Finding whose CryptoAsset is non-nil. Pure function — no DB
// access. Used by both the submit path (SaveScanWithFindings) and the
// backfill goroutine (BackfillFindings) so they produce identical rows.
// See docs/plans/2026-04-09-analytics-phase-1-design.md §6 for the
// design rationale.
//
// Field mapping from model.Finding / model.ScanResult:
//
//	Hostname ← scan.Metadata.Hostname
//	FilePath ← f.Source.Path
//	Module   ← f.Module
//	(CryptoAsset fields map 1:1 from ca)
//
// model.Finding.Category (a coarse ModuleCategory enum) is NOT stored —
// the scanner module name is the granular drill-down discriminator for
// Phase 1 views.
func ExtractFindings(scan *model.ScanResult) []Finding {
	if scan == nil || len(scan.Findings) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(scan.Findings))
	now := time.Now().UTC()
	for i := range scan.Findings {
		f := &scan.Findings[i]
		if f.CryptoAsset == nil {
			continue
		}
		ca := f.CryptoAsset
		out = append(out, Finding{
			ID:                uuid.Must(uuid.NewV7()).String(),
			ScanID:            scan.ID,
			OrgID:             scan.OrgID,
			Hostname:          scan.Metadata.Hostname,
			FindingIndex:      i,
			Module:            f.Module,
			FilePath:          f.Source.Path,
			Algorithm:         ca.Algorithm,
			KeySize:           ca.KeySize,
			PQCStatus:         ca.PQCStatus,
			MigrationPriority: ca.MigrationPriority,
			NotAfter:          ca.NotAfter,
			Subject:           ca.Subject,
			Issuer:            ca.Issuer,
			Reachability:      ca.Reachability,
			CreatedAt:         now,
		})
	}
	return out
}
