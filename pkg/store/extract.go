package store

import (
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// findingsNamespace is the fixed UUID namespace used to derive
// deterministic Finding IDs via uuid.NewSHA1. Any fixed UUID works —
// this value is arbitrary but MUST NOT CHANGE, or every previously-
// generated finding ID will become unreachable by downstream systems
// (remediation tickets in Phase 4, audit references, UI bookmarks).
// If you need to rotate it, add a schema migration that re-stamps IDs.
var findingsNamespace = uuid.MustParse("019d7400-0000-7000-a000-000000000001")

// ExtractFindings walks a ScanResult and produces one Finding row per
// model.Finding whose CryptoAsset is non-nil. Pure function — no DB
// access, no clock reads beyond CreatedAt. Used by both the submit
// path (SaveScanWithFindings) and the backfill goroutine
// (BackfillFindings) so they produce identical rows.
//
// Finding IDs are derived DETERMINISTICALLY from (scan ID, finding
// index) via uuid.NewSHA1. This is critical for the read-model
// rebuildability claim: dropping and regenerating the findings table
// must yield stable IDs so downstream systems (Phase 4 remediation,
// audit entries, UI bookmarks) survive a backfill re-run. See the
// /pensive:full-review action plan item B4 (2026-04-09).
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
			ID:                findingID(scan.ID, i),
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

// findingID derives a deterministic UUIDv5 from (scanID, findingIndex).
// Stable across extraction runs, so dropping+rebuilding the findings
// table via the backfill goroutine yields the same IDs external
// systems already know. Not exported — callers should always go
// through ExtractFindings.
func findingID(scanID string, findingIndex int) string {
	return uuid.NewSHA1(findingsNamespace, []byte(scanID+"/"+strconv.Itoa(findingIndex))).String()
}
