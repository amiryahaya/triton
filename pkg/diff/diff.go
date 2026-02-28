package diff

import (
	"fmt"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// ScanDiff holds the comparison between two scan results.
type ScanDiff struct {
	BaseID    string          `json:"baseID"`
	CompareID string          `json:"compareID"`
	Added     []model.Finding `json:"added,omitempty"`
	Removed   []model.Finding `json:"removed,omitempty"`
	Changed   []FindingChange `json:"changed,omitempty"`
	Summary   DiffSummary     `json:"summary"`
}

// FindingChange records a finding that changed PQC status between scans.
type FindingChange struct {
	Finding   model.Finding `json:"finding"`
	OldStatus string        `json:"oldStatus"`
	NewStatus string        `json:"newStatus"`
}

// DiffSummary holds aggregate counts for the diff.
type DiffSummary struct {
	AddedCount   int     `json:"addedCount"`
	RemovedCount int     `json:"removedCount"`
	ChangedCount int     `json:"changedCount"`
	NACSADelta   float64 `json:"nacsaDelta,omitempty"`
	SafeDelta    int     `json:"safeDelta"`
	UnsafeDelta  int     `json:"unsafeDelta"`
}

// ComputeDiff compares two scan results and returns the diff.
// base is the older scan, compare is the newer scan.
func ComputeDiff(base, compare *model.ScanResult) *ScanDiff {
	if base == nil || compare == nil {
		d := &ScanDiff{}
		if base != nil {
			d.BaseID = base.ID
		}
		if compare != nil {
			d.CompareID = compare.ID
		}
		return d
	}

	d := &ScanDiff{
		BaseID:    base.ID,
		CompareID: compare.ID,
	}

	// Index base findings by composite key.
	baseIndex := indexFindings(base.Findings)
	compareIndex := indexFindings(compare.Findings)

	// Find added and changed.
	for key, cf := range compareIndex {
		bf, exists := baseIndex[key]
		if !exists {
			d.Added = append(d.Added, *cf)
			continue
		}
		// Check for status change.
		if cf.CryptoAsset != nil && bf.CryptoAsset != nil &&
			cf.CryptoAsset.PQCStatus != bf.CryptoAsset.PQCStatus {
			d.Changed = append(d.Changed, FindingChange{
				Finding:   *cf,
				OldStatus: bf.CryptoAsset.PQCStatus,
				NewStatus: cf.CryptoAsset.PQCStatus,
			})
		}
	}

	// Find removed.
	for key, bf := range baseIndex {
		if _, exists := compareIndex[key]; !exists {
			d.Removed = append(d.Removed, *bf)
		}
	}

	// Compute summary.
	d.Summary = DiffSummary{
		AddedCount:   len(d.Added),
		RemovedCount: len(d.Removed),
		ChangedCount: len(d.Changed),
		SafeDelta:    compare.Summary.Safe - base.Summary.Safe,
		UnsafeDelta:  compare.Summary.Unsafe - base.Summary.Unsafe,
		NACSADelta:   compare.Summary.NACSAReadinessPercent - base.Summary.NACSAReadinessPercent,
	}

	return d
}

// findingKey generates a composite key for matching findings across scans.
// Format: (source_type, path_or_endpoint, algorithm)
func findingKey(f *model.Finding) string {
	algo := ""
	if f.CryptoAsset != nil {
		algo = strings.ToUpper(f.CryptoAsset.Algorithm)
	}

	switch f.Source.Type {
	case "file":
		return fmt.Sprintf("file:%s:%s", f.Source.Path, algo)
	case "network":
		return fmt.Sprintf("net:%s:%s", f.Source.Endpoint, algo)
	case "process":
		return fmt.Sprintf("proc:%s:%s", f.Source.Path, algo)
	default:
		return fmt.Sprintf("%s:%s:%s", f.Source.Type, f.Source.Path, algo)
	}
}

// indexFindings builds a map of finding key -> finding pointer for fast lookup.
// If multiple findings have the same key, the last one wins.
func indexFindings(findings []model.Finding) map[string]*model.Finding {
	idx := make(map[string]*model.Finding, len(findings))
	for i := range findings {
		idx[findingKey(&findings[i])] = &findings[i]
	}
	return idx
}
