package diff

import (
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// Trend holds multi-scan trend data.
type Trend struct {
	Points []TrendPoint `json:"points"`
}

// TrendPoint captures a single scan's metrics at a point in time.
type TrendPoint struct {
	ScanID       string    `json:"scanID"`
	Timestamp    time.Time `json:"timestamp"`
	Hostname     string    `json:"hostname"`
	Safe         int       `json:"safe"`
	Transitional int       `json:"transitional"`
	Deprecated   int       `json:"deprecated"`
	Unsafe       int       `json:"unsafe"`
	NACSAPercent float64   `json:"nacsaPercent"`
	CAMMLevel    int       `json:"cammLevel"`
	Total        int       `json:"total"`
}

// ComputeTrend computes trend data from a chronologically-ordered list of scan results.
// The input should be sorted from oldest to newest.
func ComputeTrend(scans []*model.ScanResult) *Trend {
	t := &Trend{
		Points: make([]TrendPoint, 0, len(scans)),
	}

	for _, s := range scans {
		point := TrendPoint{
			ScanID:       s.ID,
			Timestamp:    s.Metadata.Timestamp,
			Hostname:     s.Metadata.Hostname,
			Safe:         s.Summary.Safe,
			Transitional: s.Summary.Transitional,
			Deprecated:   s.Summary.Deprecated,
			Unsafe:       s.Summary.Unsafe,
			NACSAPercent: s.Summary.NACSAReadinessPercent,
			CAMMLevel:    s.Summary.CAMMLevel,
			Total:        s.Summary.Safe + s.Summary.Transitional + s.Summary.Deprecated + s.Summary.Unsafe,
		}
		t.Points = append(t.Points, point)
	}

	return t
}

// Direction returns "improving", "declining", or "stable" based on the trend.
func (t *Trend) Direction() string {
	if len(t.Points) < 2 {
		return "stable"
	}

	first := t.Points[0]
	last := t.Points[len(t.Points)-1]

	firstSafe := safePercent(first)
	lastSafe := safePercent(last)

	if lastSafe > firstSafe+1.0 {
		return "improving"
	}
	if lastSafe < firstSafe-1.0 {
		return "declining"
	}
	return "stable"
}

func safePercent(p TrendPoint) float64 {
	if p.Total == 0 {
		return 0
	}
	return float64(p.Safe) / float64(p.Total) * 100
}
