package diff

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
)

func trendScans() []*model.ScanResult {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []*model.ScanResult{
		{
			ID:       "s1",
			Metadata: model.ScanMetadata{Timestamp: base, Hostname: "host"},
			Summary:  model.Summary{Safe: 1, Transitional: 3, Deprecated: 2, Unsafe: 4, NACSAReadinessPercent: 10},
		},
		{
			ID:       "s2",
			Metadata: model.ScanMetadata{Timestamp: base.Add(7 * 24 * time.Hour), Hostname: "host"},
			Summary:  model.Summary{Safe: 3, Transitional: 3, Deprecated: 2, Unsafe: 2, NACSAReadinessPercent: 30},
		},
		{
			ID:       "s3",
			Metadata: model.ScanMetadata{Timestamp: base.Add(14 * 24 * time.Hour), Hostname: "host"},
			Summary:  model.Summary{Safe: 6, Transitional: 2, Deprecated: 1, Unsafe: 1, NACSAReadinessPercent: 60},
		},
	}
}

func TestComputeTrend_PointCount(t *testing.T) {
	trend := ComputeTrend(trendScans())
	assert.Len(t, trend.Points, 3)
}

func TestComputeTrend_PointValues(t *testing.T) {
	trend := ComputeTrend(trendScans())

	p0 := trend.Points[0]
	assert.Equal(t, "s1", p0.ScanID)
	assert.Equal(t, 1, p0.Safe)
	assert.Equal(t, 4, p0.Unsafe)
	assert.Equal(t, 10, p0.Total)

	p2 := trend.Points[2]
	assert.Equal(t, "s3", p2.ScanID)
	assert.Equal(t, 6, p2.Safe)
	assert.Equal(t, 1, p2.Unsafe)
	assert.Equal(t, 10, p2.Total)
}

func TestTrend_DirectionImproving(t *testing.T) {
	trend := ComputeTrend(trendScans())
	assert.Equal(t, "improving", trend.Direction())
}

func TestTrend_DirectionDeclining(t *testing.T) {
	scans := trendScans()
	// Reverse: going from good to bad
	scans[0], scans[2] = scans[2], scans[0]
	trend := ComputeTrend(scans)
	assert.Equal(t, "declining", trend.Direction())
}

func TestTrend_DirectionStable(t *testing.T) {
	scans := []*model.ScanResult{
		{ID: "s1", Summary: model.Summary{Safe: 5, Transitional: 3, Deprecated: 1, Unsafe: 1}},
		{ID: "s2", Summary: model.Summary{Safe: 5, Transitional: 3, Deprecated: 1, Unsafe: 1}},
	}
	trend := ComputeTrend(scans)
	assert.Equal(t, "stable", trend.Direction())
}

func TestTrend_DirectionSingleScan(t *testing.T) {
	trend := ComputeTrend([]*model.ScanResult{{ID: "s1"}})
	assert.Equal(t, "stable", trend.Direction())
}

func TestTrend_Empty(t *testing.T) {
	trend := ComputeTrend(nil)
	assert.Empty(t, trend.Points)
	assert.Equal(t, "stable", trend.Direction())
}
