package report

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func testScan(id, hostname string, safe, trans, depr, unsafe int) *model.ScanResult {
	findings := make([]model.Finding, 0)
	addFindings := func(status string, count int) {
		for i := 0; i < count; i++ {
			findings = append(findings, model.Finding{
				CryptoAsset: &model.CryptoAsset{
					Algorithm: status + "-algo",
					PQCStatus: status,
				},
			})
		}
	}
	addFindings("SAFE", safe)
	addFindings("TRANSITIONAL", trans)
	addFindings("DEPRECATED", depr)
	addFindings("UNSAFE", unsafe)

	return &model.ScanResult{
		ID: id,
		Metadata: model.ScanMetadata{
			Timestamp: time.Now().UTC(),
			Hostname:  hostname,
		},
		Findings: findings,
		Summary: model.Summary{
			TotalFindings: safe + trans + depr + unsafe,
			Safe:          safe,
			Transitional:  trans,
			Deprecated:    depr,
			Unsafe:        unsafe,
		},
	}
}

func TestGenerateAggregate_Basic(t *testing.T) {
	scans := []*model.ScanResult{
		testScan("s1", "host-a", 5, 2, 1, 0),
		testScan("s2", "host-b", 3, 0, 0, 2),
	}

	agg := GenerateAggregate(scans)

	assert.Equal(t, 2, agg.MachineCount)
	assert.Equal(t, 13, agg.TotalFindings)
	assert.Equal(t, 8, agg.Safe)
	assert.Equal(t, 2, agg.Transitional)
	assert.Equal(t, 1, agg.Deprecated)
	assert.Equal(t, 2, agg.Unsafe)
}

func TestGenerateAggregate_DeduplicateByHostname(t *testing.T) {
	earlier := testScan("s1", "host-a", 1, 0, 0, 0)
	earlier.Metadata.Timestamp = time.Now().Add(-1 * time.Hour)
	later := testScan("s2", "host-a", 5, 0, 0, 0)
	later.Metadata.Timestamp = time.Now()

	agg := GenerateAggregate([]*model.ScanResult{earlier, later})

	assert.Equal(t, 1, agg.MachineCount)
	assert.Equal(t, 5, agg.Safe) // Should use the later scan
}

func TestGenerateAggregate_NACSAReadiness(t *testing.T) {
	scans := []*model.ScanResult{
		testScan("s1", "host-a", 8, 2, 0, 0),
	}

	agg := GenerateAggregate(scans)

	assert.InDelta(t, 80.0, agg.NACSAReadiness, 0.1)
}

func TestGenerateAggregate_WorstMachines(t *testing.T) {
	scans := []*model.ScanResult{
		testScan("s1", "host-a", 10, 0, 0, 0), // Risk: 0
		testScan("s2", "host-b", 0, 0, 0, 5),  // Risk: 20
		testScan("s3", "host-c", 0, 0, 3, 0),  // Risk: 9
	}

	agg := GenerateAggregate(scans)

	assert.Len(t, agg.WorstMachines, 3)
	assert.Equal(t, "host-b", agg.WorstMachines[0].Hostname) // Highest risk
}

func TestGenerateAggregate_CommonAlgorithms(t *testing.T) {
	scans := []*model.ScanResult{
		testScan("s1", "host-a", 3, 0, 0, 0),
		testScan("s2", "host-b", 2, 0, 0, 0),
	}

	agg := GenerateAggregate(scans)

	assert.NotEmpty(t, agg.CommonAlgorithms)
	// SAFE-algo should appear in both machines
	found := false
	for _, a := range agg.CommonAlgorithms {
		if a.Algorithm == "SAFE-algo" {
			found = true
			assert.Equal(t, 2, a.MachineCount)
			assert.Equal(t, 5, a.TotalCount) // 3+2
		}
	}
	assert.True(t, found)
}

func TestGenerateAggregate_Empty(t *testing.T) {
	agg := GenerateAggregate(nil)

	assert.Equal(t, 0, agg.MachineCount)
	assert.Equal(t, 0, agg.TotalFindings)
	assert.InDelta(t, 0.0, agg.NACSAReadiness, 0.001)
}
