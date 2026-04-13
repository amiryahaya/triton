package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestGenerateAnalyticsPDF_ProducesValidFile(t *testing.T) {
	data := &AnalyticsReportData{
		OrgName: "Test Organization",
		Snapshot: &store.OrgSnapshot{
			ReadinessPct:     73.2,
			TotalFindings:    184,
			SafeFindings:     135,
			MachinesTotal:    50,
			MachinesRed:      4,
			MachinesYellow:   15,
			MachinesGreen:    31,
			TrendDirection:   "improving",
			TrendDeltaPct:    3.1,
			ProjectionStatus: "on-track",
			ProjectedYear:    2029,
			TargetPct:        80.0,
			DeadlineYear:     2030,
			PolicyVerdicts: []store.PolicyVerdictSummary{
				{PolicyLabel: "NACSA-2030", Verdict: "WARN", ViolationCount: 12, FindingsChecked: 184},
				{PolicyLabel: "CNSA 2.0", Verdict: "FAIL", ViolationCount: 28, FindingsChecked: 184},
			},
			TopBlockers: []store.PriorityRow{
				{Priority: 92, Algorithm: "RSA-1024", PQCStatus: "UNSAFE", Hostname: "web-srv1"},
				{Priority: 90, Algorithm: "DES", PQCStatus: "UNSAFE", Hostname: "legacy-1"},
			},
			CertsExpiring30d: 7,
			CertsExpiring90d: 15,
			CertsExpired:     3,
		},
		Hosts: []store.HostSummary{
			{Hostname: "legacy-1", ReadinessPct: 12.0, UnsafeFindings: 4, DeprecatedFindings: 12, TrendDirection: "declining"},
			{Hostname: "web-srv1", ReadinessPct: 45.0, UnsafeFindings: 0, DeprecatedFindings: 8, TrendDirection: "improving"},
		},
		Remediation: &store.RemediationSummary{Open: 142, InProgress: 8, Resolved: 23, Accepted: 11, Total: 184},
		GeneratedAt: time.Date(2026, 4, 13, 14, 32, 0, 0, time.UTC),
	}

	outputPath := filepath.Join(t.TempDir(), "test-report.pdf")
	err := GenerateAnalyticsPDF(data, outputPath)
	require.NoError(t, err)

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "PDF must not be empty")

	// Check PDF magic bytes
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.True(t, len(content) >= 4 && string(content[:4]) == "%PDF", "file must start with PDF magic bytes")
}

func TestGenerateAnalyticsPDF_EmptySnapshot(t *testing.T) {
	data := &AnalyticsReportData{
		OrgName:     "Empty Org",
		Snapshot:    nil,
		Hosts:       nil,
		Remediation: nil,
		GeneratedAt: time.Now(),
	}

	outputPath := filepath.Join(t.TempDir(), "empty-report.pdf")
	err := GenerateAnalyticsPDF(data, outputPath)
	require.NoError(t, err)

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}
