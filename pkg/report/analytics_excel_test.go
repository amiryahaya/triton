package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestGenerateAnalyticsExcel_ProducesValidFile(t *testing.T) {
	now := time.Now()
	data := &AnalyticsExcelData{
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
			CertsExpiring30d: 7,
			CertsExpiring90d: 15,
			CertsExpired:     3,
		},
		Hosts: []store.HostSummary{
			{Hostname: "legacy-1", ReadinessPct: 12.0, TotalFindings: 20, SafeFindings: 2,
				TransitionalFindings: 2, DeprecatedFindings: 12, UnsafeFindings: 4,
				TrendDirection: "declining", MaxPriority: 92, ScannedAt: now},
		},
		Remediation: &store.RemediationSummary{Open: 142, InProgress: 8, Resolved: 23, Accepted: 11, Total: 184},
		Blockers: []store.PriorityRow{
			{Hostname: "web-srv1", Algorithm: "RSA-1024", KeySize: 1024, PQCStatus: "UNSAFE", Module: "certificate", Priority: 92, FilePath: "/etc/ssl/cert.pem"},
		},
		Certs: []store.ExpiringCertRow{
			{FindingID: "c1", Subject: "*.example.com", Hostname: "web-srv1", Algorithm: "RSA", KeySize: 2048, NotAfter: now.Add(24 * time.Hour), DaysRemaining: 1, Status: "urgent"},
		},
		StatusLog: []store.FindingStatusEntry{
			{FindingKey: "abc123def456", Status: "resolved", Reason: "migrated to AES-256", ChangedBy: "admin-user", ChangedAt: now},
		},
		GeneratedAt: now,
	}

	outputPath := filepath.Join(t.TempDir(), "test-report.xlsx")
	err := GenerateAnalyticsExcel(data, outputPath)
	require.NoError(t, err)

	f, err := excelize.OpenFile(outputPath)
	require.NoError(t, err)
	defer f.Close()

	sheets := f.GetSheetList()
	assert.Equal(t, 5, len(sheets), "workbook must have 5 sheets")
	assert.Equal(t, "Executive Summary", sheets[0])
	assert.Equal(t, "Systems Health", sheets[1])
	assert.Equal(t, "Top Blockers", sheets[2])
	assert.Equal(t, "Expiring Certificates", sheets[3])
	assert.Equal(t, "Remediation Log", sheets[4])
}

func TestGenerateAnalyticsExcel_EmptyData(t *testing.T) {
	data := &AnalyticsExcelData{
		OrgName:     "Empty Org",
		GeneratedAt: time.Now(),
	}

	outputPath := filepath.Join(t.TempDir(), "empty-report.xlsx")
	err := GenerateAnalyticsExcel(data, outputPath)
	require.NoError(t, err)

	f, err := excelize.OpenFile(outputPath)
	require.NoError(t, err)
	defer f.Close()
	assert.Equal(t, 5, len(f.GetSheetList()))
}
