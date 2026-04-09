//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// saveScan is a shared test helper that creates a scan with the given
// ID/hostname/orgID, runs ExtractFindings, and calls
// SaveScanWithFindings. It replaces the scan's pre-seeded findings
// entirely with the supplied list so tests get exactly the rows they
// ask for.
func saveScan(t *testing.T, s *PostgresStore, id, hostname, orgID string, findings ...model.Finding) *model.ScanResult {
	t.Helper()
	scan := testScanResult(id, hostname, "quick")
	scan.OrgID = orgID
	scan.Findings = findings
	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, ExtractFindings(scan)))
	return scan
}

// cryptoF is a terse helper that builds a file-sourced finding with
// the given module, path, and CryptoAsset.
func cryptoF(module, path string, ca *model.CryptoAsset) model.Finding {
	return model.Finding{
		Module:      module,
		Source:      model.FindingSource{Type: "file", Path: path},
		CryptoAsset: ca,
	}
}

// queryFindingsCount counts findings rows for a scan using the
// package-private pool directly. Only available to tests in
// pkg/store.
func queryFindingsCount(t *testing.T, s *PostgresStore, scanID string) int {
	t.Helper()
	var count int
	err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE scan_id = $1`, scanID).Scan(&count)
	require.NoError(t, err)
	return count
}

// queryScanBackfilled returns true if the scan row has
// findings_extracted_at set.
func queryScanBackfilled(t *testing.T, s *PostgresStore, scanID string) bool {
	t.Helper()
	var markedAt *time.Time
	err := s.pool.QueryRow(context.Background(),
		`SELECT findings_extracted_at FROM scans WHERE id = $1`, scanID).Scan(&markedAt)
	require.NoError(t, err)
	return markedAt != nil
}

// findInventoryRow locates an inventory row by (algorithm, keySize).
func findInventoryRow(rows []InventoryRow, algo string, size int) *InventoryRow {
	for i := range rows {
		if rows[i].Algorithm == algo && rows[i].KeySize == size {
			return &rows[i]
		}
	}
	return nil
}

// --- SaveScanWithFindings ---

func TestSaveScanWithFindings_StoresScanAndFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org")

	scan := saveScan(t, s, testUUID("swf-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE", MigrationPriority: 10}),
	)

	retrieved, err := s.GetScan(context.Background(), scan.ID, orgID)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, retrieved.ID)

	assert.Equal(t, 2, queryFindingsCount(t, s, scan.ID))
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestSaveScanWithFindings_SkipsNonCryptoFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org-2")

	scan := saveScan(t, s, testUUID("swf-2"), "host-2", orgID,
		model.Finding{Module: "file", Source: model.FindingSource{Path: "/plain"}},
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	)
	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}

func TestSaveScanWithFindings_OnConflictSkipsDuplicates(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org-3")

	scan := testScanResult(testUUID("swf-3"), "host-3", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	extracted := ExtractFindings(scan)

	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, extracted))
	// Second save with the SAME extracted rows — ON CONFLICT DO NOTHING
	// should absorb the duplicates (same scan_id + finding_index).
	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, extracted))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}

// --- ListInventory ---

func TestListInventory_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListInventory(context.Background(), testUUID("empty-org"))
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListInventory_SingleFinding(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-org")
	_ = saveScan(t, s, testUUID("inv-1"), "host-1", orgID,
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	)

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
	assert.Equal(t, "DEPRECATED", rows[0].PQCStatus)
	assert.Equal(t, 1, rows[0].Instances)
	assert.Equal(t, 1, rows[0].Machines)
	assert.Equal(t, 80, rows[0].MaxPriority)
}

func TestListInventory_GroupsByAlgorithmAndSize(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-grp")
	_ = saveScan(t, s, testUUID("inv-grp-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 75}),
		cryptoF("key", "/c", &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE", MigrationPriority: 0}),
	)

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	rsa2048 := findInventoryRow(rows, "RSA", 2048)
	require.NotNil(t, rsa2048)
	assert.Equal(t, 2, rsa2048.Instances)
	assert.Equal(t, 1, rsa2048.Machines)
	assert.Equal(t, 80, rsa2048.MaxPriority)

	rsa4096 := findInventoryRow(rows, "RSA", 4096)
	require.NotNil(t, rsa4096)
	assert.Equal(t, "SAFE", rsa4096.PQCStatus)
}

func TestListInventory_TenantIsolation(t *testing.T) {
	s := testStore(t)
	orgA := testUUID("inv-tenant-a")
	orgB := testUUID("inv-tenant-b")

	_ = saveScan(t, s, testUUID("inv-tenant-scan-a"), "host-a", orgA,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED"}),
	)
	_ = saveScan(t, s, testUUID("inv-tenant-scan-b"), "host-b", orgB,
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE"}),
	)

	rowsA, err := s.ListInventory(context.Background(), orgA)
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, "RSA", rowsA[0].Algorithm)

	rowsB, err := s.ListInventory(context.Background(), orgB)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, "AES", rowsB[0].Algorithm)
}

func TestListInventory_LatestScanPerHostOnly(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-latest")

	oldScan := testScanResult(testUUID("inv-latest-old"), "host-1", "quick")
	oldScan.OrgID = orgID
	oldScan.Metadata.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	oldScan.Findings = []model.Finding{
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 1024, PQCStatus: "UNSAFE"}),
	}
	require.NoError(t, s.SaveScanWithFindings(context.Background(), oldScan, ExtractFindings(oldScan)))

	newScan := testScanResult(testUUID("inv-latest-new"), "host-1", "quick")
	newScan.OrgID = orgID
	newScan.Metadata.Timestamp = time.Now().UTC()
	newScan.Findings = []model.Finding{
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE"}),
	}
	require.NoError(t, s.SaveScanWithFindings(context.Background(), newScan, ExtractFindings(newScan)))

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the latest scan per host counts")
	assert.Equal(t, 4096, rows[0].KeySize)
}

// --- ListExpiringCertificates ---

func TestListExpiringCerts_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListExpiringCertificates(context.Background(), testUUID("cert-empty"), 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListExpiringCerts_WithinWindow(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-window")
	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-win-1"), "host-1", orgID,
		cryptoF("certificate", "/soon.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in30, Subject: "CN=soon"}),
		cryptoF("certificate", "/later.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in200, Subject: "CN=later"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the 30-day cert is inside the 90-day window")
	assert.Equal(t, "CN=soon", rows[0].Subject)
}

func TestListExpiringCerts_AlreadyExpiredAlwaysIncluded(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-expired")
	expired := time.Now().UTC().Add(-10 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-expired-1"), "host-1", orgID,
		cryptoF("certificate", "/dead.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &expired, Subject: "CN=dead"}),
	)

	// Even a 1-hour window includes already-expired certs.
	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 1*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=dead", rows[0].Subject)
	assert.True(t, rows[0].DaysRemaining < 0)
	assert.Equal(t, "expired", rows[0].Status)
}

func TestListExpiringCerts_NullNotAfterExcluded(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-null")
	_ = saveScan(t, s, testUUID("cert-null-1"), "host-1", orgID,
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListExpiringCerts_SortedAscending(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-sort")
	in15 := time.Now().UTC().Add(15 * 24 * time.Hour)
	in45 := time.Now().UTC().Add(45 * 24 * time.Hour)
	in5 := time.Now().UTC().Add(5 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-sort-1"), "host-1", orgID,
		cryptoF("certificate", "/15.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in15, Subject: "CN=fifteen"}),
		cryptoF("certificate", "/45.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in45, Subject: "CN=forty-five"}),
		cryptoF("certificate", "/5.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in5, Subject: "CN=five"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, "CN=five", rows[0].Subject)
	assert.Equal(t, "CN=fifteen", rows[1].Subject)
	assert.Equal(t, "CN=forty-five", rows[2].Subject)
}

func TestListExpiringCerts_LargeWithinReturnsFuture(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-all")
	inYear := time.Now().UTC().Add(400 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-all-1"), "host-1", orgID,
		cryptoF("certificate", "/far.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &inYear, Subject: "CN=far"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 100*365*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=far", rows[0].Subject)
}

// --- ListTopPriorityFindings ---

func TestListPriority_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListTopPriorityFindings(context.Background(), testUUID("prio-empty"), 20)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListPriority_SortedDescending(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-sort")
	_ = saveScan(t, s, testUUID("prio-sort-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "MD5", MigrationPriority: 95}),
		cryptoF("key", "/c", &model.CryptoAsset{Algorithm: "SHA-1", MigrationPriority: 80}),
	)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, 95, rows[0].Priority)
	assert.Equal(t, 80, rows[1].Priority)
	assert.Equal(t, 50, rows[2].Priority)
}

func TestListPriority_LimitRespected(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-limit")
	findings := make([]model.Finding, 0, 30)
	for i := 0; i < 30; i++ {
		findings = append(findings, cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	_ = saveScan(t, s, testUUID("prio-limit-1"), "host-1", orgID, findings...)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 10)

	rowsAll, err := s.ListTopPriorityFindings(context.Background(), orgID, 100)
	require.NoError(t, err)
	assert.Len(t, rowsAll, 30)
}

func TestListPriority_ExcludesZeroPriority(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-zero")
	_ = saveScan(t, s, testUUID("prio-zero-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "AES", MigrationPriority: 0}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}),
	)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
}

func TestListPriority_LimitZeroDefaultsTo20(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-default")
	findings := make([]model.Finding, 0, 25)
	for i := 0; i < 25; i++ {
		findings = append(findings, cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	_ = saveScan(t, s, testUUID("prio-default-1"), "host-1", orgID, findings...)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 20)
}

// --- DeleteScan cascade (Task 1.12) ---

func TestDeleteScan_CascadesToFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cascade-org")

	scan := saveScan(t, s, testUUID("cascade-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}),
	)
	require.Equal(t, 2, queryFindingsCount(t, s, scan.ID))

	require.NoError(t, s.DeleteScan(context.Background(), scan.ID, orgID))

	assert.Equal(t, 0, queryFindingsCount(t, s, scan.ID),
		"ON DELETE CASCADE should have removed the findings rows")
}
