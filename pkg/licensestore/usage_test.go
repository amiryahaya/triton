//go:build integration

package licensestore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestUsage_UpsertAndSummary(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	inst := uuid.NewString()
	reports := []licensestore.UsageReport{
		{LicenseID: lic.ID, InstanceID: inst, Metric: "seats", Window: "total", Value: 12},
		{LicenseID: lic.ID, InstanceID: inst, Metric: "scans", Window: "monthly", Value: 150},
	}
	require.NoError(t, s.UpsertUsage(ctx, reports))

	// Second push with updated value — should overwrite.
	reports[0].Value = 13
	require.NoError(t, s.UpsertUsage(ctx, reports))

	sum, err := s.UsageSummary(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(13), sum["seats"]["total"])
	assert.Equal(t, int64(150), sum["scans"]["monthly"])
}

func TestUsage_MultipleInstancesSum(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	inst1, inst2 := uuid.NewString(), uuid.NewString()
	require.NoError(t, s.UpsertUsage(ctx, []licensestore.UsageReport{
		{LicenseID: lic.ID, InstanceID: inst1, Metric: "seats", Window: "total", Value: 10},
	}))
	require.NoError(t, s.UpsertUsage(ctx, []licensestore.UsageReport{
		{LicenseID: lic.ID, InstanceID: inst2, Metric: "seats", Window: "total", Value: 15},
	}))

	sum, err := s.UsageSummary(ctx, lic.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(25), sum["seats"]["total"], "should sum across instances")
}

func TestUsage_EmptyBatchNoop(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	require.NoError(t, s.UpsertUsage(ctx, nil))
	require.NoError(t, s.UpsertUsage(ctx, []licensestore.UsageReport{}))
}

func TestUsage_ByInstance(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))
	lic := makeLicense(t, org.ID)
	require.NoError(t, s.CreateLicense(ctx, lic))

	inst := uuid.NewString()
	require.NoError(t, s.UpsertUsage(ctx, []licensestore.UsageReport{
		{LicenseID: lic.ID, InstanceID: inst, Metric: "seats", Window: "total", Value: 7},
		{LicenseID: lic.ID, InstanceID: inst, Metric: "scans", Window: "monthly", Value: 100},
	}))

	rows, err := s.UsageByInstance(ctx, lic.ID)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
}
