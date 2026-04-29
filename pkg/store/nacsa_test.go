//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetNacsaSummary_Empty(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("nacsa-summary-empty-org")

	summary, err := s.GetNacsaSummary(context.Background(), orgID, NacsaScopeFilter{})
	require.NoError(t, err)
	assert.Equal(t, float64(0), summary.ReadinessPct)
	assert.Equal(t, int64(0), summary.TotalAssets)
	assert.Empty(t, summary.TopBlockers)
	assert.Equal(t, float64(80), summary.TargetPct)
	assert.Equal(t, 2030, summary.TargetYear)
}

func TestListNacsaServers_Empty(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("nacsa-servers-empty-org")

	servers, err := s.ListNacsaServers(context.Background(), orgID)
	require.NoError(t, err)
	assert.NotNil(t, servers)
	assert.Empty(t, servers)
}

func TestGetNacsaMigration_Empty(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("nacsa-migration-empty-org")

	resp, err := s.GetNacsaMigration(context.Background(), orgID)
	require.NoError(t, err)
	assert.NotNil(t, resp.Phases)
	assert.Empty(t, resp.Phases)
}
