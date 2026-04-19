//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigration_AgentControlTables(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	cases := []struct {
		table, column, wantType string
	}{
		{"agents", "tenant_id", "uuid"},
		{"agents", "machine_id", "text"},
		{"agents", "paused_until", "timestamp with time zone"},
		{"agent_commands", "id", "uuid"},
		{"agent_commands", "type", "text"},
		{"agent_commands", "dispatched_at", "timestamp with time zone"},
		{"agent_commands", "args", "jsonb"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			got, err := s.QueryColumnTestOnly(ctx, tc.table, tc.column)
			require.NoError(t, err)
			assert.Equal(t, tc.wantType, got)
		})
	}
}

func TestAgentRecord_ZeroValues(t *testing.T) {
	var a AgentRecord
	assert.Empty(t, a.TenantID)
	assert.Empty(t, a.MachineID)
	assert.True(t, a.PausedUntil.IsZero())
}

func TestAgentCommand_ZeroValues(t *testing.T) {
	var c AgentCommand
	assert.Empty(t, c.ID)
	assert.Empty(t, c.Type)
	assert.Nil(t, c.DispatchedAt)
	assert.Nil(t, c.ResultStatus)
}

func TestAgentCommandType_Constants(t *testing.T) {
	assert.Equal(t, "cancel", string(AgentCommandCancel))
	assert.Equal(t, "force_run", string(AgentCommandForceRun))
}
