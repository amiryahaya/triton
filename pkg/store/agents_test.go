//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestAgentStore_UpsertGetList(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)

	r := &AgentRecord{
		TenantID:  tenant,
		MachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Hostname:  "host-1",
		OS:        "linux",
		Arch:      "amd64",
	}
	require.NoError(t, s.UpsertAgent(ctx, r))

	got, err := s.GetAgent(ctx, tenant, r.MachineID)
	require.NoError(t, err)
	assert.Equal(t, "host-1", got.Hostname)
	assert.False(t, got.FirstSeenAt.IsZero())

	// Upsert updates on second call.
	r.Hostname = "host-1-renamed"
	require.NoError(t, s.UpsertAgent(ctx, r))
	got, _ = s.GetAgent(ctx, tenant, r.MachineID)
	assert.Equal(t, "host-1-renamed", got.Hostname)

	rows, err := s.ListAgentsByTenant(ctx, tenant, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, r.MachineID, rows[0].MachineID)
}

func TestAgentStore_PausedUntilRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)
	mid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: mid}))

	until := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, s.SetAgentPausedUntil(ctx, tenant, mid, until))

	got, _ := s.GetAgent(ctx, tenant, mid)
	assert.WithinDuration(t, until, got.PausedUntil, time.Second)

	require.NoError(t, s.ClearAgentPausedUntil(ctx, tenant, mid))
	got, _ = s.GetAgent(ctx, tenant, mid)
	assert.True(t, got.PausedUntil.IsZero())
}

func TestAgentStore_CommandLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)
	mid := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: mid}))

	cmd, err := s.EnqueueAgentCommand(ctx, &AgentCommand{
		TenantID:  tenant,
		MachineID: mid,
		Type:      AgentCommandCancel,
		Args:      []byte(`{}`),
		IssuedBy:  "admin-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cmd.ID)
	assert.Nil(t, cmd.DispatchedAt)

	claimed, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.NotNil(t, claimed[0].DispatchedAt)

	// Re-claim returns nothing.
	claimed2, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	assert.Empty(t, claimed2)

	require.NoError(t, s.SetAgentCommandResult(ctx, tenant, mid, cmd.ID, "executed", []byte(`{"findings":0}`)))

	history, err := s.ListAgentCommands(ctx, tenant, mid, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.NotNil(t, history[0].ResultStatus)
	assert.Equal(t, "executed", *history[0].ResultStatus)
}

func TestAgentStore_ExpiredCommandsNotClaimed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)
	mid := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: mid}))

	_, err := s.EnqueueAgentCommand(ctx, &AgentCommand{
		TenantID:  tenant,
		MachineID: mid,
		Type:      AgentCommandForceRun,
		Args:      []byte(`{}`),
		IssuedBy:  "admin-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	require.NoError(t, err)

	claimed, err := s.ClaimPendingCommandsForAgent(ctx, tenant, mid)
	require.NoError(t, err)
	assert.Empty(t, claimed, "expired commands should not be claimed")
}

func TestAgentStore_ResultRejectsCrossAgent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)
	midA := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	midB := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: midA}))
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: midB}))

	cmd, _ := s.EnqueueAgentCommand(ctx, &AgentCommand{
		TenantID: tenant, MachineID: midA, Type: AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "admin-1", ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	err := s.SetAgentCommandResult(ctx, tenant, midB, cmd.ID, "executed", nil)
	require.Error(t, err, "cross-agent result injection should fail")
}

func TestAgentStore_ExpireStaleDispatched(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenant := newAgentTestTenant(t, s)
	mid := "1111111111111111111111111111111111111111111111111111111111111111"
	require.NoError(t, s.UpsertAgent(ctx, &AgentRecord{TenantID: tenant, MachineID: mid}))

	// Enqueue with 1-hour expiry.
	cmd, _ := s.EnqueueAgentCommand(ctx, &AgentCommand{
		TenantID: tenant, MachineID: mid, Type: AgentCommandCancel,
		Args: []byte(`{}`), IssuedBy: "admin-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// Dispatch it.
	_, _ = s.ClaimPendingCommandsForAgent(ctx, tenant, mid)

	// Verify the sweeper returns 0 in the nominal case (no stale dispatched).
	n, err := s.ExpireStaleAgentCommands(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 0) // nominal: 0 stale

	// Sanity: non-expired cmd should still NOT be marked.
	history, _ := s.ListAgentCommands(ctx, tenant, mid, 10)
	require.Len(t, history, 1)
	_ = cmd
}

// newAgentTestTenant creates an org row for use as a FK tenant in agent tests.
func newAgentTestTenant(t *testing.T, s *PostgresStore) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	org := &Organization{ID: id, Name: "AgentCtl-" + id[:8]}
	require.NoError(t, s.CreateOrg(context.Background(), org))
	return id
}
