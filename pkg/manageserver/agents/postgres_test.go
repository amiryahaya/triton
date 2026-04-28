//go:build integration

package agents_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_agents_%d", testSchemaSeq.Add(1))

	ctx := context.Background()
	setupPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		setupPool.Close()
		t.Fatalf("drop stale schema: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		setupPool.Close()
		t.Fatalf("create schema: %v", err)
	}
	setupPool.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		cleanup, cerr := pgxpool.New(context.Background(), dbURL)
		if cerr != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

// mkAgent returns a minimally-populated Agent ready for Create.
func mkAgent(name, serial string) agents.Agent {
	return agents.Agent{
		ID:            uuid.Must(uuid.NewV7()),
		Name:          name,
		CertSerial:    serial,
		CertExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		Status:        agents.StatusPending,
	}
}

func TestAgents_CreateGetList(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("alpha", "serial-a")
	created, err := s.Create(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, a.ID, created.ID)
	assert.False(t, created.CreatedAt.IsZero())

	got, err := s.Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "alpha", got.Name)
	assert.Equal(t, agents.StatusPending, got.Status)

	// List returns [alpha].
	b := mkAgent("beta", "serial-b")
	_, err = s.Create(ctx, b)
	require.NoError(t, err)

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "alpha", list[0].Name)
	assert.Equal(t, "beta", list[1].Name)
}

func TestAgents_GetByCertSerial(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("alpha", "unique-serial-x")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)

	got, err := s.GetByCertSerial(ctx, "unique-serial-x")
	require.NoError(t, err)
	assert.Equal(t, a.ID, got.ID)

	_, err = s.GetByCertSerial(ctx, "no-such-serial")
	assert.ErrorIs(t, err, agents.ErrNotFound)
}

func TestAgents_Create_NilIDRejected(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	_, err := s.Create(ctx, agents.Agent{
		Name:          "ghost",
		CertSerial:    "serial-z",
		CertExpiresAt: time.Now().Add(24 * time.Hour),
	})
	require.Error(t, err)
}

func TestAgents_DuplicateSerial_ReturnsConflict(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	_, err := s.Create(ctx, mkAgent("first", "dup"))
	require.NoError(t, err)

	_, err = s.Create(ctx, mkAgent("second", "dup"))
	assert.ErrorIs(t, err, agents.ErrConflict)
}

func TestAgents_MarkActive(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("alpha", "serial-a")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)

	require.NoError(t, s.MarkActive(ctx, a.ID))

	got, err := s.Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, agents.StatusActive, got.Status)
	require.NotNil(t, got.LastSeenAt)
	assert.WithinDuration(t, time.Now(), *got.LastSeenAt, 5*time.Second)
}

func TestAgents_MarkActive_RejectsRevoked(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("alpha", "serial-a")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, a.ID))

	// A revoked agent must not flip back to active.
	err = s.MarkActive(ctx, a.ID)
	assert.ErrorIs(t, err, agents.ErrNotFound)

	got, err := s.Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, agents.StatusRevoked, got.Status)
}

func TestAgents_UpdateCert(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("alpha", "old-serial")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)

	newExpiry := time.Now().Add(365 * 24 * time.Hour).UTC()
	require.NoError(t, s.UpdateCert(ctx, a.ID, "new-serial", newExpiry))

	got, err := s.Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-serial", got.CertSerial)
	assert.WithinDuration(t, newExpiry, got.CertExpiresAt, time.Second)
}

func TestAgents_Count(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	n, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)

	_, err = s.Create(ctx, mkAgent("alpha", "a"))
	require.NoError(t, err)
	_, err = s.Create(ctx, mkAgent("beta", "b"))
	require.NoError(t, err)

	n, err = s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
}

func TestAgents_Revoke_NotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	err := s.Revoke(ctx, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, agents.ErrNotFound)
}

func TestAgentStore_CommandRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("cmd-agent", "serial-cmd")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)

	// Initially no command.
	cmd, err := s.PopCommand(ctx, a.ID)
	require.NoError(t, err)
	assert.Nil(t, cmd, "expected nil command on fresh agent")

	// Set a command.
	want := &agents.AgentCommand{ScanProfile: "standard", JobID: "job-abc-123"}
	require.NoError(t, s.SetCommand(ctx, a.ID, want))

	// Pop returns the command and clears it.
	got, err := s.PopCommand(ctx, a.ID)
	require.NoError(t, err)
	require.NotNil(t, got, "expected command after SetCommand")
	assert.Equal(t, want.ScanProfile, got.ScanProfile)
	assert.Equal(t, want.JobID, got.JobID)

	// Second pop returns nil (command was cleared).
	cmd2, err := s.PopCommand(ctx, a.ID)
	require.NoError(t, err)
	assert.Nil(t, cmd2, "expected nil on second pop")
}

func TestAgentStore_SetCommand_Overwrites(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	a := mkAgent("cmd-agent-2", "serial-cmd-2")
	_, err := s.Create(ctx, a)
	require.NoError(t, err)

	first := &agents.AgentCommand{ScanProfile: "quick", JobID: "job-first"}
	require.NoError(t, s.SetCommand(ctx, a.ID, first))

	second := &agents.AgentCommand{ScanProfile: "comprehensive", JobID: "job-second"}
	require.NoError(t, s.SetCommand(ctx, a.ID, second))

	got, err := s.PopCommand(ctx, a.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "comprehensive", got.ScanProfile, "SetCommand must overwrite previous")
	assert.Equal(t, "job-second", got.JobID)
}

func TestAgentStore_SetCommand_NotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	err := s.SetCommand(ctx, uuid.Must(uuid.NewV7()), &agents.AgentCommand{ScanProfile: "quick"})
	assert.ErrorIs(t, err, agents.ErrNotFound)
}

func TestAgentStore_PopCommand_NotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	s := agents.NewPostgresStore(pool)

	_, err := s.PopCommand(ctx, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, agents.ErrNotFound)
}
