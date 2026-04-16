package jobqueue

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeReclaimer struct {
	mu     sync.Mutex
	calls  []time.Time
	notify chan struct{}
}

func (f *fakeReclaimer) ReclaimStale(_ context.Context, cutoff time.Time) error {
	f.mu.Lock()
	f.calls = append(f.calls, cutoff)
	n := f.notify
	f.mu.Unlock()
	if n != nil {
		select {
		case n <- struct{}{}:
		default:
		}
	}
	return nil
}

func TestQueue_BuildSQL_ContainsTableName(t *testing.T) {
	cfg := Config{
		Table:             "scan_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"completed", "failed", "cancelled"},
	}
	q := New(nil, cfg) // pool=nil is fine for SQL generation tests

	for name, sql := range map[string]string{
		"claimSelect":  q.claimSelectSQL,
		"claimUpdate":  q.claimUpdateSQL,
		"finish":       q.finishSQL,
		"reclaim":      q.reclaimSQL,
		"cancel":       q.cancelSQL,
		"disambiguate": q.disambiguateSQL,
		"cancelLookup": q.cancelLookupSQL,
	} {
		if !strings.Contains(sql, "scan_jobs") {
			t.Errorf("%s SQL does not contain table name 'scan_jobs': %s", name, sql)
		}
	}
}

func TestQueue_BuildSQL_ContainsAllColumns(t *testing.T) {
	cfg := Config{
		Table:             "credential_deliveries",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "acked_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"acked", "failed"},
	}
	q := New(nil, cfg)

	// claimSelect should reference engine_id, status, requested_at
	for _, col := range []string{"engine_id", "status", "requested_at"} {
		if !strings.Contains(q.claimSelectSQL, col) {
			t.Errorf("claimSelect missing %q: %s", col, q.claimSelectSQL)
		}
	}

	// claimUpdate should reference status, claimed_at
	for _, col := range []string{"status", "claimed_at"} {
		if !strings.Contains(q.claimUpdateSQL, col) {
			t.Errorf("claimUpdate missing %q: %s", col, q.claimUpdateSQL)
		}
	}

	// finish should reference acked_at (custom CompletedAtColumn) and
	// terminal statuses
	if !strings.Contains(q.finishSQL, "acked_at") {
		t.Errorf("finish SQL missing 'acked_at': %s", q.finishSQL)
	}
	for _, ts := range []string{"'acked'", "'failed'"} {
		if !strings.Contains(q.finishSQL, ts) {
			t.Errorf("finish SQL missing terminal status %s: %s", ts, q.finishSQL)
		}
	}

	// cancel should use completed_at column name from config
	if !strings.Contains(q.cancelSQL, "acked_at") {
		t.Errorf("cancel SQL missing 'acked_at': %s", q.cancelSQL)
	}
}

func TestQueue_BuildSQL_DefaultCompletedAtColumn(t *testing.T) {
	cfg := Config{
		Table:             "test_table",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		// CompletedAtColumn deliberately empty — should default
		QueuedStatus:     "queued",
		ClaimedStatus:    "claimed",
		TerminalStatuses: []string{"done"},
	}
	q := New(nil, cfg)

	if !strings.Contains(q.finishSQL, "completed_at") {
		t.Errorf("finish SQL should default to 'completed_at': %s", q.finishSQL)
	}
}

func TestNew_PanicsOnInvalidIdentifier(t *testing.T) {
	valid := Config{
		Table:             "scan_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"completed", "failed", "cancelled"},
	}

	tests := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"table with SQL injection", func(c *Config) { c.Table = `scan_jobs"; DROP TABLE scan_jobs; --` }},
		{"table with space", func(c *Config) { c.Table = "scan jobs" }},
		{"empty table", func(c *Config) { c.Table = "" }},
		{"status column with semicolon", func(c *Config) { c.StatusColumn = "status;evil" }},
		{"terminal status with quote", func(c *Config) { c.TerminalStatuses = []string{"completed", "'); DROP TABLE"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			cfg.TerminalStatuses = append([]string(nil), valid.TerminalStatuses...)
			tt.mutate(&cfg)

			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic for invalid identifier, got none")
				}
			}()
			New(nil, cfg)
		})
	}
}

func TestNew_DefensiveCopyOfTerminalStatuses(t *testing.T) {
	statuses := []string{"completed", "failed"}
	cfg := Config{
		Table:             "scan_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  statuses,
	}
	q := New(nil, cfg)

	// Mutate the original slice after construction.
	statuses[0] = "HACKED"

	// The queue's internal config should not have changed.
	if strings.Contains(q.finishSQL, "HACKED") {
		t.Error("terminal statuses were not defensively copied")
	}
}

func TestStaleReaper_DefaultsApply(t *testing.T) {
	r := &StaleReaper{Reclaimer: &fakeReclaimer{}, Label: "test"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run should exit immediately
	r.Run(ctx)
	if r.Interval != 5*time.Minute {
		t.Errorf("Interval default = %v, want 5m", r.Interval)
	}
	if r.Timeout != 15*time.Minute {
		t.Errorf("Timeout default = %v, want 15m", r.Timeout)
	}
	if r.Now == nil {
		t.Error("Now default was not applied")
	}
}

func TestStaleReaper_InvokesReclaimer(t *testing.T) {
	fixedNow := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	notify := make(chan struct{}, 1)
	rec := &fakeReclaimer{notify: notify}
	r := &StaleReaper{
		Reclaimer: rec,
		Label:     "test",
		Interval:  10 * time.Millisecond,
		Timeout:   15 * time.Minute,
		Now:       func() time.Time { return fixedNow },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("ReclaimStale was not called within 1s")
	}
	cancel()
	<-done

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) == 0 {
		t.Fatal("no ReclaimStale calls recorded")
	}
	wantCutoff := fixedNow.Add(-15 * time.Minute)
	if !rec.calls[0].Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v", rec.calls[0], wantCutoff)
	}
}
