package server

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// stubStore embeds store.Store to satisfy the interface with zero-value no-ops.
type stubStore struct {
	store.Store
}

func TestUsageSource_Collect_ReturnsNonNilSlice(t *testing.T) {
	src := NewUsageSource(&stubStore{})
	got := src.Collect()
	if got == nil {
		t.Error("Collect() returned nil; want non-nil empty slice")
	}
	for _, m := range got {
		if m.Metric == "" {
			t.Errorf("empty metric name in returned metrics: %+v", m)
		}
	}
}

func TestUsageSource_NewUsageSource_NotNil(t *testing.T) {
	src := NewUsageSource(&stubStore{})
	if src == nil {
		t.Error("NewUsageSource returned nil")
	}
}

func TestMonthStart_IsFirstDayOfMonth(t *testing.T) {
	ms := monthStart()
	if ms.Day() != 1 {
		t.Errorf("monthStart().Day() = %d, want 1", ms.Day())
	}
	if ms.Hour() != 0 || ms.Minute() != 0 || ms.Second() != 0 {
		t.Errorf("monthStart() should be midnight, got %s", ms)
	}
	if ms.Location() != time.UTC {
		t.Errorf("monthStart() should be UTC, got %s", ms.Location())
	}
}
