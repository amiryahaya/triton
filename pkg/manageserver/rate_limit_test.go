package manageserver

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLimiter returns a limiter with a fixed clock anchored at base.
// tick is a pointer the caller can advance before calling Record.
func newTestLimiter(base time.Time) (*loginRateLimiter, *time.Time) {
	tick := base
	l := newLoginRateLimiter()
	l.setNowForTest(func() time.Time { return tick })
	return l, &tick
}

func TestActiveLockouts_ReturnsOnlyOverThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	// Record 3 failures for user-a — under threshold (max=5).
	for i := 0; i < 3; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.1.1.1")
	}
	// Record 5 failures for user-b — at threshold.
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("b@example.com", "2.2.2.2")
	}

	out := l.ActiveLockouts()
	require.Len(t, out, 1, "only b should be locked")
	assert.Equal(t, "b@example.com", out[0].Email)
}

func TestActiveLockouts_PrunesExpired(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("user@example.com", "1.2.3.4")
	}
	// Advance clock past the 15-minute window.
	*tick = base.Add(16 * time.Minute)

	out := l.ActiveLockouts()
	assert.Empty(t, out, "all failures expired — no lockout")
}

func TestActiveLockouts_FieldsPopulated(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.2.3.4")
	}

	out := l.ActiveLockouts()
	require.Len(t, out, 1)
	got := out[0]
	assert.Equal(t, "a@example.com", got.Email)
	assert.Equal(t, "1.2.3.4", got.IP)
	assert.Equal(t, 5, got.Failures)
	assert.Equal(t, base, got.FirstFailure)
	assert.Equal(t, base.Add(4*time.Second), got.LastFailure)
	assert.Equal(t, base.Add(l.window), got.LockedUntil)
}

func TestActiveLockouts_SortedByLockedUntilDesc(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	// a's first failure at base — LockedUntil = base+15min
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("a@example.com", "1.1.1.1")
	}
	// b's first failure at base+1min — LockedUntil = base+16min (fresher)
	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Minute + time.Duration(i)*time.Second)
		l.Record("b@example.com", "2.2.2.2")
	}

	out := l.ActiveLockouts()
	require.Len(t, out, 2)
	assert.Equal(t, "b@example.com", out[0].Email, "b has fresher LockedUntil — should be first")
	assert.Equal(t, "a@example.com", out[1].Email)
}

func TestClear_RemovesEntry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, tick := newTestLimiter(base)

	for i := 0; i < 5; i++ {
		*tick = base.Add(time.Duration(i) * time.Second)
		l.Record("user@example.com", "1.2.3.4")
	}
	require.Len(t, l.ActiveLockouts(), 1)

	cleared := l.Clear("user@example.com", "1.2.3.4")
	assert.True(t, cleared)
	assert.Empty(t, l.ActiveLockouts())
}

func TestClear_MissingEntryReturnsFalse(t *testing.T) {
	l := newLoginRateLimiter()
	cleared := l.Clear("nobody@example.com", "0.0.0.0")
	assert.False(t, cleared)
}

func TestActiveLockouts_IsConcurrencySafe(t *testing.T) {
	l := newLoginRateLimiter()
	for i := 0; i < 5; i++ {
		l.Record("user@example.com", "127.0.0.1")
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = l.ActiveLockouts()
		}()
		go func() {
			defer wg.Done()
			l.Record("other@example.com", "10.0.0.1")
		}()
		go func() {
			defer wg.Done()
			_ = l.Clear("other@example.com", "10.0.0.1")
		}()
	}
	wg.Wait()
}
