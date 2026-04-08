package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestRateLimiter_AllowsBelowThreshold(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 5,
		Window:      1 * time.Minute,
	})
	for i := 0; i < 5; i++ {
		allowed, _ := lim.Allow("org-1")
		require.True(t, allowed, "attempt %d within budget", i+1)
	}
}

func TestRequestRateLimiter_BlocksAtThreshold(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 3,
		Window:      1 * time.Minute,
	})
	for i := 0; i < 3; i++ {
		allowed, _ := lim.Allow("org-1")
		require.True(t, allowed)
	}
	allowed, retryAfter := lim.Allow("org-1")
	assert.False(t, allowed, "4th request must be rejected")
	assert.Greater(t, retryAfter, time.Duration(0))
	assert.LessOrEqual(t, retryAfter, 1*time.Minute)
}

func TestRequestRateLimiter_PerKeyIsolation(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 2,
		Window:      1 * time.Minute,
	})
	// Burn org-1's budget.
	lim.Allow("org-1")
	lim.Allow("org-1")
	allowed, _ := lim.Allow("org-1")
	require.False(t, allowed)

	// org-2 still has its full budget.
	allowed, _ = lim.Allow("org-2")
	assert.True(t, allowed, "org-2 must not be affected by org-1's usage")
}

func TestRequestRateLimiter_WindowElapseResets(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 2,
		Window:      50 * time.Millisecond,
	})
	lim.Allow("org-1")
	lim.Allow("org-1")
	allowed, _ := lim.Allow("org-1")
	require.False(t, allowed)

	time.Sleep(80 * time.Millisecond)

	allowed, _ = lim.Allow("org-1")
	assert.True(t, allowed, "after window elapses, counter must reset")
}

func TestRequestRateLimiter_EmptyKeyAlwaysAllowed(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 1,
		Window:      1 * time.Minute,
	})
	// Empty key is never rate-limited (unauth path).
	for i := 0; i < 10; i++ {
		allowed, _ := lim.Allow("")
		assert.True(t, allowed, "empty key must always be allowed (call %d)", i+1)
	}
}

func TestRequestRateLimiter_ZeroConfigDisables(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{})
	for i := 0; i < 1000; i++ {
		allowed, _ := lim.Allow("org-1")
		require.True(t, allowed)
	}
}

func TestRequestRateLimiter_Concurrent_NoRace(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 100,
		Window:      1 * time.Minute,
	})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lim.Allow("concurrent-org")
		}()
	}
	wg.Wait()
	// We don't assert exact count — atomic additions can race with
	// the window-reset CAS in ways that are intentionally loose.
	// The race detector is what proves this test's value.
}

func TestRequestRateLimiter_Stats(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 5,
		Window:      1 * time.Minute,
	})
	lim.Allow("a")
	lim.Allow("b")
	lim.Allow("c")
	s := lim.Stats()
	assert.Equal(t, 3, s.Tracked)
}

func TestRequestRateLimiter_JanitorSweeps(t *testing.T) {
	lim := NewRequestRateLimiter(RequestRateLimiterConfig{
		MaxRequests: 5,
		Window:      30 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := lim.StartJanitor(ctx, 10*time.Millisecond)
	defer func() {
		cancel()
		<-done
	}()

	lim.Allow("stale-1")
	lim.Allow("stale-2")
	assert.Equal(t, 2, lim.Stats().Tracked)

	// Wait past the window so the next sweep reclaims entries.
	time.Sleep(80 * time.Millisecond)

	// Give the janitor a few ticks to fire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if lim.Stats().Tracked == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("janitor did not reclaim stale entries; tracked=%d", lim.Stats().Tracked)
}
