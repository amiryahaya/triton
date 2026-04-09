package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_AllowsBelowThreshold verifies that the limiter permits
// login attempts strictly below the configured maxAttempts threshold.
func TestRateLimiter_AllowsBelowThreshold(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	for i := 0; i < 4; i++ {
		allowed, _ := lim.Check("user@example.com")
		require.True(t, allowed, "attempt %d below threshold must be allowed", i+1)
		lim.RecordFailure("user@example.com")
	}
}

// TestRateLimiter_LocksAtThreshold verifies that the N+1-th attempt
// returns not-allowed and exposes a non-zero Retry-After.
func TestRateLimiter_LocksAtThreshold(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	for i := 0; i < 5; i++ {
		allowed, _ := lim.Check("user@example.com")
		require.True(t, allowed)
		lim.RecordFailure("user@example.com")
	}

	// 6th call after 5 recorded failures → locked out.
	allowed, retryAfter := lim.Check("user@example.com")
	assert.False(t, allowed, "6th attempt after 5 failures must be blocked")
	assert.Greater(t, retryAfter, time.Duration(0), "retryAfter must be positive while locked")
	assert.LessOrEqual(t, retryAfter, 15*time.Minute, "retryAfter must not exceed LockoutDuration")
}

// TestRateLimiter_SuccessResetsCounter verifies that a successful login
// clears the failure window immediately, so an attacker who burned 4
// attempts cannot accumulate failures across sessions.
func TestRateLimiter_SuccessResetsCounter(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	for i := 0; i < 4; i++ {
		lim.RecordFailure("user@example.com")
	}
	lim.RecordSuccess("user@example.com")

	// Now the user should be able to fail another 4 times before lockout.
	for i := 0; i < 4; i++ {
		allowed, _ := lim.Check("user@example.com")
		require.True(t, allowed, "attempt %d after reset must be allowed", i+1)
		lim.RecordFailure("user@example.com")
	}
}

// TestRateLimiter_WindowExpiryResets verifies that failures outside
// the sliding window are forgotten — an attacker who trickles one
// failure per hour cannot accumulate a lockout.
func TestRateLimiter_WindowExpiryResets(t *testing.T) {
	// Use a very short window so the test runs fast without sleeps.
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          50 * time.Millisecond,
		LockoutDuration: 50 * time.Millisecond,
	})

	// Burn through 2 attempts.
	lim.RecordFailure("user@example.com")
	lim.RecordFailure("user@example.com")

	// Wait for the window to expire.
	time.Sleep(80 * time.Millisecond)

	// Now we should have a full 3-attempt budget again.
	for i := 0; i < 3; i++ {
		allowed, _ := lim.Check("user@example.com")
		require.True(t, allowed, "attempt %d after window expiry must be allowed", i+1)
		lim.RecordFailure("user@example.com")
	}
	// And the 4th is locked.
	allowed, _ := lim.Check("user@example.com")
	assert.False(t, allowed)
}

// TestRateLimiter_LockoutExpiryUnlocks verifies that after LockoutDuration
// elapses, the user can attempt to log in again.
func TestRateLimiter_LockoutExpiryUnlocks(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     2,
		Window:          1 * time.Hour,
		LockoutDuration: 50 * time.Millisecond,
	})

	lim.RecordFailure("user@example.com")
	lim.RecordFailure("user@example.com")

	// Locked.
	allowed, _ := lim.Check("user@example.com")
	require.False(t, allowed)

	// Wait for lockout to expire.
	time.Sleep(80 * time.Millisecond)

	// Unlocked.
	allowed, _ = lim.Check("user@example.com")
	assert.True(t, allowed, "attempt after LockoutDuration must be allowed")
}

// TestRateLimiter_PerEmailIsolation verifies that a lockout on one
// email does NOT affect other emails.
func TestRateLimiter_PerEmailIsolation(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	for i := 0; i < 3; i++ {
		lim.RecordFailure("alice@example.com")
	}

	// Alice locked.
	allowed, _ := lim.Check("alice@example.com")
	assert.False(t, allowed)

	// Bob still free.
	allowed, _ = lim.Check("bob@example.com")
	assert.True(t, allowed, "bob must not be affected by alice's lockout")
}

// TestRateLimiter_Concurrent_NoRace verifies the limiter under concurrent
// access. Go's race detector catches any data-race bugs in sync.Map or
// our own locking.
func TestRateLimiter_Concurrent_NoRace(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lim.Check("concurrent@example.com")
			lim.RecordFailure("concurrent@example.com")
		}()
	}
	wg.Wait()
	// We don't assert on final state — we only care that the race
	// detector (-race) does not fire. The lockout may or may not be
	// engaged depending on goroutine interleaving.
}

// TestRateLimiter_SweepReclaimsStaleEntries verifies D1 from the
// Phase 5.1 review: entries for emails that accumulated failures
// (e.g., attacker dictionary probes against non-existent users) are
// reclaimed once their window and any lockout have elapsed, rather
// than leaking forever. The sweep is manual here; production calls
// it via StartJanitor.
func TestRateLimiter_SweepReclaimsStaleEntries(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          50 * time.Millisecond,
		LockoutDuration: 50 * time.Millisecond,
	})

	// Simulate a dictionary attack: 10 unique "emails", 1 failure each.
	for i := 0; i < 10; i++ {
		lim.RecordFailure(fmt.Sprintf("attacker-%d@example.com", i))
	}
	assert.Equal(t, 10, entryCount(lim), "all 10 entries must be present initially")

	// Before the window elapses, a sweep reclaims nothing (windows
	// are still active, so the entries are not stale yet).
	lim.sweepStale()
	assert.Equal(t, 10, entryCount(lim), "sweep must not reclaim live entries")

	// Wait for windows + any lockout to elapse.
	time.Sleep(80 * time.Millisecond)

	lim.sweepStale()
	assert.Equal(t, 0, entryCount(lim),
		"sweep must reclaim all stale entries after window expiry")
}

// TestRateLimiter_JanitorStopsOnContextCancel verifies that
// StartJanitor's goroutine shuts down deterministically when its
// context is canceled: the done channel returned by StartJanitor
// must close within a bounded deadline. A regression in ctx.Done()
// handling fails this test explicitly (rather than hanging the
// whole process and relying on go test's top-level timeout).
func TestRateLimiter_JanitorStopsOnContextCancel(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          10 * time.Millisecond,
		LockoutDuration: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := lim.StartJanitor(ctx, 5*time.Millisecond)

	// Populate then cancel.
	for i := 0; i < 5; i++ {
		lim.RecordFailure(fmt.Sprintf("ctxstop-%d@example.com", i))
	}
	time.Sleep(25 * time.Millisecond) // let at least one tick fire
	cancel()

	select {
	case <-done:
		// goroutine exited — shutdown deterministic
	case <-time.After(200 * time.Millisecond):
		t.Fatal("janitor goroutine did not exit within 200ms of ctx cancel")
	}
}

// TestRateLimiter_StartJanitor_ZeroIntervalIsNoOp verifies the
// contract that interval <= 0 starts no goroutine at all and
// returns an already-closed done channel so callers that want to
// wait on stop don't block forever.
func TestRateLimiter_StartJanitor_ZeroIntervalIsNoOp(t *testing.T) {
	lim := NewLoginRateLimiter(DefaultLoginRateLimiterConfig)
	done := lim.StartJanitor(context.Background(), 0)
	select {
	case <-done:
		// closed immediately — correct
	default:
		t.Fatal("StartJanitor(..., 0) must return an already-closed done channel")
	}
}

// TestRateLimiter_LockoutExpiryThenFail_ResetsWindowCounter is the
// D6 coverage gap: after a lockout elapses, a FRESH failure must
// start a new window at count=1, not immediately re-lock at count=N.
func TestRateLimiter_LockoutExpiryThenFail_ResetsWindowCounter(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          1 * time.Hour,
		LockoutDuration: 50 * time.Millisecond,
	})

	// Lock the user out.
	for i := 0; i < 3; i++ {
		lim.RecordFailure("recover@example.com")
	}
	allowed, _ := lim.Check("recover@example.com")
	require.False(t, allowed)

	// Wait for lockout to expire.
	time.Sleep(80 * time.Millisecond)

	// Now a single failure must NOT immediately re-lock — the
	// counter was reset by RecordFailure's expired-lockout branch,
	// so we should be back to count=1 of 3.
	lim.RecordFailure("recover@example.com")
	allowed, _ = lim.Check("recover@example.com")
	assert.True(t, allowed,
		"after lockout expiry, a single failure must not immediately re-lock")

	// And the user gets a full fresh budget (2 more fails before lock).
	lim.RecordFailure("recover@example.com")
	allowed, _ = lim.Check("recover@example.com")
	assert.True(t, allowed, "2nd post-expiry failure still under budget")

	lim.RecordFailure("recover@example.com")
	allowed, _ = lim.Check("recover@example.com")
	assert.False(t, allowed, "3rd post-expiry failure re-locks")
}

// entryCount returns the number of entries in the limiter's sync.Map.
// Phase 5 Sprint 2 (N2) replaced the handwritten Range with
// Stats().Tracked so tests exercise the same counting path operators
// will use via the metrics endpoint.
func entryCount(l *LoginRateLimiter) int {
	return l.Stats().Tracked
}

// TestRateLimiter_Stats_CountsLockedAndTracked verifies that Stats()
// returns (a) the total number of tracked entries and (b) the
// subset currently in a locked state.
func TestRateLimiter_Stats_CountsLockedAndTracked(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     3,
		Window:          1 * time.Hour,
		LockoutDuration: 1 * time.Hour,
	})

	// Three users, only one crosses the lockout threshold.
	for i := 0; i < 3; i++ {
		lim.RecordFailure("alice@example.com")
	}
	lim.RecordFailure("bob@example.com")
	lim.RecordFailure("carol@example.com")
	lim.RecordFailure("carol@example.com")

	stats := lim.Stats()
	assert.Equal(t, 3, stats.Tracked, "three distinct emails should be tracked")
	assert.Equal(t, 1, stats.LockedEmails, "only alice should be locked")
}

// TestRateLimiter_Stats_EmptyLimiter verifies the zero state.
func TestRateLimiter_Stats_EmptyLimiter(t *testing.T) {
	lim := NewLoginRateLimiter(DefaultLoginRateLimiterConfig)
	stats := lim.Stats()
	assert.Equal(t, 0, stats.Tracked)
	assert.Equal(t, 0, stats.LockedEmails)
}

// TestRateLimiter_EmailIsCaseInsensitive verifies that "Alice@..."
// and "alice@..." share a bucket. Handlers always lowercase before
// calling the limiter, but defence in depth: the limiter also
// normalises.
func TestRateLimiter_EmailIsCaseInsensitive(t *testing.T) {
	lim := NewLoginRateLimiter(LoginRateLimiterConfig{
		MaxAttempts:     2,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	})

	lim.RecordFailure("Alice@Example.COM")
	lim.RecordFailure("ALICE@example.com")

	allowed, _ := lim.Check("alice@example.com")
	assert.False(t, allowed, "limiter must canonicalize email case")
}
