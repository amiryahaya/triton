package auth

import (
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
