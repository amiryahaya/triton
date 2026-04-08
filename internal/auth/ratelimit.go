package auth

import (
	"strings"
	"sync"
	"time"
)

// LoginRateLimiterConfig tunes the limiter's per-email window.
//
//	MaxAttempts     — failures permitted within Window before lockout.
//	Window          — sliding window for counting failures; older ones
//	                  are forgotten.
//	LockoutDuration — once locked, how long the email is blocked from
//	                  further login attempts.
type LoginRateLimiterConfig struct {
	MaxAttempts     int
	Window          time.Duration
	LockoutDuration time.Duration
}

// DefaultLoginRateLimiterConfig is the policy applied when wiring the
// limiter into handleLogin with no explicit tuning: 5 failures in any
// 15-minute window triggers a 15-minute lockout. Keep this conservative;
// ops can tune via a future env var or config file if needed.
var DefaultLoginRateLimiterConfig = LoginRateLimiterConfig{
	MaxAttempts:     5,
	Window:          15 * time.Minute,
	LockoutDuration: 15 * time.Minute,
}

// LoginRateLimiter is an in-memory, per-email sliding-window rate
// limiter for authentication endpoints. It is SAFE for concurrent use.
//
// Design notes
//
//   - State is held in a sync.Map keyed by lowercased email. This keeps
//     the hot path (Check during a login) non-blocking across unrelated
//     emails, while each email's own entry is protected by a sync.Mutex.
//
//   - The limiter is NOT durable: restarting the process clears all
//     lockouts. That is a deliberate trade-off for v1 — it keeps the
//     dependency surface small and prevents operators from locking
//     themselves out during a rolling deploy. A future iteration can
//     promote this to a DB-backed counter if ops asks.
//
//   - The limiter tracks FAILURES only. Successful logins reset the
//     entry via RecordSuccess, which both clears the counter and frees
//     any memory held by a stale entry.
//
//   - "Sliding window" here means: the first failure timestamp is the
//     window anchor. Once Window has elapsed since the anchor, the
//     counter resets on the next failure. This is simpler than a true
//     sliding log and cheaper than a bucketed counter — adequate for
//     the coarse human-login timescale.
type LoginRateLimiter struct {
	cfg     LoginRateLimiterConfig
	entries sync.Map // map[string]*rateLimitEntry
}

// rateLimitEntry tracks failures for a single email. Protected by mu.
type rateLimitEntry struct {
	mu           sync.Mutex
	failureCount int
	windowStart  time.Time // first failure within the current window
	lockedUntil  time.Time // zero if not locked
}

// NewLoginRateLimiter returns a limiter configured with cfg. A zero-value
// config will never lock (useful in tests that pass an unbounded config
// by accident); production callers should use DefaultLoginRateLimiterConfig.
func NewLoginRateLimiter(cfg LoginRateLimiterConfig) *LoginRateLimiter {
	return &LoginRateLimiter{cfg: cfg}
}

// normalizeEmail canonicalizes the key so "Alice@Example.COM" and
// "alice@example.com" share a bucket. Handlers already lowercase, but
// this is defence in depth.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// getOrCreate returns the entry for email, creating it if absent.
func (l *LoginRateLimiter) getOrCreate(email string) *rateLimitEntry {
	key := normalizeEmail(email)
	if v, ok := l.entries.Load(key); ok {
		return v.(*rateLimitEntry)
	}
	fresh := &rateLimitEntry{}
	actual, _ := l.entries.LoadOrStore(key, fresh)
	return actual.(*rateLimitEntry)
}

// Check reports whether email is currently allowed to attempt a login.
// If blocked, retryAfter is the duration the caller should surface in a
// Retry-After header. The return value (true, 0) means "allowed".
//
// Check does NOT mutate counters — a handler that wants the check to
// count as an attempt must call RecordFailure after a failed password
// comparison, or RecordSuccess after a successful login.
func (l *LoginRateLimiter) Check(email string) (allowed bool, retryAfter time.Duration) {
	entry := l.getOrCreate(email)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
		return false, time.Until(entry.lockedUntil)
	}
	return true, 0
}

// RecordFailure increments the failure counter for email and may
// transition the entry into a locked state. Safe to call after Check
// has returned allowed=true.
func (l *LoginRateLimiter) RecordFailure(email string) {
	if l.cfg.MaxAttempts <= 0 {
		// Zero-value config → never lock. Skip bookkeeping entirely.
		return
	}
	entry := l.getOrCreate(email)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	// If a prior lockout has expired, clear it before counting.
	if !entry.lockedUntil.IsZero() && now.After(entry.lockedUntil) {
		entry.lockedUntil = time.Time{}
		entry.failureCount = 0
		entry.windowStart = time.Time{}
	}

	// If the window has elapsed since the anchor, reset.
	if !entry.windowStart.IsZero() && now.Sub(entry.windowStart) >= l.cfg.Window {
		entry.failureCount = 0
		entry.windowStart = time.Time{}
	}

	// Begin a new window if this is the first failure of a fresh cycle.
	if entry.failureCount == 0 {
		entry.windowStart = now
	}
	entry.failureCount++

	if entry.failureCount >= l.cfg.MaxAttempts {
		entry.lockedUntil = now.Add(l.cfg.LockoutDuration)
	}
}

// RecordSuccess clears the failure state for email. Call this after a
// successful password comparison so a legitimate user whose first
// attempt(s) mistyped can log in cleanly without an accumulating
// counter.
func (l *LoginRateLimiter) RecordSuccess(email string) {
	key := normalizeEmail(email)
	l.entries.Delete(key)
}
