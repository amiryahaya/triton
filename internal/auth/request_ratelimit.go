package auth

import (
	"context"
	"strings"
	"sync"
	"time"
)

// RequestRateLimiterConfig tunes the per-key request rate limit.
//
//	MaxRequests  — requests permitted within Window before 429.
//	Window       — rolling window for request counting.
//	Cleanup      — optional sweep interval for stale entries.
//
// Unlike LoginRateLimiter this is a simple token-bucket-style
// counter rather than a sliding window with lockout, because the
// semantics differ: for an already-authenticated user we just want
// to throttle them back, not lock them out — they'll retry after
// Window elapses naturally.
type RequestRateLimiterConfig struct {
	MaxRequests int
	Window      time.Duration
}

// DefaultRequestRateLimiterConfig gives each authenticated tenant
// 600 requests per minute (10/sec sustained) — generous enough for
// a busy agent fleet submitting scans while still catching
// accidental infinite loops and insider DoS.
var DefaultRequestRateLimiterConfig = RequestRateLimiterConfig{
	MaxRequests: 600,
	Window:      1 * time.Minute,
}

// RequestRateLimiter is a per-key rolling-window counter used for
// non-login data endpoints. Safe for concurrent use across many
// goroutines.
//
// Key is typically the authenticated tenant's org_id (so one noisy
// org cannot starve another), but callers can choose — the limiter
// itself treats keys as opaque strings.
type RequestRateLimiter struct {
	cfg     RequestRateLimiterConfig
	entries sync.Map // map[string]*requestBucket
}

// requestBucket tracks a single key's window. Guarded by a mutex
// because the reset-or-increment transition must be atomic as a
// pair — the earlier atomic-only implementation lost count updates
// between the CAS that rolled the window and the Store(1) that
// reset the counter (Sprint 3 review D1). A mutex per key keeps
// the hot path per-entry contention-free while giving us the
// single critical section we need for correctness.
type requestBucket struct {
	mu          sync.Mutex
	count       int64
	windowStart int64 // nanoseconds since epoch, 0 = not yet armed
}

// NewRequestRateLimiter constructs a limiter with the given config.
// A zero-value config disables rate limiting entirely (Allow always
// returns true) — useful for tests and single-tenant deployments
// that don't need the protection.
func NewRequestRateLimiter(cfg RequestRateLimiterConfig) *RequestRateLimiter {
	return &RequestRateLimiter{cfg: cfg}
}

// Allow increments the counter for key and returns whether the
// request is permitted. On rejection, returns false and the time
// until the current window closes (the Retry-After hint).
//
// Contract: Allow is idempotent within a single call — every call
// counts as one request regardless of the return value, matching
// the semantics of "attempted requests within window".
func (l *RequestRateLimiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	if l.cfg.MaxRequests <= 0 {
		return true, 0
	}
	key = strings.TrimSpace(key)
	if key == "" {
		// Empty key (unauthenticated or malformed context) is never
		// rate-limited here — other middleware (UnifiedAuth, login
		// limiter) already handles that case.
		return true, 0
	}

	bucket := l.getOrCreate(key)
	now := time.Now()
	nowNs := now.UnixNano()
	windowNs := l.cfg.Window.Nanoseconds()

	// Single critical section covers the "roll window OR increment"
	// decision so we don't lose count updates between a concurrent
	// window reset and a concurrent increment. Earlier atomic-only
	// code had a gap where a goroutine that read the old windowStart,
	// took the increment branch, and called count.Add(1) would be
	// silently clobbered by a CAS-winner's count.Store(1). See
	// Sprint 3 review D1 for the full rationale.
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	if bucket.windowStart == 0 || nowNs-bucket.windowStart >= windowNs {
		// Window has elapsed (or never armed) — roll it forward and
		// count this request as the first of the new window.
		bucket.windowStart = nowNs
		bucket.count = 1
		return true, 0
	}

	bucket.count++
	if bucket.count > int64(l.cfg.MaxRequests) {
		closes := time.Unix(0, bucket.windowStart+windowNs)
		return false, time.Until(closes)
	}
	return true, 0
}

// getOrCreate returns the bucket for key, creating it if absent.
func (l *RequestRateLimiter) getOrCreate(key string) *requestBucket {
	if v, ok := l.entries.Load(key); ok {
		return v.(*requestBucket)
	}
	fresh := &requestBucket{}
	actual, _ := l.entries.LoadOrStore(key, fresh)
	return actual.(*requestBucket)
}

// Stats returns a snapshot of observable counters for /metrics.
type RequestRateLimiterStats struct {
	Tracked int
}

// Stats returns the observable counter snapshot.
func (l *RequestRateLimiter) Stats() RequestRateLimiterStats {
	var s RequestRateLimiterStats
	l.entries.Range(func(_, _ any) bool {
		s.Tracked++
		return true
	})
	return s
}

// sweepStale removes buckets whose window has elapsed. Called by
// the janitor goroutine; safe to call concurrently with Allow.
// The Delete must happen inside the per-bucket mutex so a
// concurrent Allow that already locked the entry either completes
// before us (in which case windowStart is now fresh and we won't
// delete) or runs on a fresh entry constructed after our Delete
// (via LoadOrStore). Mirrors the Sprint 1 D8 pattern on the
// LoginRateLimiter's sweepStale.
func (l *RequestRateLimiter) sweepStale() {
	nowNs := time.Now().UnixNano()
	windowNs := l.cfg.Window.Nanoseconds()
	l.entries.Range(func(key, value any) bool {
		b := value.(*requestBucket)
		b.mu.Lock()
		if b.windowStart != 0 && nowNs-b.windowStart >= windowNs {
			l.entries.Delete(key)
		}
		b.mu.Unlock()
		return true
	})
}

// StartJanitor launches a periodic cleanup goroutine. Returns a
// done channel that closes when the goroutine exits. Matches the
// LoginRateLimiter.StartJanitor contract.
func (l *RequestRateLimiter) StartJanitor(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if interval <= 0 {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.sweepStale()
			}
		}
	}()
	return done
}
