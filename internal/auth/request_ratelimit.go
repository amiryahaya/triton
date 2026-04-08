package auth

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
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

// requestBucket tracks a single key's window. Using atomic counters
// avoids a mutex on the hot path; the windowStart timestamp needs
// atomic swap too, so we wrap it in an atomic.Int64 (unix nanos).
type requestBucket struct {
	count       atomic.Int64
	windowStart atomic.Int64 // nanoseconds since epoch
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

	// If the current window has elapsed since bucket's anchor, roll
	// it forward atomically: set windowStart = now and reset count
	// to 1. Use CAS to avoid the "two goroutines reset, both think
	// they set count=1, total count becomes 2" race.
	start := bucket.windowStart.Load()
	if start == 0 || nowNs-start >= windowNs {
		if bucket.windowStart.CompareAndSwap(start, nowNs) {
			// We won the race — reset counter.
			bucket.count.Store(1)
			return true, 0
		}
		// Someone else reset it — fall through to normal increment.
	}

	n := bucket.count.Add(1)
	if n > int64(l.cfg.MaxRequests) {
		// Compute retry-after based on when the window closes.
		closes := time.Unix(0, bucket.windowStart.Load()+windowNs)
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
func (l *RequestRateLimiter) sweepStale() {
	nowNs := time.Now().UnixNano()
	windowNs := l.cfg.Window.Nanoseconds()
	l.entries.Range(func(key, value any) bool {
		b := value.(*requestBucket)
		start := b.windowStart.Load()
		if start != 0 && nowNs-start >= windowNs {
			l.entries.Delete(key)
		}
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
