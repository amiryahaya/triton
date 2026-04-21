package manageserver

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Lockout is the serialisable snapshot of one (email, IP) pair currently
// over the failure threshold.
type Lockout struct {
	Email        string    `json:"email"`
	IP           string    `json:"ip"`
	Failures     int       `json:"failures"`
	FirstFailure time.Time `json:"first_failure"`
	LastFailure  time.Time `json:"last_failure"`
	LockedUntil  time.Time `json:"locked_until"`
}

// loginRateLimiter tracks failed login attempts per (email, IP) pair.
// It is intentionally in-memory and non-persistent — a restart resets
// the counters, which is acceptable for the Manage Server's threat model.
type loginRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = email+"|"+ip
	window   time.Duration
	max      int
	now      func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		failures: make(map[string][]time.Time),
		window:   15 * time.Minute,
		max:      5,
		now:      time.Now,
	}
}

// Locked returns true if the (email, ip) pair has exceeded the failure
// threshold within the sliding window. It prunes expired entries inline.
func (l *loginRateLimiter) Locked(email, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	cutoff := l.now().Add(-l.window)
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.failures[key] = kept
	return len(kept) >= l.max
}

// Record appends a failure timestamp for the given (email, ip) pair.
func (l *loginRateLimiter) Record(email, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	l.failures[key] = append(l.failures[key], l.now())
}

// ActiveLockouts returns a snapshot of all (email, IP) pairs currently
// over the failure threshold. Prunes expired entries inline (same
// semantics as Locked). Returned slice is freshly allocated — safe to
// mutate by the caller. Results are sorted by LockedUntil DESC.
func (l *loginRateLimiter) ActiveLockouts() []Lockout {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.window)
	var out []Lockout
	for k, ts := range l.failures {
		// kept aliases ts's backing array — safe because appends only move elements left.
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		l.failures[k] = kept
		if len(kept) < l.max {
			continue
		}
		idx := strings.Index(k, "|")
		if idx < 0 {
			continue // malformed key — skip silently
		}
		out = append(out, Lockout{
			Email:        k[:idx],
			IP:           k[idx+1:],
			Failures:     len(kept),
			FirstFailure: kept[0],
			LastFailure:  kept[len(kept)-1],
			LockedUntil:  kept[0].Add(l.window),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LockedUntil.After(out[j].LockedUntil)
	})
	return out
}

// Clear removes the tracked failures for the given (email, IP) pair.
// Returns true if the entry existed, false otherwise.
func (l *loginRateLimiter) Clear(email, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	if _, exists := l.failures[key]; !exists {
		return false
	}
	delete(l.failures, key)
	return true
}

// setNowForTest replaces the clock function for deterministic tests.
// Never called in production code.
func (l *loginRateLimiter) setNowForTest(fn func() time.Time) {
	l.now = fn
}
