package manageserver

import (
	"sync"
	"time"
)

// loginRateLimiter tracks failed login attempts per (email, IP) pair.
// It is intentionally in-memory and non-persistent — a restart resets
// the counters, which is acceptable for the Manage Server's threat model.
type loginRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = email+"|"+ip
	window   time.Duration
	max      int
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		failures: make(map[string][]time.Time),
		window:   15 * time.Minute,
		max:      5,
	}
}

// Locked returns true if the (email, ip) pair has exceeded the failure
// threshold within the sliding window. It prunes expired entries inline.
func (l *loginRateLimiter) Locked(email, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := email + "|" + ip
	cutoff := time.Now().Add(-l.window)
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
	l.failures[key] = append(l.failures[key], time.Now())
}
