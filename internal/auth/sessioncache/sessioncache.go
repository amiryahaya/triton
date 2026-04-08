// Package sessioncache provides a short-TTL, bounded LRU cache for
// authenticated JWT sessions on the report-server hot path. It is
// keyed by sha256(token) and stores just enough to skip both the
// sessions-table lookup and the users-table lookup on a cache hit.
//
// Arch #4 — Phase 5 Sprint 4 architectural hygiene. Without this
// cache, JWTAuth incurs two PG round-trips per authenticated
// request (sessions + users), capping p99 throughput at around
// 500 req/s under sustained multi-tenant load.
//
// Revocation is eventually-consistent: a token flushed from the
// cache by logout/refresh/change-password is instantly invalidated,
// but a token revoked via a direct DB mutation (admin DeleteSession)
// will remain valid for up to TTL seconds on any replica that has
// it cached. Operators who need instant-kill can call the admin
// flush endpoint.
package sessioncache

import (
	"container/list"
	"sync"
	"time"
)

// Entry is the cached per-token state. It holds exactly the fields
// the JWTAuth middleware needs to build the request context:
// user identity, role for RequireOrgAdmin, must-change-password gate,
// and the JWT's own expiry so the cache never returns an entry past
// its token's stated lifetime.
type Entry struct {
	UserID             string
	OrgID              string
	Role               string
	MustChangePassword bool
	// JWTExpiry is the exp claim from the JWT. Entries are
	// invalidated on Get when JWTExpiry has passed, even if the
	// cache TTL has not yet elapsed. This prevents the cache
	// from outliving the token.
	JWTExpiry time.Time
	cachedAt  time.Time
}

// Config tunes the cache. MaxEntries <= 0 disables the cache
// entirely (every Get returns miss, Put is a no-op) so callers can
// wire a non-nil *SessionCache unconditionally.
type Config struct {
	MaxEntries int
	TTL        time.Duration
}

// Stats is a snapshot of cache counters. Currently only hit/miss;
// future fields (evictions, flush count) can be added without
// breaking the struct tag contract because callers read by name.
type Stats struct {
	Hits    uint64
	Misses  uint64
	Entries int
}

// SessionCache is a bounded LRU with per-entry TTL. Safe for
// concurrent use. Single-mutex design is adequate here because
// the critical section is a map lookup + list splice, both O(1);
// sharding would add complexity without measurable benefit at
// the cache sizes we expect (<10k entries).
type SessionCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	ll      *list.List
	items   map[string]*list.Element
	hits    uint64
	misses  uint64
}

// lruItem is the *list.Element value — key + entry so eviction
// (which happens from the list side) can delete the matching
// map entry.
type lruItem struct {
	key   string
	entry Entry
}

// New creates a SessionCache with the given config. A zero
// MaxEntries produces a disabled cache that passes through every
// request.
func New(cfg Config) *SessionCache {
	return &SessionCache{
		ttl:     cfg.TTL,
		maxSize: cfg.MaxEntries,
		ll:      list.New(),
		items:   make(map[string]*list.Element),
	}
}

// Get returns the cached entry for key if present, not expired,
// and not past its JWT expiry. A hit moves the entry to the
// most-recently-used position.
func (c *SessionCache) Get(key string) (Entry, bool) {
	if c == nil || c.maxSize <= 0 {
		return Entry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return Entry{}, false
	}
	item := el.Value.(*lruItem)
	now := time.Now()
	// TTL expiry — drop the entry and report a miss.
	if c.ttl > 0 && now.Sub(item.entry.cachedAt) >= c.ttl {
		c.removeElement(el)
		c.misses++
		return Entry{}, false
	}
	// JWT exp expiry — never hand back a dead token.
	if !item.entry.JWTExpiry.IsZero() && !now.Before(item.entry.JWTExpiry) {
		c.removeElement(el)
		c.misses++
		return Entry{}, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	return item.entry, true
}

// Put inserts or overwrites an entry. Evicts the least-recently-used
// entry if the cache is at capacity. cachedAt is stamped to now().
func (c *SessionCache) Put(key string, entry Entry) {
	if c == nil || c.maxSize <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.cachedAt = time.Now()
	if el, ok := c.items[key]; ok {
		el.Value.(*lruItem).entry = entry
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruItem{key: key, entry: entry})
	c.items[key] = el
	for c.ll.Len() > c.maxSize {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.removeElement(oldest)
	}
}

// Delete removes the entry for key if present. No-op on miss.
// Called by logout/refresh/change-password handlers to make
// revocation instant for user-driven invalidation paths.
func (c *SessionCache) Delete(key string) {
	if c == nil || c.maxSize <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeElement(el)
	}
}

// Flush drops every entry. Returns the number removed so admin
// endpoints can report how much state was cleared.
func (c *SessionCache) Flush() int {
	if c == nil || c.maxSize <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.ll.Len()
	c.ll.Init()
	c.items = make(map[string]*list.Element)
	return n
}

// Len returns the current number of live entries. Useful for
// tests; metrics go through Stats.
func (c *SessionCache) Len() int {
	if c == nil || c.maxSize <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Stats returns a snapshot of counters.
func (c *SessionCache) Stats() Stats {
	if c == nil || c.maxSize <= 0 {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Hits:    c.hits,
		Misses:  c.misses,
		Entries: c.ll.Len(),
	}
}

// removeElement deletes an element from both the list and the map.
// Caller must hold c.mu.
func (c *SessionCache) removeElement(el *list.Element) {
	c.ll.Remove(el)
	delete(c.items, el.Value.(*lruItem).key)
}
