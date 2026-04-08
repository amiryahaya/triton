package license

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ValidationCache is an in-memory TTL cache for license server /validate
// responses. Used by the report server to avoid hitting the license
// server on every request that presents a license token.
//
// Distinct from CacheMeta (agent-side offline cache in ~/.triton) —
// ValidationCache lives in the report server process memory, keyed by
// token hash, populated on demand, and honors the server-supplied
// cacheTTL field introduced in Phase 1.6.
//
// Thread-safe. Safe for concurrent use from multiple goroutines.
//
// NOT persisted across restarts — the first few requests after a
// restart will miss and re-validate. This is acceptable: license
// server latency is bounded and cold-start performance is not a
// multi-tenant concern.
type ValidationCache struct {
	upstream Validator // underlying validator (typically *ServerClient)
	mu       sync.RWMutex
	entries  map[string]*validationEntry
}

// Validator is the minimal interface ValidationCache needs from its
// backing client. *ServerClient satisfies it.
type Validator interface {
	Validate(licenseID, token string) (*ValidateResponse, error)
}

type validationEntry struct {
	response  *ValidateResponse
	expiresAt time.Time
}

// NewValidationCache wraps the given Validator with a TTL cache.
func NewValidationCache(upstream Validator) *ValidationCache {
	return &ValidationCache{
		upstream: upstream,
		entries:  make(map[string]*validationEntry),
	}
}

// Validate returns a cached validation response if the entry is
// present AND not expired. On miss or stale entry, it calls the
// upstream Validator and populates the cache using the CacheTTL
// field from the response (or defaultCacheTTL if not set).
//
// Cache key is SHA-256 of the presented token. Using the token hash
// rather than the license ID means two different tokens for the same
// license (e.g., before and after a key rotation) get independent
// cache entries and don't poison each other.
//
// Context is currently unused (the underlying ServerClient doesn't
// accept context yet) but is on the signature so callers can pass
// request context for future propagation.
func (c *ValidationCache) Validate(ctx context.Context, licenseID, token string) (*ValidateResponse, error) {
	key := tokenHashKey(token)

	// Fast path: read lock + return if fresh.
	c.mu.RLock()
	if entry, ok := c.entries[key]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.response, nil
	}
	c.mu.RUnlock()

	// Miss or stale — call upstream.
	resp, err := c.upstream.Validate(licenseID, token)
	if err != nil {
		return nil, err
	}

	// Only cache positive results. Negative results (revoked, expired,
	// wrong token) should re-query immediately on the next request so
	// the report server catches revocations as fast as possible.
	if resp.Valid {
		ttl := time.Duration(resp.CacheTTL) * time.Second
		if ttl <= 0 {
			ttl = defaultCacheTTL
		}
		c.mu.Lock()
		c.entries[key] = &validationEntry{
			response:  resp,
			expiresAt: time.Now().Add(ttl),
		}
		c.mu.Unlock()
	}

	return resp, nil
}

// Invalidate removes the cache entry for a specific token. Used by
// an eventual admin callback that wants to force re-validation after
// an out-of-band state change on the license server.
func (c *ValidationCache) Invalidate(token string) {
	key := tokenHashKey(token)
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Clear drops all cache entries. Used in tests and for admin reset.
func (c *ValidationCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*validationEntry)
	c.mu.Unlock()
}

// Size returns the number of cached entries. Used in tests.
func (c *ValidationCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// tokenHashKey returns the cache key for a token. Using SHA-256 of
// the token keeps cache memory bounded (fixed-length keys) and means
// the raw token never sits in the map.
func tokenHashKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// defaultCacheTTL is used when the upstream response has no CacheTTL
// field (e.g., from an older license server). Five minutes matches
// the Phase 1 validateCacheTTLSeconds default.
const defaultCacheTTL = 5 * time.Minute
