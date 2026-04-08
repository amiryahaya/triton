package license

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockValidator is a test double implementing the Validator interface.
// Counts calls so tests can verify cache hits avoid upstream traffic.
type mockValidator struct {
	mu           sync.Mutex
	callCount    atomic.Int32
	response     *ValidateResponse
	err          error
	delay        time.Duration
	perLicenseID map[string]*ValidateResponse
}

func (m *mockValidator) Validate(licenseID, _ string) (*ValidateResponse, error) {
	m.callCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	if resp, ok := m.perLicenseID[licenseID]; ok {
		return resp, nil
	}
	return m.response, nil
}

// --- Basic caching behavior ---

func TestValidationCache_HitReturnsCached(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{
			Valid:    true,
			Tier:     "pro",
			OrgID:    "org-123",
			CacheTTL: 60,
		},
	}
	cache := NewValidationCache(mock)

	// First call — upstream hit
	resp1, err := cache.Validate(context.Background(), "lic-1", "token-abc")
	require.NoError(t, err)
	assert.True(t, resp1.Valid)
	assert.Equal(t, int32(1), mock.callCount.Load())

	// Second call with same token — cache hit, no upstream
	resp2, err := cache.Validate(context.Background(), "lic-1", "token-abc")
	require.NoError(t, err)
	assert.True(t, resp2.Valid)
	assert.Equal(t, int32(1), mock.callCount.Load(), "second call must be served from cache")
}

func TestValidationCache_DifferentTokensGetSeparateEntries(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{Valid: true, Tier: "pro", CacheTTL: 60},
	}
	cache := NewValidationCache(mock)

	_, _ = cache.Validate(context.Background(), "lic-1", "token-A")
	_, _ = cache.Validate(context.Background(), "lic-1", "token-B")
	assert.Equal(t, int32(2), mock.callCount.Load(), "different tokens must miss independently")
	assert.Equal(t, 2, cache.Size())
}

// --- TTL expiry ---

func TestValidationCache_ExpiredEntryRefetches(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{
			Valid:    true,
			Tier:     "pro",
			CacheTTL: 1, // 1 second TTL
		},
	}
	cache := NewValidationCache(mock)

	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, int32(1), mock.callCount.Load())

	// Wait past TTL
	time.Sleep(1100 * time.Millisecond)

	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, int32(2), mock.callCount.Load(), "expired entry must re-fetch")
}

func TestValidationCache_ZeroCacheTTLUsesDefault(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{
			Valid:    true,
			Tier:     "pro",
			CacheTTL: 0, // not supplied — use default
		},
	}
	cache := NewValidationCache(mock)

	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	// Second call within default TTL → cache hit
	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, int32(1), mock.callCount.Load(),
		"zero CacheTTL must fall back to defaultCacheTTL, not bypass cache")
}

// --- Negative results are NOT cached ---

func TestValidationCache_NegativeResultsNotCached(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{
			Valid:    false,
			Reason:   "license revoked",
			CacheTTL: 60,
		},
	}
	cache := NewValidationCache(mock)

	// First call returns false
	resp1, err := cache.Validate(context.Background(), "lic-1", "token")
	require.NoError(t, err)
	assert.False(t, resp1.Valid)

	// Second call must hit upstream again — revocation should propagate
	// as fast as possible, not be cached for the TTL.
	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, int32(2), mock.callCount.Load(),
		"negative results must not be cached")
}

// --- Error pass-through ---

func TestValidationCache_UpstreamErrorPassThrough(t *testing.T) {
	mock := &mockValidator{err: errors.New("license server down")}
	cache := NewValidationCache(mock)

	_, err := cache.Validate(context.Background(), "lic-1", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "license server down")
	assert.Equal(t, 0, cache.Size(), "errors must not populate the cache")
}

// --- Invalidation ---

func TestValidationCache_InvalidateRemovesEntry(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{Valid: true, CacheTTL: 3600},
	}
	cache := NewValidationCache(mock)

	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, 1, cache.Size())

	cache.Invalidate("token")
	assert.Equal(t, 0, cache.Size())

	// Next call re-fetches
	_, _ = cache.Validate(context.Background(), "lic-1", "token")
	assert.Equal(t, int32(2), mock.callCount.Load())
}

func TestValidationCache_ClearEmptiesCache(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{Valid: true, CacheTTL: 3600},
	}
	cache := NewValidationCache(mock)

	_, _ = cache.Validate(context.Background(), "lic-1", "token-A")
	_, _ = cache.Validate(context.Background(), "lic-1", "token-B")
	require.Equal(t, 2, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

// --- Concurrency ---

func TestValidationCache_ConcurrentReadsSafe(t *testing.T) {
	mock := &mockValidator{
		response: &ValidateResponse{Valid: true, CacheTTL: 3600},
	}
	cache := NewValidationCache(mock)

	// Prime the cache
	_, _ = cache.Validate(context.Background(), "lic-1", "shared-token")

	// Fire 100 concurrent reads of the same token — all should hit cache.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.Validate(context.Background(), "lic-1", "shared-token")
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), mock.callCount.Load(),
		"100 concurrent cache hits must not trigger additional upstream calls")
}
