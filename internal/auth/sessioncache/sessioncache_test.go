package sessioncache

import (
	"sync"
	"testing"
	"time"
)

func makeEntry(userID string) Entry {
	return Entry{
		UserID:             userID,
		OrgID:              "org-1",
		Role:               "org_user",
		MustChangePassword: false,
		JWTExpiry:          time.Now().Add(15 * time.Minute),
	}
}

func TestGetMissReturnsFalse(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	if _, ok := c.Get("nope"); ok {
		t.Fatalf("Get on empty cache returned ok=true")
	}
}

func TestPutThenGetHit(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	e := makeEntry("u1")
	c.Put("k1", e)
	got, ok := c.Get("k1")
	if !ok {
		t.Fatalf("Get after Put returned ok=false")
	}
	if got.UserID != "u1" {
		t.Errorf("UserID = %q, want u1", got.UserID)
	}
}

func TestTTLExpiry(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: 20 * time.Millisecond})
	c.Put("k1", makeEntry("u1"))
	time.Sleep(30 * time.Millisecond)
	if _, ok := c.Get("k1"); ok {
		t.Fatalf("entry not expired after TTL elapsed")
	}
}

func TestJWTExpiryBoundsTTL(t *testing.T) {
	// If the JWT's own exp is sooner than the cache TTL, the cache
	// must honor the JWT exp — never hand back a token that the
	// signer already considers dead.
	c := New(Config{MaxEntries: 10, TTL: time.Hour})
	e := makeEntry("u1")
	e.JWTExpiry = time.Now().Add(-1 * time.Second)
	c.Put("k1", e)
	if _, ok := c.Get("k1"); ok {
		t.Fatalf("expired JWT returned from cache")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(Config{MaxEntries: 2, TTL: time.Minute})
	c.Put("a", makeEntry("ua"))
	c.Put("b", makeEntry("ub"))
	// Touch "a" to make it most-recently-used.
	if _, ok := c.Get("a"); !ok {
		t.Fatalf("Get(a) miss")
	}
	c.Put("c", makeEntry("uc"))
	if _, ok := c.Get("b"); ok {
		t.Errorf("b should have been evicted (LRU)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Errorf("a should still be present")
	}
	if _, ok := c.Get("c"); !ok {
		t.Errorf("c should be present")
	}
	if n := c.Len(); n != 2 {
		t.Errorf("Len = %d, want 2", n)
	}
}

func TestPutOverwritesExisting(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	c.Put("k", makeEntry("old"))
	c.Put("k", makeEntry("new"))
	got, _ := c.Get("k")
	if got.UserID != "new" {
		t.Errorf("UserID = %q, want new", got.UserID)
	}
	if n := c.Len(); n != 1 {
		t.Errorf("Len = %d after overwrite, want 1", n)
	}
}

func TestDelete(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	c.Put("k", makeEntry("u1"))
	c.Delete("k")
	if _, ok := c.Get("k"); ok {
		t.Fatalf("Delete did not remove entry")
	}
	// Delete on missing key is a no-op, not a panic.
	c.Delete("never-existed")
}

func TestDeleteByUserID(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	c.Put("hash-a", makeEntry("alice")) // OrgID "org-1"
	c.Put("hash-b", makeEntry("bob"))
	c.Put("hash-a2", makeEntry("alice")) // alice has two active sessions

	n := c.DeleteByUserID("alice")
	if n != 2 {
		t.Errorf("DeleteByUserID(alice) = %d, want 2", n)
	}
	if _, ok := c.Get("hash-a"); ok {
		t.Errorf("hash-a should be gone")
	}
	if _, ok := c.Get("hash-a2"); ok {
		t.Errorf("hash-a2 should be gone")
	}
	if _, ok := c.Get("hash-b"); !ok {
		t.Errorf("bob's entry should still be present")
	}
	// Missing user is a no-op, not an error.
	if n := c.DeleteByUserID("ghost"); n != 0 {
		t.Errorf("DeleteByUserID(ghost) = %d, want 0", n)
	}
	// Empty user ID is a no-op (defensive — an empty string would
	// otherwise match any zero-value cached entry if the cache is
	// ever populated with one).
	if n := c.DeleteByUserID(""); n != 0 {
		t.Errorf("DeleteByUserID(\"\") = %d, want 0", n)
	}
}

func TestFlushRemovesAll(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	c.Put("a", makeEntry("ua"))
	c.Put("b", makeEntry("ub"))
	c.Put("c", makeEntry("uc"))
	n := c.Flush()
	if n != 3 {
		t.Errorf("Flush returned %d, want 3", n)
	}
	if c.Len() != 0 {
		t.Errorf("Len after Flush = %d, want 0", c.Len())
	}
}

func TestStatsHitMiss(t *testing.T) {
	c := New(Config{MaxEntries: 10, TTL: time.Minute})
	c.Get("miss1")
	c.Put("k", makeEntry("u"))
	c.Get("k")
	c.Get("k")
	c.Get("miss2")
	s := c.Stats()
	if s.Hits != 2 {
		t.Errorf("Hits = %d, want 2", s.Hits)
	}
	if s.Misses != 2 {
		t.Errorf("Misses = %d, want 2", s.Misses)
	}
}

func TestNilCacheDisabled(t *testing.T) {
	// Zero-valued config disables the cache (size==0).
	c := New(Config{})
	c.Put("k", makeEntry("u"))
	if _, ok := c.Get("k"); ok {
		t.Errorf("disabled cache should not retain entries")
	}
}

func TestConcurrentGetPut(t *testing.T) {
	c := New(Config{MaxEntries: 64, TTL: time.Minute})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "k"
			c.Put(key, makeEntry("u"))
			for j := 0; j < 100; j++ {
				c.Get(key)
			}
		}(i)
	}
	wg.Wait()
}
