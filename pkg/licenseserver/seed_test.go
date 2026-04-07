//go:build integration

package licenseserver_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// setupTestStore returns an isolated test store, reusing the same schema
// isolation as setupTestServer but without spinning up an HTTP server.
func setupTestStore(t *testing.T) *licensestore.PostgresStore {
	t.Helper()
	_, store := setupTestServer(t)
	return store
}

func TestSeedInitialSuperadmin_NoUsers(t *testing.T) {
	store := setupTestStore(t)

	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "bootstrap@example.com", "correct-horse-battery-staple")
	require.NoError(t, err)
	assert.True(t, created, "expected created=true on empty store")

	// Verify the user landed in the store with the right role.
	users, err := store.ListUsers(t.Context(), licensestore.UserFilter{})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "bootstrap@example.com", users[0].Email)
	assert.Equal(t, "platform_admin", users[0].Role)
	assert.Equal(t, "", users[0].OrgID)
}

func TestSeedInitialSuperadmin_AlreadySeeded(t *testing.T) {
	store := setupTestStore(t)

	// Seed once.
	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "first@example.com", "correct-horse-battery-staple")
	require.NoError(t, err)
	require.True(t, created)

	// Second call should be a no-op even with different credentials.
	created2, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "second@example.com", "another-strong-passphrase")
	require.NoError(t, err)
	assert.False(t, created2, "expected created=false when users already exist")

	// Confirm only the first user exists.
	users, err := store.ListUsers(t.Context(), licensestore.UserFilter{})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "first@example.com", users[0].Email)
}

func TestSeedInitialSuperadmin_EmptyPassword(t *testing.T) {
	store := setupTestStore(t)

	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "bootstrap@example.com", "")
	require.Error(t, err)
	assert.False(t, created)
	assert.Contains(t, strings.ToLower(err.Error()), "password")
}

func TestSeedInitialSuperadmin_WeakPassword(t *testing.T) {
	store := setupTestStore(t)

	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "bootstrap@example.com", "short")
	require.Error(t, err)
	assert.False(t, created)
	assert.Contains(t, strings.ToLower(err.Error()), "password")
}

func TestSeedInitialSuperadmin_InvalidEmail(t *testing.T) {
	store := setupTestStore(t)

	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "notanemail", "correct-horse-battery-staple")
	require.Error(t, err)
	assert.False(t, created)
	assert.Contains(t, strings.ToLower(err.Error()), "email")
}

// TestSeedInitialSuperadmin_ConcurrentCallsAreRaceSafe forces multiple
// goroutines to race on Seed and verifies that exactly one wins, the others
// no-op cleanly without error, and only one user lands in the table. Without
// the ErrConflict handler in Seed, the losing goroutines would surface a
// unique-constraint violation as a fatal error (and a multi-replica deploy
// against an empty DB would crash one instance at startup).
func TestSeedInitialSuperadmin_ConcurrentCallsAreRaceSafe(t *testing.T) {
	store := setupTestStore(t)

	const concurrency = 20
	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var wg sync.WaitGroup
	results := make([]struct {
		created bool
		err     error
	}, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			startBarrier.Wait() // release all goroutines simultaneously
			results[idx].created, results[idx].err = licenseserver.SeedInitialSuperadmin(
				t.Context(), store, "race@example.com", "correct-horse-battery-staple",
			)
		}(i)
	}
	startBarrier.Done()
	wg.Wait()

	// Exactly one goroutine should report created=true; all others created=false.
	// None should return an error.
	createdCount := 0
	for _, r := range results {
		require.NoError(t, r.err)
		if r.created {
			createdCount++
		}
	}
	assert.Equal(t, 1, createdCount, "exactly one goroutine should create the user")

	// And the table should contain exactly one user.
	users, err := store.ListUsers(t.Context(), licensestore.UserFilter{})
	require.NoError(t, err)
	assert.Len(t, users, 1)
}

func TestSeedInitialSuperadmin_HashesPassword(t *testing.T) {
	store := setupTestStore(t)

	plaintext := "correct-horse-battery-staple"
	created, err := licenseserver.SeedInitialSuperadmin(t.Context(), store, "bootstrap@example.com", plaintext)
	require.NoError(t, err)
	require.True(t, created)

	user, err := store.GetUserByEmail(t.Context(), "bootstrap@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, user.Password, "stored password must not be plaintext")
	// Verify it's a valid bcrypt hash that matches the plaintext.
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plaintext)))
}
