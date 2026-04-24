//go:build integration

package licensestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestCountUsers_EmptyAndPopulated(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	n, err := s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	u := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    "a@b.com",
		Name:     "A",
		Role:     "platform_admin",
		Password: "$2a$10$fakebcrypthashfortesting000000000000000000000000000000",
	}
	require.NoError(t, s.CreateUser(ctx, u))

	n, err = s.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestCountPlatformAdmins_IgnoresOrgUsers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	org := makeOrg(t)
	require.NoError(t, s.CreateOrg(ctx, org))

	admin := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    "admin@test.com",
		Name:     "Admin",
		Role:     "platform_admin",
		Password: "$2a$10$fakebcrypthashfortesting000000000000000000000000000000",
	}
	orgUser := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    org.ID,
		Email:    "orguser@test.com",
		Name:     "OrgUser",
		Role:     "org_user",
		Password: "$2a$10$fakebcrypthashfortesting000000000000000000000000000000",
	}
	require.NoError(t, s.CreateUser(ctx, admin))
	require.NoError(t, s.CreateUser(ctx, orgUser))

	n, err := s.CountPlatformAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestDeleteSessionsForUser_RevokesAll(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    "sessuser@test.com",
		Name:     "SessUser",
		Role:     "platform_admin",
		Password: "$2a$10$fakebcrypthashfortesting000000000000000000000000000000",
	}
	require.NoError(t, s.CreateUser(ctx, u))

	s1 := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    u.ID,
		TokenHash: "hash1-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s2 := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    u.ID,
		TokenHash: "hash2-" + uuid.Must(uuid.NewV7()).String(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, s.CreateSession(ctx, s1))
	require.NoError(t, s.CreateSession(ctx, s2))

	require.NoError(t, s.DeleteSessionsForUser(ctx, u.ID))

	for _, h := range []string{s1.TokenHash, s2.TokenHash} {
		_, err := s.GetSessionByHash(ctx, h)
		assert.Error(t, err, "session with hash %q should be gone", h)
	}
}
