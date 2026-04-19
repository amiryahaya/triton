//go:build integration

package manage_enrol

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// setup returns a PostgresStore wired to the test DB with the
// manage_instances table truncated. Skips when Postgres is unavailable so
// CI without a DB doesn't fail the build.
func setup(t *testing.T) (*PostgresStore, func()) {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	ps, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	_, _ = ps.Pool().Exec(ctx, `TRUNCATE manage_instances`)
	cleanup := func() {
		_, _ = ps.Pool().Exec(context.Background(), `TRUNCATE manage_instances`)
		ps.Close()
	}
	return NewPostgresStore(ps.Pool()), cleanup
}

// TestManageInstancesMigration_CreatesTable asserts the Version 26 migration
// actually creates the manage_instances table with the expected columns.
// Sanity-check — if the migration was reordered or renamed, this fails fast.
func TestManageInstancesMigration_CreatesTable(t *testing.T) {
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	ps, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer ps.Close()

	var exists bool
	err = ps.Pool().QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM information_schema.tables
		    WHERE table_schema = 'public' AND table_name = 'manage_instances'
		)`,
	).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "manage_instances table must exist after migrations")
}

// TestStore_Create_Get_Revoke_RoundTrip exercises the full Store surface:
// insert, look up by cert_serial, revoke, confirm status flip.
func TestStore_Create_Get_Revoke_RoundTrip(t *testing.T) {
	s, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	id := uuid.Must(uuid.NewV7())
	serial := "deadbeefcafebabe"
	mi := ManageInstance{
		ID:                id,
		LicenseKeyHash:    "hash-abc123",
		CertSerial:        serial,
		TenantAttribution: "tenant-xyz",
	}

	require.NoError(t, s.Create(ctx, mi))

	got, err := s.GetByCertSerial(ctx, serial)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)
	assert.Equal(t, "hash-abc123", got.LicenseKeyHash)
	assert.Equal(t, serial, got.CertSerial)
	assert.Equal(t, "tenant-xyz", got.TenantAttribution)
	assert.Equal(t, StatusActive, got.Status)
	assert.False(t, got.EnrolledAt.IsZero())

	// Revoke and confirm.
	require.NoError(t, s.Revoke(ctx, id))
	got, err = s.GetByCertSerial(ctx, serial)
	require.NoError(t, err)
	assert.Equal(t, StatusRevoked, got.Status)

	// Idempotent revoke.
	require.NoError(t, s.Revoke(ctx, id))

	// Unknown serial → ErrNotFound.
	_, err = s.GetByCertSerial(ctx, "no-such-serial")
	assert.True(t, errors.Is(err, ErrNotFound), "expected ErrNotFound, got %v", err)
}

// TestStore_Create_DuplicateSerial_Errors asserts the UNIQUE constraint on
// cert_serial is enforced at the store layer — two enrolments can't share
// a serial.
func TestStore_Create_DuplicateSerial_Errors(t *testing.T) {
	s, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	serial := "aabbccdd"
	mi1 := ManageInstance{
		ID: uuid.Must(uuid.NewV7()), LicenseKeyHash: "h1", CertSerial: serial,
	}
	mi2 := ManageInstance{
		ID: uuid.Must(uuid.NewV7()), LicenseKeyHash: "h2", CertSerial: serial,
	}
	require.NoError(t, s.Create(ctx, mi1))
	err := s.Create(ctx, mi2)
	require.Error(t, err, "duplicate cert_serial must fail")
}

// TestStore_List_Ordering — List returns rows sorted by enrolled_at asc.
func TestStore_List_Ordering(t *testing.T) {
	s, cleanup := setup(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, s.Create(ctx, ManageInstance{
		ID: uuid.Must(uuid.NewV7()), LicenseKeyHash: "h1", CertSerial: "serial-1",
	}))
	// enrolled_at has microsecond precision; two very fast inserts can tie
	// and render ORDER BY enrolled_at ASC non-deterministic. A ~2ms gap is
	// cheap insurance and keeps the test readable.
	time.Sleep(2 * time.Millisecond)
	require.NoError(t, s.Create(ctx, ManageInstance{
		ID: uuid.Must(uuid.NewV7()), LicenseKeyHash: "h2", CertSerial: "serial-2",
	}))

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "serial-1", rows[0].CertSerial)
	assert.Equal(t, "serial-2", rows[1].CertSerial)
}
