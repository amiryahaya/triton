//go:build integration

package managestore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationV16_CredentialsSchema asserts migration v16:
//   - creates the manage_credentials table with the expected schema
//   - adds credentials_ref (FK, nullable) and ssh_port (INT, NOT NULL default 22) to manage_hosts
//     (column was named access_port in v16 and renamed to ssh_port in v19)
func TestMigrationV16_CredentialsSchema(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// manage_credentials table must exist
	require.True(t, tableExists(t, s, "manage_credentials"),
		"manage_credentials table must exist after v16")

	// manage_credentials required columns
	for _, col := range []string{"id", "tenant_id", "name", "auth_type", "vault_path", "created_at"} {
		assert.True(t, columnExists(t, s, "manage_credentials", col),
			"manage_credentials must have column %q", col)
	}

	// manage_hosts must have credentials_ref + ssh_port (renamed from access_port in v19)
	assert.True(t, columnExists(t, s, "manage_hosts", "credentials_ref"),
		"manage_hosts must have credentials_ref column after v16")
	assert.True(t, columnExists(t, s, "manage_hosts", "ssh_port"),
		"manage_hosts must have ssh_port column (renamed from access_port in v19)")

	// ssh_port default must be 22: insert a host row without specifying
	// ssh_port and read the stored value back.
	// hostname is required (NOT NULL since v19).
	var sshPort int
	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_hosts (ip, hostname)
		VALUES ('192.0.2.1'::inet, 'v16-test-host')
		RETURNING ssh_port
	`).Scan(&sshPort)
	require.NoError(t, err, "insert without ssh_port must succeed")
	assert.Equal(t, 22, sshPort, "ssh_port default must be 22")

	// auth_type CHECK constraint: verify the valid values are accepted
	// by attempting an INSERT with each valid auth_type.
	// Use a tenant_id that is a valid UUID.
	tenantID := "00000000-0000-0000-0000-000000000001"
	for _, authType := range []string{"ssh-key", "ssh-password", "winrm-password"} {
		_, err := s.ExecForTest(ctx,
			`INSERT INTO manage_credentials (tenant_id, name, auth_type, vault_path)
			 VALUES ($1::uuid, $2, $3, '/vault/test')`,
			tenantID, "cred-"+authType, authType)
		assert.NoError(t, err, "auth_type %q should be accepted", authType)
	}

	// An invalid auth_type must be rejected.
	_, err = s.ExecForTest(ctx,
		`INSERT INTO manage_credentials (tenant_id, name, auth_type, vault_path)
		 VALUES ($1::uuid, 'bad', 'invalid-type', '/vault/bad')`,
		tenantID)
	assert.Error(t, err, "invalid auth_type must be rejected by CHECK constraint")
}
