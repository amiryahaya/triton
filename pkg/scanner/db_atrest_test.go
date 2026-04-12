package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsDBAtRestFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// Oracle Wallet
		{"/opt/oracle/wallet/ewallet.p12", true},
		{"/etc/oracle/wallet/cwallet.sso", true},
		{"/opt/oracle/admin/orcl/wallet/ewallet.p12", true},

		// MySQL keyring
		{"/var/lib/mysql-keyring/keyring", true},
		{"/var/lib/mysql/keyring-encrypted", true},
		{"/etc/mysql/keyring.conf", true},
		{"/etc/percona/keyring.conf", true},

		// MSSQL TDE
		{"/var/opt/mssql/secrets/mssql.conf", true},
		{"/etc/mssql-conf/mssql.conf", true},

		// PostgreSQL TDE (community extensions)
		{"/etc/postgresql/15/main/postgresql.conf", true},

		// LUKS
		{"/etc/crypttab", true},

		// Not at-rest
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/wallet.txt", false},
		{"/var/lib/mysql/data/ibdata1", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isDBAtRestFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- Oracle Wallet tests ---

func TestParseOracleWallet_PKCS12(t *testing.T) {
	// Oracle ewallet.p12 is a PKCS#12 file — we report its presence
	// and format, not the contents (would require the wallet password).
	m := &DBAtRestModule{}
	findings := m.parseOracleWallet("/opt/oracle/wallet/ewallet.p12")
	require.Len(t, findings, 1)
	assert.Equal(t, "Oracle Wallet (PKCS#12)", findings[0].CryptoAsset.Function)
	assert.Equal(t, "PKCS#12", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "db_atrest", findings[0].Module)
}

func TestParseOracleWallet_SSO(t *testing.T) {
	m := &DBAtRestModule{}
	findings := m.parseOracleWallet("/etc/oracle/wallet/cwallet.sso")
	require.Len(t, findings, 1)
	assert.Equal(t, "Oracle Wallet (SSO auto-login)", findings[0].CryptoAsset.Function)
	assert.Equal(t, "3DES", findings[0].CryptoAsset.Algorithm)
}

// --- MySQL keyring tests ---

func TestParseMySQLKeyring_EncryptedFile(t *testing.T) {
	conf := `[mysqld]
early-plugin-load=keyring_encrypted_file.so
keyring_encrypted_file_data=/var/lib/mysql-keyring/keyring-encrypted
keyring_encrypted_file_password=secret
`
	m := &DBAtRestModule{}
	findings := m.parseMySQLKeyringConfig("/etc/mysql/keyring.conf", []byte(conf))
	require.NotEmpty(t, findings)

	found := false
	for _, f := range findings {
		if f.CryptoAsset.Function == "MySQL keyring plugin" {
			found = true
			assert.Equal(t, "AES-256", f.CryptoAsset.Algorithm)
		}
	}
	assert.True(t, found)
}

func TestParseMySQLKeyring_FilePlugin(t *testing.T) {
	conf := `[mysqld]
early-plugin-load=keyring_file.so
keyring_file_data=/var/lib/mysql-keyring/keyring
`
	m := &DBAtRestModule{}
	findings := m.parseMySQLKeyringConfig("/etc/mysql/keyring.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "MySQL keyring plugin", findings[0].CryptoAsset.Function)
}

func TestParseMySQLKeyring_NoPlugin(t *testing.T) {
	conf := `[mysqld]
datadir=/var/lib/mysql
`
	m := &DBAtRestModule{}
	findings := m.parseMySQLKeyringConfig("/etc/mysql/keyring.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- MSSQL TDE tests ---

func TestParseMSSQLConf_TDE(t *testing.T) {
	conf := `[sqlagent]
enabled = true
[network]
tlscert = /etc/ssl/mssql.pem
tlskey = /etc/ssl/mssql.key
tlsprotocols = 1.2
forceencryption = 1
`
	m := &DBAtRestModule{}
	findings := m.parseMSSQLConfig("/var/opt/mssql/secrets/mssql.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["MSSQL TLS protocol"])
	assert.True(t, funcSet["MSSQL forced encryption"])
}

func TestParseMSSQLConf_NoTLS(t *testing.T) {
	conf := `[sqlagent]
enabled = true
`
	m := &DBAtRestModule{}
	findings := m.parseMSSQLConfig("/var/opt/mssql/secrets/mssql.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- LUKS / crypttab tests ---

func TestParseCrypttab(t *testing.T) {
	conf := `# /etc/crypttab
# target  source                                   keyfile         options
data_crypt UUID=abcd-1234-5678-efgh /etc/keys/data.key luks,discard
swap_crypt /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64,size=256
root_crypt UUID=wxyz-9876 none luks
`
	m := &DBAtRestModule{}
	findings := m.parseCrypttab("/etc/crypttab", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	algoSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["LUKS"], "LUKS volumes should be reported")
	assert.True(t, algoSet["AES-XTS"], "explicit cipher should be parsed")
}

func TestParseCrypttab_Empty(t *testing.T) {
	conf := `# empty crypttab
`
	m := &DBAtRestModule{}
	findings := m.parseCrypttab("/etc/crypttab", []byte(conf))
	assert.Empty(t, findings)
}

func TestParseCrypttab_SwapOnly(t *testing.T) {
	conf := `swap /dev/sda2 /dev/urandom swap,cipher=aes-cbc-essiv:sha256,size=256
`
	m := &DBAtRestModule{}
	findings := m.parseCrypttab("/etc/crypttab", []byte(conf))
	require.Len(t, findings, 1)
	assert.Equal(t, "AES-CBC", findings[0].CryptoAsset.Algorithm)
}

// --- PostgreSQL TDE tests ---

func TestParsePostgreSQLConf_TDE(t *testing.T) {
	conf := `# PostgreSQL with pg_tde or similar
shared_preload_libraries = 'pg_tde'
pg_tde.keyring_provider = 'file'
pg_tde.keyring_file = '/etc/postgresql/keyring/key.json'
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:!aNULL'
`
	m := &DBAtRestModule{}
	findings := m.parsePostgreSQLConfig("/etc/postgresql/15/main/postgresql.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["PostgreSQL TDE"])
	assert.True(t, funcSet["PostgreSQL TLS protocol"])
}

func TestParsePostgreSQLConf_NoEncryption(t *testing.T) {
	conf := `listen_addresses = '*'
port = 5432
`
	m := &DBAtRestModule{}
	findings := m.parsePostgreSQLConfig("/etc/postgresql/15/main/postgresql.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- module interface tests ---

func TestDBAtRestModuleInterface(t *testing.T) {
	m := NewDBAtRestModule(nil)
	assert.Equal(t, "db_atrest", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}

// --- luksDump command runner mock tests ---

func TestLuksDump_Mock(t *testing.T) {
	orig := dbAtRestCmdRunner
	defer func() { dbAtRestCmdRunner = orig }()

	dbAtRestCmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`LUKS header information
Version:       	2
Epoch:         	5
Metadata area: 	16384 [bytes]
UUID:          	abcd1234-5678-9012-3456-789012345678

Keyslots:
  0: luks2
	Key:        256 bits
	Priority:   normal
	Cipher:     aes-xts-plain64
	Cipher key: 512 bits
`), nil
	}

	m := &DBAtRestModule{}
	findings := m.parseLuksDump(context.Background(), "/dev/sda1")
	require.NotEmpty(t, findings)
	assert.Equal(t, "AES-XTS", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, 512, findings[0].CryptoAsset.KeySize)
}

func TestLuksDump_NotAvailable(t *testing.T) {
	orig := dbAtRestCmdRunner
	defer func() { dbAtRestCmdRunner = orig }()

	dbAtRestCmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("command not found")
	}

	m := &DBAtRestModule{}
	findings := m.parseLuksDump(context.Background(), "/dev/sda1")
	assert.Empty(t, findings)
}
