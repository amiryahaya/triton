package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*DatabaseModule)(nil)

func TestDatabaseModule_Name(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	assert.Equal(t, "database", m.Name())
}

func TestDatabaseModule_Category(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	assert.Equal(t, model.CategoryActiveRuntime, m.Category())
}

func TestDatabaseModule_ScanTargetType(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	assert.Equal(t, model.TargetDatabase, m.ScanTargetType())
}

func TestDatabaseModule_ParsePostgresSSL(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `ssl|on
ssl_ciphers|HIGH:MEDIUM:+3DES:!aNULL
ssl_min_protocol_version|TLSv1.2
ssl_max_protocol_version|TLSv1.3
password_encryption|scram-sha-256`

	findings := m.parsePostgresSettings(output, "postgres://localhost:5432/mydb")
	require.NotEmpty(t, findings)

	// Should emit findings for each setting
	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.Equal(t, "database", f.Module)
		assert.Equal(t, "database", f.Source.Type)
		assert.Equal(t, "postgres://localhost:5432/mydb", f.Source.Endpoint)
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
		assert.Equal(t, 0.90, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
	}
	// Should have findings for: ssl=on, ssl_ciphers, ssl_min, ssl_max, password_encryption
	assert.Len(t, findings, 5, "should emit one finding per setting")
}

func TestDatabaseModule_ParsePostgresExtensions(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `pgcrypto|1.3
pg_tde|1.0
pgsodium|3.1.9`

	findings := m.parsePostgresExtensions(output, "postgres://localhost:5432/mydb")
	require.Len(t, findings, 3)

	libs := make([]string, 0, len(findings))
	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.Equal(t, "database", f.Module)
		assert.NotNil(t, f.CryptoAsset)
		libs = append(libs, f.CryptoAsset.Library)
	}
	assert.Contains(t, libs[0], "pgcrypto", "should detect pgcrypto extension")
	assert.Contains(t, libs[1], "pg_tde", "should detect pg_tde extension")
	assert.Contains(t, libs[2], "pgsodium", "should detect pgsodium extension")
}

func TestDatabaseModule_ParsePostgresSSLStatus(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `t|TLSv1.3|TLS_AES_256_GCM_SHA384|256`

	findings := m.parsePostgresSSLStatus(output, "postgres://localhost:5432/mydb")
	require.NotEmpty(t, findings)

	f := findings[0]
	assert.Equal(t, 7, f.Category)
	assert.NotNil(t, f.CryptoAsset)
	assert.NotEmpty(t, f.CryptoAsset.Algorithm, "should have classified algorithm")
	assert.Equal(t, 256, f.CryptoAsset.KeySize)
	assert.Equal(t, "Active TLS connection cipher", f.CryptoAsset.Function)
	assert.NotEmpty(t, f.CryptoAsset.PQCStatus, "should have PQC classification")
}

func TestDatabaseModule_ParseMySQLEncryption(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `have_ssl	YES
ssl_cipher	TLS_AES_256_GCM_SHA384
tls_version	TLSv1.2,TLSv1.3
innodb_encrypt_tables	ON
default_table_encryption	ON`

	findings := m.parseMySQLVariables(output, "mysql://localhost:3306/mydb")
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.Equal(t, "database", f.Module)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
	}
	assert.GreaterOrEqual(t, len(findings), 3, "should detect SSL, cipher, and encryption settings")
}

func TestDatabaseModule_ParseMySQLTablespaces(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `innodb_system	innodb_system	Y
test/customers	test/customers	Y`

	findings := m.parseMySQLTablespaces(output, "mysql://localhost:3306/mydb")
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.NotNil(t, f.CryptoAsset)
		assert.Equal(t, "AES", f.CryptoAsset.Algorithm)
		assert.Equal(t, "InnoDB tablespace encryption", f.CryptoAsset.Function)
	}
}

func TestDatabaseModule_ParseSQLServerTDE(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `master	3	AES	256
tempdb	3	AES	256
myapp	3	TRIPLE_DES	168`

	findings := m.parseSQLServerTDE(output, "sqlserver://localhost:1433")
	require.Len(t, findings, 3)

	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.NotNil(t, f.CryptoAsset)
		assert.Contains(t, []string{"AES", "3DES"}, f.CryptoAsset.Algorithm)
		assert.Equal(t, "TDE encryption", f.CryptoAsset.Function)
	}

	// Verify key sizes
	assert.Equal(t, 256, findings[0].CryptoAsset.KeySize)
	assert.Equal(t, 168, findings[2].CryptoAsset.KeySize)
}

func TestDatabaseModule_ParseOracleTDE(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	walletOutput := `/opt/oracle/wallet	OPEN	AUTOLOGIN`
	columnOutput := `CUSTOMERS	SSN	AES256
EMPLOYEES	SALARY	AES192`

	findings := m.parseOracleWallet(walletOutput, "oracle://localhost:1521")
	require.Len(t, findings, 1)
	assert.Equal(t, "Oracle TDE wallet", findings[0].CryptoAsset.Function)

	findings2 := m.parseOracleEncryptedColumns(columnOutput, "oracle://localhost:1521")
	require.Len(t, findings2, 2)

	for _, f := range findings2 {
		assert.Equal(t, 7, f.Category)
		assert.NotNil(t, f.CryptoAsset)
		assert.Equal(t, "Column-level encryption", f.CryptoAsset.Function)
	}
	assert.Equal(t, "AES", findings2[0].CryptoAsset.Algorithm)
	assert.Equal(t, 256, findings2[0].CryptoAsset.KeySize)
}

func TestDatabaseModule_AutoDiscovery(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	pgrepOutput := `1234 /usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main
5678 /usr/sbin/mysqld --basedir=/usr`

	dbs := m.parseProcessDiscovery(pgrepOutput)
	require.Len(t, dbs, 2)

	types := make(map[string]bool)
	for _, db := range dbs {
		types[db.dbType] = true
	}
	assert.True(t, types["postgres"])
	assert.True(t, types["mysql"])
}

func TestDatabaseModule_PostgresConfigFile(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	pgConf := `# PostgreSQL configuration
listen_addresses = '*'
port = 5432
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
ssl_min_protocol_version = 'TLSv1.2'
password_encryption = scram-sha-256
`

	findings := m.parsePostgresConfigFile(pgConf, "postgres://localhost:5432")
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.Equal(t, "database", f.Module)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
	}
	// Should have: ssl=on, ssl_ciphers, ssl_min_protocol_version, password_encryption
	assert.GreaterOrEqual(t, len(findings), 3, "should detect SSL and password settings from config file")
}

func TestDatabaseModule_MySQLConfigFile(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	myConf := `[mysqld]
ssl-ca=/etc/mysql/certs/ca.pem
ssl-cert=/etc/mysql/certs/server-cert.pem
ssl-key=/etc/mysql/certs/server-key.pem
require_secure_transport=ON
tls_version=TLSv1.2,TLSv1.3
innodb_encrypt_tables=ON
default_table_encryption=ON
`

	findings := m.parseMySQLConfigFile(myConf, "mysql://localhost:3306")
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, 7, f.Category)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
	}
	// Should have: ssl-ca, ssl-cert, ssl-key (TLS), require_secure_transport, tls_version,
	// innodb_encrypt_tables, default_table_encryption
	assert.GreaterOrEqual(t, len(findings), 5, "should detect TLS and encryption settings from config")
}

func TestDatabaseModule_NoDBsRunning(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetDatabase, Value: "auto"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)

	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestDatabaseModule_ContextCancellation(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("1234 /usr/sbin/postgres -D /var/lib/postgresql/16/main"), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetDatabase, Value: "auto"}
	err := m.Scan(ctx, target, findings)
	close(findings)

	// Should either return context error or nil (graceful)
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}

func TestDatabaseModule_FindingClassification(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	// Parse settings that produce classifiable algorithms
	output := `ssl_min_protocol_version|TLSv1.2`
	findings := m.parsePostgresSettings(output, "postgres://localhost:5432/db")
	require.NotEmpty(t, findings)

	f := findings[0]
	require.NotNil(t, f.CryptoAsset)
	assert.NotEmpty(t, f.CryptoAsset.PQCStatus, "PQC classification should be applied")
}

func TestDatabaseModule_ExplicitTarget(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	// Track which commands were run
	var cmdsRun []string
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdsRun = append(cmdsRun, name)
		return []byte("ssl|on\nssl_min_protocol_version|TLSv1.2"), nil
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetDatabase, Value: "postgres://dbhost:5432/mydb"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)

	require.NoError(t, err)

	for range findings {
	}
	// Should have called psql (not pgrep for discovery)
	assert.Contains(t, cmdsRun, "psql", "should probe postgres directly with psql")
}

func TestDatabaseModule_ParseProcessDiscovery_SQLServer(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `9876 /opt/mssql/bin/sqlservr --accept-eula`

	dbs := m.parseProcessDiscovery(output)
	require.Len(t, dbs, 1)
	assert.Equal(t, "sqlserver", dbs[0].dbType)
}

func TestDatabaseModule_ParseProcessDiscovery_Oracle(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `5555 /u01/app/oracle/product/19.0.0/dbhome_1/bin/oracle_instance`

	dbs := m.parseProcessDiscovery(output)
	require.Len(t, dbs, 1)
	assert.Equal(t, "oracle", dbs[0].dbType)
}

func TestDatabaseModule_PostgresSSLOff(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})

	output := `ssl|off
password_encryption|md5`

	findings := m.parsePostgresSettings(output, "postgres://localhost:5432/mydb")
	require.NotEmpty(t, findings)

	// md5 should be classified
	var hasMD5 bool
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "MD5" {
			hasMD5 = true
		}
	}
	assert.True(t, hasMD5, "should detect MD5 password hashing")
}

func TestSafeHostPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		defHost string
		defPort string
		wantOK  bool
	}{
		{"normal", "postgres://localhost:5432/db", "localhost", "5432", true},
		{"flag-injection-host", "postgres://-h:5432/db", "localhost", "5432", false},
		{"non-numeric-port", "postgres://host:abc/db", "localhost", "5432", false},
		{"empty-host-uses-default", "postgres://:5432/db", "localhost", "5432", true},
		{"empty-port-uses-default", "postgres://myhost/db", "localhost", "5432", true},
		{"newline-in-host", "postgres://evil\nhost:5432/db", "localhost", "5432", false},
		{"null-byte-in-host", "postgres://evil\x00host:5432/db", "localhost", "5432", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, ok := safeHostPort(tt.input, tt.defHost, tt.defPort)
			assert.Equal(t, tt.wantOK, ok, "safeHostPort(%q) ok", tt.input)
			if ok {
				assert.NotEmpty(t, host)
				assert.NotEmpty(t, port)
			}
			_ = host
			_ = port
		})
	}
}

func TestDatabaseModule_MalformedTarget(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	for _, target := range []string{"no-scheme", "", "://bad", "just-a-hostname"} {
		findings := make(chan *model.Finding, 10)
		err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetDatabase, Value: target}, findings)
		close(findings)
		assert.NoError(t, err, "should not error on malformed target %q", target)

		var collected []*model.Finding
		for f := range findings {
			collected = append(collected, f)
		}
		assert.Empty(t, collected, "should not emit findings for malformed target %q", target)
	}
}

func TestDatabaseModule_NoPgrepMatches(t *testing.T) {
	m := NewDatabaseModule(&scannerconfig.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("exit status 1")
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetDatabase, Value: "auto"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)

	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "pgrep exit 1 means no databases running")
}
