package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// cmdRunnerFunc is a function type for executing external commands.
// It enables dependency injection for testing.
type cmdRunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// defaultCmdRunner executes a real subprocess command.
func defaultCmdRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// discoveredDB holds info about a detected database process.
type discoveredDB struct {
	dbType  string // "postgres", "mysql", "sqlserver", "oracle"
	process string // process command line
}

// DatabaseModule scans database instances for encryption settings,
// TDE configuration, and SSL/TLS status.
type DatabaseModule struct {
	config    *config.Config
	cmdRunner cmdRunnerFunc
}

// NewDatabaseModule creates a new DatabaseModule.
func NewDatabaseModule(cfg *config.Config) *DatabaseModule {
	return &DatabaseModule{
		config:    cfg,
		cmdRunner: defaultCmdRunner,
	}
}

func (m *DatabaseModule) Name() string                         { return "database" }
func (m *DatabaseModule) Category() model.ModuleCategory       { return model.CategoryActiveRuntime }
func (m *DatabaseModule) ScanTargetType() model.ScanTargetType { return model.TargetDatabase }

// Scan probes database instances for encryption and TLS configuration.
func (m *DatabaseModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "auto" {
		return m.scanAutoDiscovery(ctx, findings)
	}
	return m.scanExplicitTarget(ctx, target.Value, findings)
}

// scanAutoDiscovery detects running database processes and probes each.
func (m *DatabaseModule) scanAutoDiscovery(ctx context.Context, findings chan<- *model.Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Detect running database processes.
	// Use pgrep -l -f on macOS (no -a flag), pgrep -a on Linux.
	var output []byte
	var err error
	if runtime.GOOS == "darwin" {
		output, err = m.cmdRunner(ctx, "pgrep", "-l", "-f", "postgres|mysqld|sqlservr|oracle")
	} else {
		output, err = m.cmdRunner(ctx, "pgrep", "-a", "postgres|mysqld|sqlservr|oracle")
	}
	if err != nil {
		// Propagate context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// pgrep returns exit 1 when no matches — that's fine
		return nil
	}

	dbs := m.parseProcessDiscovery(string(output))
	if len(dbs) == 0 {
		return nil
	}

	for _, db := range dbs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		switch db.dbType {
		case "postgres":
			m.probePostgres(ctx, "postgres://localhost:5432", findings)
		case "mysql":
			m.probeMySQL(ctx, "mysql://localhost:3306", findings)
		case "sqlserver":
			m.probeSQLServer(ctx, "sqlserver://localhost:1433", findings)
		case "oracle":
			m.probeOracle(ctx, "oracle://localhost:1521", findings)
		}
	}

	return nil
}

// scanExplicitTarget probes a specific database endpoint.
func (m *DatabaseModule) scanExplicitTarget(ctx context.Context, target string, findings chan<- *model.Finding) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return nil // Skip malformed URLs
	}

	switch u.Scheme {
	case "postgres", "postgresql":
		m.probePostgres(ctx, target, findings)
	case "mysql":
		m.probeMySQL(ctx, target, findings)
	case "sqlserver":
		m.probeSQLServer(ctx, target, findings)
	case "oracle":
		m.probeOracle(ctx, target, findings)
	}

	return nil
}

// safeHostPort extracts and validates host/port from a URL string.
// Returns empty strings if the input is invalid or potentially malicious.
func safeHostPort(endpoint, defaultHost, defaultPort string) (host, port string, ok bool) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", false
	}

	host = u.Hostname()
	if host == "" {
		host = defaultHost
	}
	port = u.Port()
	if port == "" {
		port = defaultPort
	}

	// Reject hosts that could cause issues with subprocess arguments
	if strings.HasPrefix(host, "-") {
		return "", "", false
	}
	if strings.ContainsAny(host, "\n\r\x00") {
		return "", "", false
	}
	// Validate port is numeric
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false
	}

	return host, port, true
}

// parseProcessDiscovery parses pgrep output to identify running databases.
func (m *DatabaseModule) parseProcessDiscovery(output string) []discoveredDB {
	var dbs []discoveredDB
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)
		var dbType string
		switch {
		case strings.Contains(lower, "postgres"):
			dbType = "postgres"
		case strings.Contains(lower, "mysqld"):
			dbType = "mysql"
		case strings.Contains(lower, "sqlservr"):
			dbType = "sqlserver"
		case strings.Contains(lower, "oracle"):
			dbType = "oracle"
		default:
			continue
		}

		if seen[dbType] {
			continue
		}
		seen[dbType] = true
		dbs = append(dbs, discoveredDB{dbType: dbType, process: line})
	}

	return dbs
}

// --- PostgreSQL probing ---

func (m *DatabaseModule) probePostgres(ctx context.Context, endpoint string, findings chan<- *model.Finding) {
	host, port, ok := safeHostPort(endpoint, "localhost", "5432")
	if !ok {
		return
	}
	u, _ := url.Parse(endpoint)
	db := "postgres"
	if u != nil && u.Path != "" {
		db = strings.TrimPrefix(u.Path, "/")
		if db == "" {
			db = "postgres"
		}
	}

	baseArgs := []string{"-h", host, "-p", port, "-d", db, "-t", "-A"}

	// Query pg_settings for SSL/crypto settings
	settingsQuery := "SELECT name, setting FROM pg_settings WHERE name IN ('ssl', 'ssl_ciphers', 'ssl_min_protocol_version', 'ssl_max_protocol_version', 'password_encryption')"
	if out, err := m.cmdRunner(ctx, "psql", append(baseArgs, "-c", settingsQuery)...); err == nil {
		for _, f := range m.parsePostgresSettings(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}

	// Query crypto extensions
	extQuery := "SELECT extname, extversion FROM pg_extension WHERE extname IN ('pgcrypto', 'pg_tde', 'pgsodium')"
	if out, err := m.cmdRunner(ctx, "psql", append(baseArgs, "-c", extQuery)...); err == nil {
		for _, f := range m.parsePostgresExtensions(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}

	// Query active SSL connection status
	sslQuery := "SELECT ssl, version, cipher, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
	if out, err := m.cmdRunner(ctx, "psql", append(baseArgs, "-c", sslQuery)...); err == nil {
		for _, f := range m.parsePostgresSSLStatus(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}
}

// parsePostgresSettings parses psql pipe-delimited output from pg_settings.
func (m *DatabaseModule) parsePostgresSettings(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		var algo, function string

		switch name {
		case "ssl":
			if value == "on" {
				algo = "TLS"
				function = "Database SSL enabled"
			} else {
				algo = "NONE"
				function = "Database SSL disabled"
			}
		case "ssl_ciphers":
			algo = value
			function = "SSL cipher suite configuration"
		case "ssl_min_protocol_version":
			algo = normalizeTLSVersion(value)
			function = "Minimum TLS protocol version"
		case "ssl_max_protocol_version":
			if value != "" {
				algo = normalizeTLSVersion(value)
				function = "Maximum TLS protocol version"
			}
		case "password_encryption":
			algo = normalizePasswordAlgo(value)
			function = "Password hashing algorithm"
		default:
			continue
		}

		if algo == "" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  function,
			Algorithm: algo,
			Purpose:   fmt.Sprintf("PostgreSQL %s setting", name),
			Library:   "PostgreSQL",
			State:     cryptoState(name),
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// parsePostgresExtensions parses extension output (extname|extversion).
func (m *DatabaseModule) parsePostgresExtensions(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}

		extName := strings.TrimSpace(parts[0])
		extVersion := strings.TrimSpace(parts[1])

		var algo, function string
		switch extName {
		case "pgcrypto":
			algo = "AES"
			function = "PostgreSQL pgcrypto extension"
		case "pg_tde":
			algo = "AES"
			function = "PostgreSQL Transparent Data Encryption"
		case "pgsodium":
			algo = "XChaCha20-Poly1305"
			function = "PostgreSQL libsodium encryption"
		default:
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  function,
			Algorithm: algo,
			Purpose:   "Database encryption extension",
			Library:   fmt.Sprintf("%s v%s", extName, extVersion),
			State:     "AT_REST",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// parsePostgresSSLStatus parses pg_stat_ssl output (ssl|version|cipher|bits).
func (m *DatabaseModule) parsePostgresSSLStatus(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}

		sslEnabled := strings.TrimSpace(parts[0])
		if sslEnabled != "t" {
			continue
		}

		cipher := strings.TrimSpace(parts[2])
		bits, _ := strconv.Atoi(strings.TrimSpace(parts[3]))

		if cipher == "" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "Active TLS connection cipher",
			Algorithm: cipher,
			KeySize:   bits,
			Purpose:   "PostgreSQL active SSL connection",
			Library:   "PostgreSQL",
			State:     "IN_TRANSIT",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// --- MySQL probing ---

func (m *DatabaseModule) probeMySQL(ctx context.Context, endpoint string, findings chan<- *model.Finding) {
	host, port, ok := safeHostPort(endpoint, "localhost", "3306")
	if !ok {
		return
	}

	baseArgs := []string{"-h", host, "-P", port, "--batch", "--skip-column-names"}

	// Query encryption variables
	varQuery := "SHOW VARIABLES WHERE Variable_name LIKE '%encrypt%' OR Variable_name LIKE '%ssl%' OR Variable_name LIKE '%tls%'"
	if out, err := m.cmdRunner(ctx, "mysql", append(baseArgs, "-e", varQuery)...); err == nil {
		for _, f := range m.parseMySQLVariables(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}

	// Query encrypted tablespaces
	tsQuery := "SELECT SPACE, NAME, ENCRYPTION FROM INFORMATION_SCHEMA.INNODB_TABLESPACES WHERE ENCRYPTION='Y'"
	if out, err := m.cmdRunner(ctx, "mysql", append(baseArgs, "-e", tsQuery)...); err == nil {
		for _, f := range m.parseMySQLTablespaces(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}
}

// mysqlCryptoVars maps MySQL variable names to crypto significance.
var mysqlCryptoVars = map[string]struct {
	function string
	state    string
}{
	"have_ssl":                 {function: "SSL availability", state: "IN_TRANSIT"},
	"ssl_cipher":               {function: "Active SSL cipher", state: "IN_TRANSIT"},
	"tls_version":              {function: "Supported TLS versions", state: "IN_TRANSIT"},
	"innodb_encrypt_tables":    {function: "InnoDB table encryption", state: "AT_REST"},
	"default_table_encryption": {function: "Default table encryption", state: "AT_REST"},
}

// parseMySQLVariables parses MySQL SHOW VARIABLES output (tab-delimited).
func (m *DatabaseModule) parseMySQLVariables(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}

		varName := strings.TrimSpace(parts[0])
		varValue := strings.TrimSpace(parts[1])

		info, ok := mysqlCryptoVars[varName]
		if !ok {
			continue
		}

		if varValue == "" || varValue == "DISABLED" {
			continue
		}

		algo := normalizeMySQLAlgo(varName, varValue)
		if algo == "" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  info.function,
			Algorithm: algo,
			Purpose:   fmt.Sprintf("MySQL %s", varName),
			Library:   "MySQL",
			State:     info.state,
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// parseMySQLTablespaces parses InnoDB encrypted tablespace output (tab-delimited).
func (m *DatabaseModule) parseMySQLTablespaces(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 3 {
			continue
		}

		tablespace := strings.TrimSpace(parts[1])
		encrypted := strings.TrimSpace(parts[2])

		if encrypted != "Y" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "InnoDB tablespace encryption",
			Algorithm: "AES",
			Purpose:   fmt.Sprintf("Encrypted tablespace: %s", tablespace),
			Library:   "MySQL InnoDB",
			State:     "AT_REST",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// --- SQL Server probing ---

func (m *DatabaseModule) probeSQLServer(ctx context.Context, endpoint string, findings chan<- *model.Finding) {
	host, port, ok := safeHostPort(endpoint, "localhost", "1433")
	if !ok {
		return
	}

	server := fmt.Sprintf("%s,%s", host, port)

	tdeQuery := "SET NOCOUNT ON; SELECT d.name, dek.encryption_state, dek.key_algorithm, dek.key_length FROM sys.databases d JOIN sys.dm_database_encryption_keys dek ON d.database_id = dek.database_id"
	if out, err := m.cmdRunner(ctx, "sqlcmd", "-S", server, "-h", "-1", "-s", "\t", "-W", "-Q", tdeQuery); err == nil {
		for _, f := range m.parseSQLServerTDE(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}
}

// parseSQLServerTDE parses SQL Server TDE query output (tab-delimited).
func (m *DatabaseModule) parseSQLServerTDE(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 4 {
			continue
		}

		dbName := strings.TrimSpace(parts[0])
		keyAlgo := strings.TrimSpace(parts[2])
		keyLength, _ := strconv.Atoi(strings.TrimSpace(parts[3]))

		algo := normalizeSQLServerAlgo(keyAlgo)

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "TDE encryption",
			Algorithm: algo,
			KeySize:   keyLength,
			Purpose:   fmt.Sprintf("SQL Server TDE on database: %s", dbName),
			Library:   "SQL Server",
			State:     "AT_REST",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// --- Oracle probing ---

func (m *DatabaseModule) probeOracle(ctx context.Context, endpoint string, findings chan<- *model.Finding) {
	host, port, ok := safeHostPort(endpoint, "localhost", "1521")
	if !ok {
		return
	}

	connectStr := fmt.Sprintf("/@%s:%s", host, port)

	// Query wallet status
	walletQuery := "SET HEADING OFF FEEDBACK OFF PAGESIZE 0;\nSELECT WRL_PARAMETER, STATUS, WALLET_TYPE FROM V$ENCRYPTION_WALLET;\nEXIT;"
	if out, err := m.cmdRunner(ctx, "sqlplus", "-S", connectStr, walletQuery); err == nil {
		for _, f := range m.parseOracleWallet(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}

	// Query encrypted columns
	colQuery := "SET HEADING OFF FEEDBACK OFF PAGESIZE 0;\nSELECT TABLE_NAME, COLUMN_NAME, ENCRYPTION_ALG FROM DBA_ENCRYPTED_COLUMNS;\nEXIT;"
	if out, err := m.cmdRunner(ctx, "sqlplus", "-S", connectStr, colQuery); err == nil {
		for _, f := range m.parseOracleEncryptedColumns(string(out), endpoint) {
			emitFinding(ctx, findings, f)
		}
	}
}

// parseOracleWallet parses V$ENCRYPTION_WALLET output.
func (m *DatabaseModule) parseOracleWallet(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		walletPath := parts[0]
		status := parts[1]

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "Oracle TDE wallet",
			Algorithm: "AES",
			Purpose:   fmt.Sprintf("TDE wallet at %s (status: %s)", walletPath, status),
			Library:   "Oracle",
			State:     "AT_REST",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// oracleAlgoRegex extracts algorithm and key size from Oracle encryption algo names.
// Handles both "AES256" and "AES 256" formats.
var oracleAlgoRegex = regexp.MustCompile(`^(AES|3DES)[-_ ]?(\d+)?$`)

// parseOracleEncryptedColumns parses DBA_ENCRYPTED_COLUMNS output.
func (m *DatabaseModule) parseOracleEncryptedColumns(output, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		tableName := parts[0]
		columnName := parts[1]
		encAlgo := parts[2]

		algo, keySize := parseOracleAlgo(encAlgo)

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "Column-level encryption",
			Algorithm: algo,
			KeySize:   keySize,
			Purpose:   fmt.Sprintf("Encrypted column %s.%s", tableName, columnName),
			Library:   "Oracle",
			State:     "AT_REST",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// --- Config file parsing (fallback when CLI tools unavailable) ---

// pgSSLSettingRegex matches PostgreSQL config file settings.
var pgSSLSettingRegex = regexp.MustCompile(`^\s*(ssl|ssl_ciphers|ssl_min_protocol_version|ssl_max_protocol_version|password_encryption)\s*=\s*'?([^'#\n]+?)'?\s*(?:#.*)?$`)

// parsePostgresConfigFile extracts crypto settings from postgresql.conf content.
func (m *DatabaseModule) parsePostgresConfigFile(content, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := pgSSLSettingRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		value := strings.TrimSpace(matches[2])

		var algo, function string
		switch name {
		case "ssl":
			if value == "on" {
				algo = "TLS"
				function = "Database SSL enabled (config file)"
			} else {
				continue
			}
		case "ssl_ciphers":
			algo = value
			function = "SSL cipher suite (config file)"
		case "ssl_min_protocol_version":
			algo = normalizeTLSVersion(value)
			function = "Minimum TLS protocol version (config file)"
		case "ssl_max_protocol_version":
			algo = normalizeTLSVersion(value)
			function = "Maximum TLS protocol version (config file)"
		case "password_encryption":
			algo = normalizePasswordAlgo(value)
			function = "Password hashing algorithm (config file)"
		default:
			continue
		}

		if algo == "" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  function,
			Algorithm: algo,
			Purpose:   fmt.Sprintf("PostgreSQL config: %s = %s", name, value),
			Library:   "PostgreSQL",
			State:     cryptoState(name),
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// mysqlSSLSettingRegex matches MySQL config file settings.
var mysqlSSLSettingRegex = regexp.MustCompile(`^\s*(ssl-ca|ssl-cert|ssl-key|require_secure_transport|tls_version|innodb_encrypt_tables|default_table_encryption|ssl_cipher)\s*=\s*(.+?)\s*$`)

// parseMySQLConfigFile extracts crypto settings from my.cnf content.
func (m *DatabaseModule) parseMySQLConfigFile(content, endpoint string) []*model.Finding {
	var findings []*model.Finding

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}

		matches := mysqlSSLSettingRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		value := strings.TrimSpace(matches[2])

		var algo, function string
		switch name {
		case "tls_version":
			algo = value
			function = "Supported TLS versions (config file)"
		case "ssl_cipher":
			algo = value
			function = "SSL cipher (config file)"
		case "innodb_encrypt_tables":
			if strings.ToUpper(value) == "ON" {
				algo = "AES"
				function = "InnoDB table encryption (config file)"
			}
		case "default_table_encryption":
			if strings.ToUpper(value) == "ON" {
				algo = "AES"
				function = "Default table encryption (config file)"
			}
		case "require_secure_transport":
			if strings.ToUpper(value) == "ON" {
				algo = "TLS"
				function = "Secure transport required (config file)"
			}
		case "ssl-ca", "ssl-cert", "ssl-key":
			algo = "TLS"
			function = fmt.Sprintf("SSL %s configured (config file)", strings.TrimPrefix(name, "ssl-"))
		default:
			continue
		}

		if algo == "" {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  function,
			Algorithm: algo,
			Purpose:   fmt.Sprintf("MySQL config: %s = %s", name, value),
			Library:   "MySQL",
			State:     mysqlCryptoState(name),
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
			Category: 7,
			Source: model.FindingSource{
				Type:            "database",
				Endpoint:        endpoint,
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      "database",
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// --- Helper functions ---

// emitFinding sends a finding to the channel, respecting context cancellation.
func emitFinding(ctx context.Context, findings chan<- *model.Finding, f *model.Finding) {
	select {
	case findings <- f:
	case <-ctx.Done():
	}
}

// normalizeTLSVersion normalizes TLS version strings to canonical form.
func normalizeTLSVersion(value string) string {
	lower := strings.ToLower(value)
	switch lower {
	case "tlsv1", "tls1.0", "tlsv1.0":
		return "TLSv1.0"
	case "tlsv1.1", "tls1.1":
		return "TLSv1.1"
	case "tlsv1.2", "tls1.2":
		return "TLSv1.2"
	case "tlsv1.3", "tls1.3":
		return "TLSv1.3"
	default:
		return value
	}
}

// normalizePasswordAlgo normalizes database password hashing algorithm names.
func normalizePasswordAlgo(value string) string {
	switch strings.ToLower(value) {
	case "scram-sha-256":
		return "SCRAM-SHA-256"
	case "md5":
		return "MD5"
	case "password", "plain", "plaintext":
		return "PLAINTEXT"
	default:
		return strings.ToUpper(value)
	}
}

// normalizeMySQLAlgo normalizes MySQL variable values to algorithm names.
func normalizeMySQLAlgo(varName, value string) string {
	switch varName {
	case "have_ssl":
		if strings.ToUpper(value) == "YES" {
			return "TLS"
		}
		return ""
	case "ssl_cipher":
		return value
	case "tls_version":
		// Return the value as-is; it might be "TLSv1.2,TLSv1.3"
		return value
	case "innodb_encrypt_tables", "default_table_encryption":
		if strings.ToUpper(value) == "ON" {
			return "AES"
		}
		return ""
	default:
		return value
	}
}

// normalizeSQLServerAlgo normalizes SQL Server algorithm names.
func normalizeSQLServerAlgo(algo string) string {
	switch strings.ToUpper(algo) {
	case "AES":
		return "AES"
	case "TRIPLE_DES", "3DES", "TRIPLEDES":
		return "3DES"
	case "RSA":
		return "RSA"
	default:
		return algo
	}
}

// parseOracleAlgo extracts algorithm and key size from Oracle encryption names.
func parseOracleAlgo(encAlgo string) (string, int) {
	matches := oracleAlgoRegex.FindStringSubmatch(encAlgo)
	if matches == nil {
		return encAlgo, 0
	}

	algo := matches[1]

	var keySize int
	if matches[2] != "" {
		keySize, _ = strconv.Atoi(matches[2])
	}

	return algo, keySize
}

// cryptoState determines the crypto state based on the setting name.
func cryptoState(settingName string) string {
	if strings.HasPrefix(settingName, "ssl") || strings.Contains(settingName, "tls") {
		return "IN_TRANSIT"
	}
	if strings.Contains(settingName, "encrypt") || strings.Contains(settingName, "tde") || settingName == "password_encryption" {
		return "AT_REST"
	}
	return "IN_USE"
}

// mysqlCryptoState determines state for MySQL config settings.
func mysqlCryptoState(name string) string {
	switch {
	case strings.HasPrefix(name, "ssl") || strings.HasPrefix(name, "tls") || name == "require_secure_transport":
		return "IN_TRANSIT"
	case strings.Contains(name, "encrypt"):
		return "AT_REST"
	default:
		return "IN_USE"
	}
}
