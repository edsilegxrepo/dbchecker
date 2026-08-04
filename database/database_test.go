package database_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/database"
)

func TestFactorySupportedDrivers(t *testing.T) {
	drivers := []string{"mysql", "postgres", "oracle", "sqlserver", "sqlite", "mongodb"}
	for _, driver := range drivers {
		db, err := database.New(driver)
		if err != nil {
			t.Errorf("Failed to instantiate driver %q: %v", driver, err)
		}
		if db == nil {
			t.Errorf("Driver %q returned nil instance", driver)
		}

		// Ensure Close on uninitialized driver is nil-safe
		if err := db.Close(); err != nil {
			t.Errorf("Driver %q Close on uninitialized instance returned error: %v", driver, err)
		}
	}
}

func TestFactoryUnsupportedDriver(t *testing.T) {
	_, err := database.New("invalid_driver")
	if err == nil {
		t.Errorf("Expected error for unsupported driver, got nil")
	}
}

func TestIsSupportedFunction(t *testing.T) {
	if !database.IsSupported("mysql") {
		t.Errorf("Expected mysql to be supported")
	}
	if !database.IsSupported("postgres") {
		t.Errorf("Expected postgres to be supported")
	}
	if database.IsSupported("non_existent_driver_abc") {
		t.Errorf("Expected non_existent_driver_abc to be unsupported")
	}
}

func TestNilSafetyOnUninitializedDrivers(t *testing.T) {
	ctx := context.Background()
	drivers := []string{"mysql", "postgres", "oracle", "sqlserver", "sqlite", "mongodb"}

	for _, driver := range drivers {
		db, err := database.New(driver)
		if err != nil {
			t.Fatalf("Failed to create driver %s: %v", driver, err)
		}

		if err := db.Ping(ctx); err == nil {
			t.Errorf("Expected Ping error on uninitialized driver %s, got nil", driver)
		}

		if err := db.HealthCheck(ctx, "SELECT 1"); err == nil {
			t.Errorf("Expected HealthCheck error on uninitialized driver %s, got nil", driver)
		}
	}
}

func TestSQLiteDriverLifecycle(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.sqlite")

	sqliteDB, err := database.New("sqlite")
	if err != nil {
		t.Fatalf("Failed to instantiate sqlite driver: %v", err)
	}

	cfg := config.DatabaseConfig{
		Type: "sqlite",
		Name: dbPath,
	}

	// 1. Connect
	if err := sqliteDB.Connect(ctx, cfg, ""); err != nil {
		t.Fatalf("SQLite Connect failed: %v", err)
	}
	defer func() {
		if closeErr := sqliteDB.Close(); closeErr != nil {
			t.Errorf("sqliteDB.Close failed: %v", closeErr)
		}
	}()

	// 2. Ping
	if err := sqliteDB.Ping(ctx); err != nil {
		t.Fatalf("SQLite Ping failed: %v", err)
	}

	// 3. HealthCheck valid query
	if err := sqliteDB.HealthCheck(ctx, "SELECT 1;"); err != nil {
		t.Fatalf("SQLite HealthCheck failed: %v", err)
	}

	// 4. HealthCheck invalid query syntax
	if err := sqliteDB.HealthCheck(ctx, "SELECT * FROM non_existent_table_xyz_123;"); err == nil {
		t.Errorf("Expected error for invalid table query, got nil")
	}
}

func TestDriverConnectValidDSNs(t *testing.T) {
	ctx := context.Background()
	drivers := []string{"mysql", "postgres", "oracle", "sqlserver", "mongodb"}

	for _, drvName := range drivers {
		db, err := database.New(drvName)
		if err != nil {
			t.Fatalf("Failed to create driver %s: %v", drvName, err)
		}

		cfg := config.DatabaseConfig{
			Type:    drvName,
			Host:    "127.0.0.1",
			Port:    12345,
			User:    "testuser",
			Name:    "testdb",
			TLSMode: "disable",
		}

		// Connect returns nil (or mock connection handle) without performing immediate network dial
		_ = db.Connect(ctx, cfg, "testpass")
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Driver %s Close failed: %v", drvName, closeErr)
		}
	}
}

func TestDriverConnectVariousTLSModes(t *testing.T) {
	ctx := context.Background()
	modes := []string{"disable", "require", "verify-ca", "verify-full"}

	for _, mode := range modes {
		// Test Postgres
		pg, _ := database.New("postgres")
		cfgPG := config.DatabaseConfig{
			Type:    "postgres",
			Host:    "127.0.0.1",
			Port:    5432,
			User:    "pguser",
			Name:    "pgdb",
			TLSMode: mode,
		}
		_ = pg.Connect(ctx, cfgPG, "pass")
		if closeErr := pg.Close(); closeErr != nil {
			t.Errorf("Postgres Close failed: %v", closeErr)
		}

		// Test MySQL
		my, _ := database.New("mysql")
		cfgMY := config.DatabaseConfig{
			Type:    "mysql",
			Host:    "127.0.0.1",
			Port:    3306,
			User:    "myuser",
			Name:    "mydb",
			TLSMode: mode,
		}
		_ = my.Connect(ctx, cfgMY, "pass")
		if closeErr := my.Close(); closeErr != nil {
			t.Errorf("MySQL Close failed: %v", closeErr)
		}

		// Test SQL Server
		ss, _ := database.New("sqlserver")
		cfgSS := config.DatabaseConfig{
			Type:    "sqlserver",
			Host:    "127.0.0.1",
			Port:    1433,
			User:    "ssuser",
			Name:    "ssdb",
			TLSMode: mode,
		}
		_ = ss.Connect(ctx, cfgSS, "pass")
		if closeErr := ss.Close(); closeErr != nil {
			t.Errorf("SQLServer Close failed: %v", closeErr)
		}
	}
}

func TestDriverConnectInvalidTLSModes(t *testing.T) {
	ctx := context.Background()
	drivers := []string{"postgres", "oracle", "sqlserver", "mysql"}

	for _, drvName := range drivers {
		db, _ := database.New(drvName)
		cfg := config.DatabaseConfig{
			Type:    drvName,
			Host:    "127.0.0.1",
			Port:    12345,
			User:    "user",
			Name:    "db",
			TLSMode: "invalid_mode_xyz",
		}
		err := db.Connect(ctx, cfg, "pass")
		if err == nil {
			t.Errorf("Expected error for invalid TLS mode %q on driver %s, got nil", cfg.TLSMode, drvName)
		}
	}
}

func TestOracleDriverWalletValidation(t *testing.T) {
	ctx := context.Background()

	// Oracle verify-ca without wallet_path should return error
	ora1, _ := database.New("oracle")
	cfg := config.DatabaseConfig{
		Type:       "oracle",
		Host:       "127.0.0.1",
		Port:       1521,
		User:       "orauser",
		Name:       "oradb",
		TLSMode:    "verify-ca",
		WalletPath: "",
	}
	err := ora1.Connect(ctx, cfg, "pass")
	if err == nil {
		t.Errorf("Expected error for Oracle verify-ca without WalletPath, got nil")
	}

	// Oracle verify-full without wallet_path should return error
	ora2, _ := database.New("oracle")
	cfg.TLSMode = "verify-full"
	err = ora2.Connect(ctx, cfg, "pass")
	if err == nil {
		t.Errorf("Expected error for Oracle verify-full without WalletPath, got nil")
	}

	// Oracle require mode (no wallet needed)
	ora3, _ := database.New("oracle")
	cfgRequire := config.DatabaseConfig{
		Type:    "oracle",
		Host:    "127.0.0.1",
		Port:    1521,
		User:    "orauser",
		Name:    "oradb",
		TLSMode: "require",
	}
	// Connect should succeed (DSN built, no network dial yet)
	_ = ora3.Connect(ctx, cfgRequire, "pass")
	_ = ora3.Close()

	// Oracle verify-ca WITH wallet_path should succeed (DSN built)
	ora4, _ := database.New("oracle")
	cfgWithWallet := config.DatabaseConfig{
		Type:       "oracle",
		Host:       "127.0.0.1",
		Port:       1521,
		User:       "orauser",
		Name:       "oradb",
		TLSMode:    "verify-ca",
		WalletPath: t.TempDir(),
	}
	_ = ora4.Connect(ctx, cfgWithWallet, "pass")
	_ = ora4.Close()
}

func TestScopedFileReadErrors(t *testing.T) {
	ctx := context.Background()
	my, _ := database.New("mysql")

	// Invalid root_cert_path file for MySQL (calls buildTLSConfig -> readScopedFile)
	cfg := config.DatabaseConfig{
		Type:         "mysql",
		Host:         "127.0.0.1",
		Port:         3306,
		User:         "myuser",
		Name:         "mydb",
		TLSMode:      "verify-ca",
		RootCertPath: "/non_existent_path_xyz/ca.crt",
	}
	err := my.Connect(ctx, cfg, "pass")
	if err == nil {
		t.Errorf("Expected error for non-existent root cert path, got nil")
	}
}

func TestRegisterDriverNilPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when registering nil factory, got nil")
		}
	}()

	database.RegisterDriver("nil_driver", nil)
}

func TestMongoDBConnectTLSModes(t *testing.T) {
	ctx := context.Background()

	// MongoDB with TLS disabled
	mongo1, _ := database.New("mongodb")
	cfg := config.DatabaseConfig{
		Type:    "mongodb",
		Host:    "127.0.0.1",
		Port:    27017,
		User:    "mongouser",
		Name:    "testdb",
		TLSMode: "disable",
	}
	// Connect initializes client but doesn't dial yet (lazy connection)
	_ = mongo1.Connect(ctx, cfg, "pass")
	_ = mongo1.Close()

	// MongoDB without auth (empty user)
	mongo2, _ := database.New("mongodb")
	cfgNoAuth := config.DatabaseConfig{
		Type:    "mongodb",
		Host:    "127.0.0.1",
		Port:    27017,
		User:    "",
		Name:    "testdb",
		TLSMode: "disable",
	}
	_ = mongo2.Connect(ctx, cfgNoAuth, "")
	_ = mongo2.Close()

	// MongoDB with require TLS mode
	mongo3, _ := database.New("mongodb")
	cfgTLS := config.DatabaseConfig{
		Type:    "mongodb",
		Host:    "127.0.0.1",
		Port:    27017,
		User:    "user",
		Name:    "testdb",
		TLSMode: "require",
	}
	_ = mongo3.Connect(ctx, cfgTLS, "pass")
	_ = mongo3.Close()

	// MongoDB with verify-ca (no certs, will use buildTLSConfig)
	mongo4, _ := database.New("mongodb")
	cfgVerifyCA := config.DatabaseConfig{
		Type:    "mongodb",
		Host:    "127.0.0.1",
		Port:    27017,
		User:    "user",
		Name:    "testdb",
		TLSMode: "verify-ca",
	}
	_ = mongo4.Connect(ctx, cfgVerifyCA, "pass")
	_ = mongo4.Close()

	// MongoDB invalid TLS mode
	mongo5, _ := database.New("mongodb")
	cfgInvalid := config.DatabaseConfig{
		Type:    "mongodb",
		Host:    "127.0.0.1",
		Port:    27017,
		User:    "user",
		Name:    "testdb",
		TLSMode: "invalid_tls_mode",
	}
	err := mongo5.Connect(ctx, cfgInvalid, "pass")
	if err == nil {
		t.Errorf("Expected error for invalid MongoDB TLS mode, got nil")
	}
}

func TestBuildTLSConfigModes(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Test verify-full mode with ServerName
	my, _ := database.New("mysql")
	cfgVerifyFull := config.DatabaseConfig{
		Type:    "mysql",
		Host:    "db.example.com",
		Port:    3306,
		User:    "user",
		Name:    "testdb",
		TLSMode: "verify-full",
	}
	// This will fail on cert read but exercises verify-full code path
	_ = my.Connect(ctx, cfgVerifyFull, "pass")
	_ = my.Close()

	// Test mTLS incomplete (only client cert, no key) - should error
	my2, _ := database.New("mysql")
	cfgMTLSIncomplete := config.DatabaseConfig{
		Type:           "mysql",
		Host:           "127.0.0.1",
		Port:           3306,
		User:           "user",
		Name:           "testdb",
		TLSMode:        "verify-ca",
		ClientCertPath: filepath.Join(tempDir, "client.crt"),
		ClientKeyPath:  "",
	}
	err := my2.Connect(ctx, cfgMTLSIncomplete, "pass")
	if err == nil {
		t.Errorf("Expected error for incomplete mTLS (cert without key), got nil")
	}

	// Test mTLS incomplete (only client key, no cert) - should error
	my3, _ := database.New("mysql")
	cfgMTLSIncomplete2 := config.DatabaseConfig{
		Type:           "mysql",
		Host:           "127.0.0.1",
		Port:           3306,
		User:           "user",
		Name:           "testdb",
		TLSMode:        "verify-ca",
		ClientCertPath: "",
		ClientKeyPath:  filepath.Join(tempDir, "client.key"),
	}
	err = my3.Connect(ctx, cfgMTLSIncomplete2, "pass")
	if err == nil {
		t.Errorf("Expected error for incomplete mTLS (key without cert), got nil")
	}
}

func TestMySQLConnectTLSModes(t *testing.T) {
	ctx := context.Background()

	tlsModes := []string{"disable", "require", "verify-ca", "verify-full"}
	for _, mode := range tlsModes {
		my, _ := database.New("mysql")
		cfg := config.DatabaseConfig{
			Type:    "mysql",
			Host:    "127.0.0.1",
			Port:    3306,
			User:    "testuser",
			Name:    "testdb",
			TLSMode: mode,
		}
		// Connect builds DSN and opens handle (no network dial yet)
		_ = my.Connect(ctx, cfg, "testpass")
		_ = my.Close()
	}

	// MySQL with empty TLS mode (defaults to disable)
	myEmpty, _ := database.New("mysql")
	cfgEmpty := config.DatabaseConfig{
		Type:    "mysql",
		Host:    "127.0.0.1",
		Port:    3306,
		User:    "user",
		Name:    "db",
		TLSMode: "",
	}
	_ = myEmpty.Connect(ctx, cfgEmpty, "pass")
	_ = myEmpty.Close()
}

func TestPostgreSQLConnectTLSModes(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	tlsModes := []string{"disable", "require", "verify-ca", "verify-full"}
	for _, mode := range tlsModes {
		pg, _ := database.New("postgres")
		cfg := config.DatabaseConfig{
			Type:    "postgres",
			Host:    "127.0.0.1",
			Port:    5432,
			User:    "testuser",
			Name:    "testdb",
			TLSMode: mode,
		}
		_ = pg.Connect(ctx, cfg, "testpass")
		_ = pg.Close()
	}

	// PostgreSQL with empty TLS mode
	pgEmpty, _ := database.New("postgres")
	cfgEmpty := config.DatabaseConfig{
		Type:    "postgres",
		Host:    "127.0.0.1",
		Port:    5432,
		User:    "user",
		Name:    "db",
		TLSMode: "",
	}
	_ = pgEmpty.Connect(ctx, cfgEmpty, "pass")
	_ = pgEmpty.Close()

	// PostgreSQL with root cert path
	pg2, _ := database.New("postgres")
	cfgWithCert := config.DatabaseConfig{
		Type:         "postgres",
		Host:         "127.0.0.1",
		Port:         5432,
		User:         "user",
		Name:         "db",
		TLSMode:      "verify-ca",
		RootCertPath: filepath.Join(tempDir, "ca.crt"),
	}
	_ = pg2.Connect(ctx, cfgWithCert, "pass")
	_ = pg2.Close()

	// PostgreSQL with client cert and key paths (mTLS DSN params)
	pg3, _ := database.New("postgres")
	cfgMTLS := config.DatabaseConfig{
		Type:           "postgres",
		Host:           "127.0.0.1",
		Port:           5432,
		User:           "user",
		Name:           "db",
		TLSMode:        "verify-full",
		RootCertPath:   filepath.Join(tempDir, "ca.crt"),
		ClientCertPath: filepath.Join(tempDir, "client.crt"),
		ClientKeyPath:  filepath.Join(tempDir, "client.key"),
	}
	_ = pg3.Connect(ctx, cfgMTLS, "pass")
	_ = pg3.Close()

	// PostgreSQL invalid TLS mode
	pg4, _ := database.New("postgres")
	cfgInvalid := config.DatabaseConfig{
		Type:    "postgres",
		Host:    "127.0.0.1",
		Port:    5432,
		User:    "user",
		Name:    "db",
		TLSMode: "invalid_mode",
	}
	err := pg4.Connect(ctx, cfgInvalid, "pass")
	if err == nil {
		t.Errorf("Expected error for invalid PostgreSQL TLS mode, got nil")
	}
}

func TestSQLiteConnectModes(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// SQLite with file path
	sqlite1, _ := database.New("sqlite")
	cfg := config.DatabaseConfig{
		Type: "sqlite",
		Name: filepath.Join(tempDir, "test1.db"),
	}
	if err := sqlite1.Connect(ctx, cfg, ""); err != nil {
		t.Errorf("SQLite Connect failed: %v", err)
	}
	_ = sqlite1.Close()

	// SQLite in-memory
	sqlite2, _ := database.New("sqlite")
	cfgMemory := config.DatabaseConfig{
		Type: "sqlite",
		Name: ":memory:",
	}
	if err := sqlite2.Connect(ctx, cfgMemory, ""); err != nil {
		t.Errorf("SQLite in-memory Connect failed: %v", err)
	}
	// Verify in-memory works with ping and healthcheck
	if err := sqlite2.Ping(ctx); err != nil {
		t.Errorf("SQLite in-memory Ping failed: %v", err)
	}
	if err := sqlite2.HealthCheck(ctx, "SELECT 1"); err != nil {
		t.Errorf("SQLite in-memory HealthCheck failed: %v", err)
	}
	_ = sqlite2.Close()

	// SQLite with empty health query (exercises default behavior)
	sqlite3, _ := database.New("sqlite")
	cfgNoQuery := config.DatabaseConfig{
		Type: "sqlite",
		Name: filepath.Join(tempDir, "test2.db"),
	}
	if err := sqlite3.Connect(ctx, cfgNoQuery, ""); err != nil {
		t.Errorf("SQLite Connect failed: %v", err)
	}
	// Empty health query should be handled gracefully
	if err := sqlite3.HealthCheck(ctx, ""); err != nil {
		t.Errorf("SQLite HealthCheck with empty query failed: %v", err)
	}
	_ = sqlite3.Close()
}

func TestSQLServerConnectTLSModes(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	tlsModes := []string{"disable", "require", "verify-ca", "verify-full"}
	for _, mode := range tlsModes {
		ss, _ := database.New("sqlserver")
		cfg := config.DatabaseConfig{
			Type:    "sqlserver",
			Host:    "127.0.0.1",
			Port:    1433,
			User:    "sa",
			Name:    "master",
			TLSMode: mode,
		}
		_ = ss.Connect(ctx, cfg, "testpass")
		_ = ss.Close()
	}

	// SQL Server with certificate path
	ss2, _ := database.New("sqlserver")
	cfgWithCert := config.DatabaseConfig{
		Type:         "sqlserver",
		Host:         "127.0.0.1",
		Port:         1433,
		User:         "sa",
		Name:         "master",
		TLSMode:      "verify-ca",
		RootCertPath: filepath.Join(tempDir, "ca.crt"),
	}
	_ = ss2.Connect(ctx, cfgWithCert, "pass")
	_ = ss2.Close()

	// SQL Server with empty TLS mode
	ss3, _ := database.New("sqlserver")
	cfgEmpty := config.DatabaseConfig{
		Type:    "sqlserver",
		Host:    "127.0.0.1",
		Port:    1433,
		User:    "sa",
		Name:    "master",
		TLSMode: "",
	}
	_ = ss3.Connect(ctx, cfgEmpty, "pass")
	_ = ss3.Close()

	// SQL Server invalid TLS mode
	ss4, _ := database.New("sqlserver")
	cfgInvalid := config.DatabaseConfig{
		Type:    "sqlserver",
		Host:    "127.0.0.1",
		Port:    1433,
		User:    "sa",
		Name:    "master",
		TLSMode: "invalid_mode",
	}
	err := ss4.Connect(ctx, cfgInvalid, "pass")
	if err == nil {
		t.Errorf("Expected error for invalid SQL Server TLS mode, got nil")
	}
}
