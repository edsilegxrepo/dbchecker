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
	ora, _ := database.New("oracle")

	// Oracle verify-ca without wallet_path should return error
	cfg := config.DatabaseConfig{
		Type:       "oracle",
		Host:       "127.0.0.1",
		Port:       1521,
		User:       "orauser",
		Name:       "oradb",
		TLSMode:    "verify-ca",
		WalletPath: "",
	}
	err := ora.Connect(ctx, cfg, "pass")
	if err == nil {
		t.Errorf("Expected error for Oracle verify-ca without WalletPath, got nil")
	}
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
