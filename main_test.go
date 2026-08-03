package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/crypto"
	"github.com/edsilegxrepo/dbchecker/database"
	pkgdb "github.com/edsilegxrepo/dbchecker/pkg/dbchecker"
)

type MockTestDB struct {
	connectErr     error
	pingErr        error
	healthCheckErr error
	closeErr       error
}

func (m *MockTestDB) Connect(ctx context.Context, cfg config.DatabaseConfig, password string) error {
	return m.connectErr
}

func (m *MockTestDB) Ping(ctx context.Context) error {
	return m.pingErr
}

func (m *MockTestDB) HealthCheck(ctx context.Context, query string) error {
	return m.healthCheckErr
}

func (m *MockTestDB) Close() error {
	return m.closeErr
}

func init() {
	database.RegisterDriver("mock_test_db", func() database.DB {
		return &MockTestDB{}
	})
	database.RegisterDriver("mock_fail_connect", func() database.DB {
		return &MockTestDB{connectErr: errors.New("mock connect error")}
	})
	database.RegisterDriver("mock_fail_ping", func() database.DB {
		return &MockTestDB{pingErr: errors.New("mock ping error")}
	})
	database.RegisterDriver("mock_fail_health", func() database.DB {
		return &MockTestDB{healthCheckErr: errors.New("mock health error")}
	})
}

func TestCheckDatabaseLifecycle(t *testing.T) {
	ctx := context.Background()
	secretKey := []byte("12345678901234567890123456789012") // 32 bytes
	var stdout, stderr bytes.Buffer

	// Encrypt a mock password
	encryptedPass, err := crypto.Encrypt(ctx, "secret_password", secretKey)
	if err != nil {
		t.Fatalf("Failed to encrypt test password: %v", err)
	}

	// 1. Success case with HealthQuery
	cfgSuccess := config.DatabaseConfig{
		Type:        "mock_test_db",
		Password:    encryptedPass,
		HealthQuery: "SELECT 1",
	}

	if err := checkDatabase(ctx, cfgSuccess, "test_success", secretKey, 5*time.Second, &stdout, &stderr); err != nil {
		t.Errorf("Expected checkDatabase success, got: %v", err)
	}

	// 2. Decryption error case
	cfgBadPass := config.DatabaseConfig{
		Type:     "mock_test_db",
		Password: "not_a_base64_ciphertext",
	}
	if err := checkDatabase(ctx, cfgBadPass, "test_bad_pass", secretKey, 5*time.Second, &stdout, &stderr); err == nil {
		t.Errorf("Expected error for invalid password decryption, got nil")
	}

	// 3. Unsupported DB type case
	cfgUnsupported := config.DatabaseConfig{
		Type:     "non_existent_driver_xyz",
		Password: encryptedPass,
	}
	if err := checkDatabase(ctx, cfgUnsupported, "test_unsupported", secretKey, 5*time.Second, &stdout, &stderr); err == nil {
		t.Errorf("Expected error for unsupported DB type, got nil")
	}

	// 4. Connection failure case
	cfgFailConnect := config.DatabaseConfig{
		Type:     "mock_fail_connect",
		Password: encryptedPass,
	}
	if err := checkDatabase(ctx, cfgFailConnect, "test_fail_connect", secretKey, 5*time.Second, &stdout, &stderr); err == nil {
		t.Errorf("Expected error for Connect failure, got nil")
	}

	// 5. Ping failure case
	cfgFailPing := config.DatabaseConfig{
		Type:     "mock_fail_ping",
		Password: encryptedPass,
	}
	if err := checkDatabase(ctx, cfgFailPing, "test_fail_ping", secretKey, 5*time.Second, &stdout, &stderr); err == nil {
		t.Errorf("Expected error for Ping failure, got nil")
	}

	// 6. HealthCheck failure case
	cfgFailHealth := config.DatabaseConfig{
		Type:        "mock_fail_health",
		Password:    encryptedPass,
		HealthQuery: "SELECT 1",
	}
	if err := checkDatabase(ctx, cfgFailHealth, "test_fail_health", secretKey, 5*time.Second, &stdout, &stderr); err == nil {
		t.Errorf("Expected error for HealthCheck failure, got nil")
	}
}

func TestRunAppCLIExecution(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. Test -version flag
	code := runApp([]string{"-version"}, &stdout, &stderr)
	if code != pkgdb.ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for -version, got %d", code)
	}

	// 2. Test Key resolution failure (no env, no key file) -> ExitKeyError (2)
	t.Setenv("DB_SECRET_KEY", "")
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-config", "non_existent.yaml"}, &stdout, &stderr)
	if code != pkgdb.ExitKeyError {
		t.Errorf("Expected exit code ExitKeyError (%d) when secret key is missing, got %d", pkgdb.ExitKeyError, code)
	}

	// 3. Test -encrypt flag with valid secret key in env
	secretKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars = 32 bytes
	t.Setenv("DB_SECRET_KEY", secretKeyHex)
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-encrypt", "mypassword"}, &stdout, &stderr)
	if code != pkgdb.ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for -encrypt, got %d", code)
	}
	if stdout.Len() == 0 {
		t.Errorf("Expected encrypted password in stdout")
	}

	// 4. Test execution with YAML config file and single DB check
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "app_config.yaml")

	secretKeyBytes, err := crypto.ResolveKey(context.Background(), secretKeyHex, "", "")
	if err != nil {
		t.Fatalf("Failed to resolve test key: %v", err)
	}

	encryptedPass, _ := crypto.Encrypt(context.Background(), "pass123", secretKeyBytes)
	yamlData := `
databases:
  db1:
    type: mock_test_db
    password: ` + encryptedPass + `
  db2:
    type: mock_fail_ping
    password: ` + encryptedPass + `
`
	_ = os.WriteFile(configPath, []byte(yamlData), 0o600)

	// Test single valid DB execution (-db db1)
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-config", configPath, "-db", "db1", "-timeout", "2s"}, &stdout, &stderr)
	if code != pkgdb.ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for single valid DB check, got %d. Stderr: %s", code, stderr.String())
	}

	// Test non-existent DB ID (-db missing_db) -> ExitConfigError (1)
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-config", configPath, "-db", "missing_db"}, &stdout, &stderr)
	if code != pkgdb.ExitConfigError {
		t.Errorf("Expected exit code ExitConfigError (%d) for missing DB ID, got %d", pkgdb.ExitConfigError, code)
	}

	// Test batch mode execution with failing DB (db2 fails ping) -> ExitHealthError (5)
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-config", configPath, "-concurrency", "2"}, &stdout, &stderr)
	if code != pkgdb.ExitHealthError {
		t.Errorf("Expected exit code ExitHealthError (%d) for batch mode with failing DB, got %d", pkgdb.ExitHealthError, code)
	}

	// Test flag parsing error -> ExitConfigError (1)
	stdout.Reset()
	stderr.Reset()
	code = runApp([]string{"-invalid-flag-xyz"}, &stdout, &stderr)
	if code != pkgdb.ExitConfigError {
		t.Errorf("Expected exit code ExitConfigError (%d) for invalid CLI flags, got %d", pkgdb.ExitConfigError, code)
	}
}
