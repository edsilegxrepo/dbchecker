package dbchecker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"criticalsys.net/dbchecker/config"
	"criticalsys.net/dbchecker/crypto"
	"criticalsys.net/dbchecker/database"
	"criticalsys.net/dbchecker/pkg/dbchecker"
)

type MockLibDB struct {
	connectErr     error
	pingErr        error
	healthCheckErr error
}

func (m *MockLibDB) Connect(ctx context.Context, cfg config.DatabaseConfig, password string) error {
	return m.connectErr
}

func (m *MockLibDB) Ping(ctx context.Context) error {
	return m.pingErr
}

func (m *MockLibDB) HealthCheck(ctx context.Context, query string) error {
	return m.healthCheckErr
}

func (m *MockLibDB) Close() error {
	return nil
}

func init() {
	database.RegisterDriver("mock_lib_ok", func() database.DB { return &MockLibDB{} })
	database.RegisterDriver("mock_lib_fail_conn", func() database.DB { return &MockLibDB{connectErr: errors.New("conn error")} })
	database.RegisterDriver("mock_lib_fail_ping", func() database.DB { return &MockLibDB{pingErr: errors.New("ping error")} })
	database.RegisterDriver("mock_lib_fail_health", func() database.DB { return &MockLibDB{healthCheckErr: errors.New("health error")} })
}

func TestLibraryCheck(t *testing.T) {
	ctx := context.Background()
	secretKey := []byte("12345678901234567890123456789012")
	encryptedPass, _ := crypto.Encrypt(ctx, "secret", secretKey)

	// Test Success with HealthQuery
	cfgOK := config.DatabaseConfig{Type: "mock_lib_ok", Password: encryptedPass, HealthQuery: "SELECT 1"}
	resOK := dbchecker.Check(ctx, "ok_db", cfgOK, secretKey, 2*time.Second)
	if !resOK.Success || resOK.FailedStep != dbchecker.StepNone {
		t.Errorf("Expected Check success, got result: %+v", resOK)
	}

	// Test Success with zero timeout (defaults to 10s)
	resZeroTimeout := dbchecker.Check(ctx, "ok_db_zero_timeout", cfgOK, secretKey, 0)
	if !resZeroTimeout.Success {
		t.Errorf("Expected Check success with zero timeout, got result: %+v", resZeroTimeout)
	}

	// Test Decryption Failure
	cfgBadPass := config.DatabaseConfig{Type: "mock_lib_ok", Password: "bad_password"}
	resBadPass := dbchecker.Check(ctx, "bad_pass_db", cfgBadPass, secretKey, 2*time.Second)
	if resBadPass.Success || resBadPass.FailedStep != dbchecker.StepDecryption {
		t.Errorf("Expected StepDecryption failure, got: %+v", resBadPass)
	}

	// Test Driver Init Failure
	cfgBadDriver := config.DatabaseConfig{Type: "unknown_driver_type", Password: encryptedPass}
	resBadDriver := dbchecker.Check(ctx, "bad_driver_db", cfgBadDriver, secretKey, 2*time.Second)
	if resBadDriver.Success || resBadDriver.FailedStep != dbchecker.StepDriverInit {
		t.Errorf("Expected StepDriverInit failure, got: %+v", resBadDriver)
	}

	// Test Connect Failure
	cfgFailConn := config.DatabaseConfig{Type: "mock_lib_fail_conn", Password: encryptedPass}
	resFailConn := dbchecker.Check(ctx, "fail_conn_db", cfgFailConn, secretKey, 2*time.Second)
	if resFailConn.Success || resFailConn.FailedStep != dbchecker.StepConnect {
		t.Errorf("Expected StepConnect failure, got: %+v", resFailConn)
	}

	// Test Ping Failure
	cfgFailPing := config.DatabaseConfig{Type: "mock_lib_fail_ping", Password: encryptedPass}
	resFailPing := dbchecker.Check(ctx, "fail_ping_db", cfgFailPing, secretKey, 2*time.Second)
	if resFailPing.Success || resFailPing.FailedStep != dbchecker.StepPing {
		t.Errorf("Expected StepPing failure, got: %+v", resFailPing)
	}

	// Test HealthCheck Failure
	cfgFailHealth := config.DatabaseConfig{Type: "mock_lib_fail_health", Password: encryptedPass, HealthQuery: "SELECT 1"}
	resFailHealth := dbchecker.Check(ctx, "fail_health_db", cfgFailHealth, secretKey, 2*time.Second)
	if resFailHealth.Success || resFailHealth.FailedStep != dbchecker.StepHealthCheck {
		t.Errorf("Expected StepHealthCheck failure, got: %+v", resFailHealth)
	}
}

func TestLibraryCheckAll(t *testing.T) {
	ctx := context.Background()
	secretKey := []byte("12345678901234567890123456789012")
	encryptedPass, _ := crypto.Encrypt(ctx, "secret", secretKey)

	// Test nil and empty config
	if res := dbchecker.CheckAll(ctx, nil, secretKey); res != nil {
		t.Errorf("Expected nil for nil config in CheckAll")
	}
	if res := dbchecker.CheckAll(ctx, &config.Config{}, secretKey); res != nil {
		t.Errorf("Expected nil for empty config in CheckAll")
	}

	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"db_ok1": {Type: "mock_lib_ok", Password: encryptedPass},
			"db_ok2": {Type: "mock_lib_ok", Password: encryptedPass},
			"db_err": {Type: "mock_lib_fail_ping", Password: encryptedPass},
		},
	}

	results := dbchecker.CheckAll(ctx, cfg, secretKey,
		dbchecker.WithTimeout(3*time.Second),
		dbchecker.WithConcurrency(2),
	)

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	successCount := 0
	for _, res := range results {
		if res.Success {
			successCount++
		}
	}
	if successCount != 2 {
		t.Errorf("Expected 2 successful checks, got %d", successCount)
	}
}
