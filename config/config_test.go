package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dbchecker/config"
)

func TestLoadConfigAndValidation(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.yaml")

	yamlData := `
databases:
  test_db:
    type: mysql
    host: localhost
    port: 3306
    user: root
    password: encrypted_secret
    name: testdb
    tls_mode: verify-ca
`

	if err := os.WriteFile(configPath, []byte(yamlData), 0o600); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := config.LoadConfig(configPath, func(t string) bool { return t == "mysql" })
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Databases) != 1 {
		t.Fatalf("Expected 1 database config, got %d", len(cfg.Databases))
	}

	dbCfg, ok := cfg.Databases["test_db"]
	if !ok {
		t.Fatalf("Database 'test_db' not found in loaded config")
	}

	if dbCfg.Type != "mysql" || dbCfg.Host != "localhost" || dbCfg.Port != 3306 {
		t.Errorf("Unexpected database config fields: %+v", dbCfg)
	}
}

func TestInvalidConfigValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Unsupported DB type
	configPath1 := filepath.Join(tempDir, "invalid_type.yaml")
	yamlData1 := `
databases:
  bad_db:
    type: unsupported_db_engine
`
	_ = os.WriteFile(configPath1, []byte(yamlData1), 0o600)
	_, err := config.LoadConfig(configPath1, func(t string) bool { return t == "mysql" })
	if err == nil {
		t.Errorf("Expected validation error for unsupported DB engine")
	}

	// Unsupported TLS mode
	configPath2 := filepath.Join(tempDir, "invalid_tls.yaml")
	yamlData2 := `
databases:
  bad_db:
    type: mysql
    tls_mode: invalid_tls_mode
`
	_ = os.WriteFile(configPath2, []byte(yamlData2), 0o600)
	_, err = config.LoadConfig(configPath2, func(t string) bool { return t == "mysql" })
	if err == nil {
		t.Errorf("Expected validation error for unsupported TLS mode")
	}
}

func TestLoadConfigErrors(t *testing.T) {
	// Non-existent file
	_, err := config.LoadConfig("non_existent_file.yaml", func(t string) bool { return true })
	if err == nil {
		t.Errorf("Expected error loading non-existent file")
	}

	// Malformed YAML content
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "malformed.yaml")
	_ = os.WriteFile(configPath, []byte("invalid: yaml: [:::"), 0o600)
	_, err = config.LoadConfig(configPath, func(t string) bool { return true })
	if err == nil {
		t.Errorf("Expected error unmarshaling malformed YAML")
	}
}
