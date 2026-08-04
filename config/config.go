/*
Package config handles the loading and validation of the database checker configuration.
It supports YAML-based configuration for multiple database instances and their connection details.

Security:
  - Uses os.OpenRoot (Go 1.24+) to prevent directory traversal attacks
  - Passwords stored as encrypted Base64 ciphertext, decrypted at runtime
  - Config files should have 0600 permissions (enforced by caller)

Shared Constants:
  - SupportedTLSModes: Centralized TLS mode validation used by both config
    validation and database driver implementations (DRY principle)
*/
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DatabaseConfig defines the connection and health check parameters for a single database.
type DatabaseConfig struct {
	Type           string `yaml:"type"`
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	User           string `yaml:"user"`
	Password       string `yaml:"password"`
	Name           string `yaml:"name"`
	HealthQuery    string `yaml:"health_query"`
	TLSMode        string `yaml:"tls_mode,omitempty"`
	WalletPath     string `yaml:"wallet_path,omitempty"`
	RootCertPath   string `yaml:"root_cert_path,omitempty"`
	ClientCertPath string `yaml:"client_cert_path,omitempty"`
	ClientKeyPath  string `yaml:"client_key_path,omitempty"`
}

// Config holds the collection of database configurations indexed by a unique identifier.
type Config struct {
	Databases map[string]DatabaseConfig `yaml:"databases"`
}

// SupportedTLSModes defines valid TLS mode values for database connections.
// Single source of truth used by config.Validate() and database/tls.go.
// Modes: "" (default=disable), "disable", "require", "verify-ca", "verify-full"
var SupportedTLSModes = map[string]struct{}{"disable": {}, "require": {}, "verify-ca": {}, "verify-full": {}, "": {}}

// Validate checks the configuration for any unsupported or invalid values.
func (c *Config) Validate(isSupportedType func(string) bool) error {
	for id, dbConfig := range c.Databases {
		if isSupportedType != nil && !isSupportedType(dbConfig.Type) {
			return fmt.Errorf("database %q has unsupported type: %s", id, dbConfig.Type)
		}
		if _, ok := SupportedTLSModes[dbConfig.TLSMode]; !ok {
			return fmt.Errorf("database %q has unsupported tls_mode: %s", id, dbConfig.TLSMode)
		}
	}
	return nil
}

// LoadConfig reads a YAML configuration file from disk.
// It uses os.OpenRoot (Go 1.24+) to safely access the file and prevent directory traversal.
func LoadConfig(configFile string, isSupportedType func(string) bool) (*Config, error) {
	dir := filepath.Dir(configFile)
	if dir == "" || dir == "." {
		absPath, err := filepath.Abs(configFile)
		if err == nil {
			dir = filepath.Dir(absPath)
			configFile = absPath
		} else {
			dir = "."
		}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open config directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	data, err := root.ReadFile(filepath.Base(configFile))
	if err != nil {
		return nil, err
	}

	var config Config
	if err = yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if err = config.Validate(isSupportedType); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}
