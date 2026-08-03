//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/database"
	"github.com/edsilegxrepo/dbchecker/pkg/dbchecker"
)

// TestLiveEndToEndCLI verifies the entire live application stack end-to-end:
// 1. Live Key generation via secretprotector
// 2. Live Encryption via CLI (-encrypt)
// 3. Live YAML config loading with os.OpenRoot scoping
// 4. Live database connection, Ping, and HealthCheck execution against SQLite
func TestLiveEndToEndCLI(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "live_config.yaml")
	dbPath := filepath.Join(tempDir, "live_db.sqlite")

	// 1. Generate live 64-char hex key and configure in DB_SECRET_KEY environment variable
	hexKey, err := libsecsecrets.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate live master key: %v", err)
	}
	t.Setenv("DB_SECRET_KEY", hexKey)

	// 2. Run live encryption via CLI flag (-encrypt)
	var encryptStdout, encryptStderr bytes.Buffer
	plainPassword := "MyLiveSecureDBPassword2026!"
	exitCode := dbchecker.RunAppCLI([]string{"-encrypt", plainPassword}, &encryptStdout, &encryptStderr)
	if exitCode != 0 {
		t.Fatalf("Live encryption CLI failed with exit code %d. Stderr: %s", exitCode, encryptStderr.String())
	}

	encryptedPassword := strings.TrimSpace(encryptStdout.String())
	if encryptedPassword == "" || encryptedPassword == plainPassword {
		t.Fatalf("Expected valid Base64 encrypted string, got: %q", encryptedPassword)
	}

	// 3. Create live YAML config referencing live encrypted password and SQLite database file
	yamlContent := `
databases:
  live_sqlite_check:
    type: sqlite
    name: ` + filepath.ToSlash(dbPath) + `
    password: ` + encryptedPassword + `
    health_query: "SELECT 42;"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("Failed to write live YAML config: %v", err)
	}

	// 4. Execute live dbchecker scan using -config and -db
	var scanStdout, scanStderr bytes.Buffer
	exitCode = dbchecker.RunAppCLI([]string{"-config", configPath, "-db", "live_sqlite_check"}, &scanStdout, &scanStderr)
	if exitCode != 0 {
		t.Fatalf("Live scan CLI failed with exit code %d. Stderr: %s", exitCode, scanStderr.String())
	}

	scanOutput := scanStdout.String()
	if !strings.Contains(scanOutput, "Successfully connected and checked live_sqlite_check") {
		t.Errorf("Expected success confirmation in output, got: %s", scanOutput)
	}

	// 5. Verify live SQLite database file was created and executed query successfully
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("Expected live SQLite database file to be created at %s, got err: %v", dbPath, err)
	}
}

// TestLiveExternalDBIntegration Framework for testing remote databases when live connection env vars are provided.
// Supported environment variables:
// - LIVE_MYSQL_HOST, LIVE_MYSQL_PORT, LIVE_MYSQL_USER, LIVE_MYSQL_PASS, LIVE_MYSQL_DB
// - LIVE_POSTGRES_HOST, LIVE_POSTGRES_PORT, LIVE_POSTGRES_USER, LIVE_POSTGRES_PASS, LIVE_POSTGRES_DB
// - LIVE_MONGO_HOST, LIVE_MONGO_PORT, LIVE_MONGO_USER, LIVE_MONGO_PASS, LIVE_MONGO_DB
func TestLiveExternalDBIntegration(t *testing.T) {
	ctx := context.Background()

	// Live MySQL check if environment is configured
	if host := os.Getenv("LIVE_MYSQL_HOST"); host != "" {
		t.Run("Live_MySQL", func(t *testing.T) {
			db, err := database.New("mysql")
			if err != nil {
				t.Fatalf("Failed to create mysql driver: %v", err)
			}
			cfg := config.DatabaseConfig{
				Type:        "mysql",
				Host:        host,
				Port:        3306,
				User:        os.Getenv("LIVE_MYSQL_USER"),
				Name:        os.Getenv("LIVE_MYSQL_DB"),
				HealthQuery: "SELECT 1;",
			}
			if err := db.Connect(ctx, cfg, os.Getenv("LIVE_MYSQL_PASS")); err != nil {
				t.Fatalf("Live MySQL Connect failed: %v", err)
			}
			defer func() {
				if closeErr := db.Close(); closeErr != nil {
					t.Errorf("Live MySQL Close failed: %v", closeErr)
				}
			}()

			if err := db.Ping(ctx); err != nil {
				t.Errorf("Live MySQL Ping failed: %v", err)
			}
			if err := db.HealthCheck(ctx, cfg.HealthQuery); err != nil {
				t.Errorf("Live MySQL HealthCheck failed: %v", err)
			}
		})
	}

	// Live PostgreSQL check if environment is configured
	if host := os.Getenv("LIVE_POSTGRES_HOST"); host != "" {
		t.Run("Live_PostgreSQL", func(t *testing.T) {
			db, err := database.New("postgres")
			if err != nil {
				t.Fatalf("Failed to create postgres driver: %v", err)
			}
			cfg := config.DatabaseConfig{
				Type:        "postgres",
				Host:        host,
				Port:        5432,
				User:        os.Getenv("LIVE_POSTGRES_USER"),
				Name:        os.Getenv("LIVE_POSTGRES_DB"),
				HealthQuery: "SELECT 1;",
			}
			if err := db.Connect(ctx, cfg, os.Getenv("LIVE_POSTGRES_PASS")); err != nil {
				t.Fatalf("Live Postgres Connect failed: %v", err)
			}
			defer func() {
				if closeErr := db.Close(); closeErr != nil {
					t.Errorf("Live Postgres Close failed: %v", closeErr)
				}
			}()

			if err := db.Ping(ctx); err != nil {
				t.Errorf("Live Postgres Ping failed: %v", err)
			}
			if err := db.HealthCheck(ctx, cfg.HealthQuery); err != nil {
				t.Errorf("Live Postgres HealthCheck failed: %v", err)
			}
		})
	}

	// Live MongoDB check if environment is configured
	if host := os.Getenv("LIVE_MONGO_HOST"); host != "" {
		t.Run("Live_MongoDB", func(t *testing.T) {
			db, err := database.New("mongodb")
			if err != nil {
				t.Fatalf("Failed to create mongodb driver: %v", err)
			}
			cfg := config.DatabaseConfig{
				Type: "mongodb",
				Host: host,
				Port: 27017,
				User: os.Getenv("LIVE_MONGO_USER"),
				Name: os.Getenv("LIVE_MONGO_DB"),
			}
			if err := db.Connect(ctx, cfg, os.Getenv("LIVE_MONGO_PASS")); err != nil {
				t.Fatalf("Live MongoDB Connect failed: %v", err)
			}
			defer func() {
				if closeErr := db.Close(); closeErr != nil {
					t.Errorf("Live MongoDB Close failed: %v", closeErr)
				}
			}()

			if err := db.Ping(ctx); err != nil {
				t.Errorf("Live MongoDB Ping failed: %v", err)
			}
			if err := db.HealthCheck(ctx, ""); err != nil {
				t.Errorf("Live MongoDB HealthCheck failed: %v", err)
			}
		})
	}
}
