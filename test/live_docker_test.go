//go:build integration
// +build integration

/*
Integration tests for live Docker database containers.

Test Strategy:
  - Spins up 5 database engines (Postgres, MySQL, MongoDB, MSSQL, Oracle) via testutil.StartLiveDatabaseCluster()
  - Each engine tested in parallel subtest for connect/ping/healthcheck
  - Full CLI batch scan validates end-to-end encrypted credential flow
  - Negative tests verify authentication rejection with wrong passwords

Requirements:
  - Docker daemon available (test skipped if not)
  - ~3 minutes for all containers to reach ready state (Oracle slowest)
  - Build tag "integration" required: go test -tags integration ./test/...
*/
package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/dbchecker/database"
	"github.com/edsilegxrepo/dbchecker/pkg/dbchecker"
	"github.com/edsilegxrepo/dbchecker/testutil"
)

// TestLiveDockerContainers exercises all database drivers against real containers.
func TestLiveDockerContainers(t *testing.T) {
	cluster := testutil.StartLiveDatabaseCluster(t, "dbchecker-test")
	ctx := context.Background()

	t.Run("PostgreSQL_Container", func(t *testing.T) {
		t.Parallel()
		db, err := database.New("postgres")
		if err != nil {
			t.Fatalf("Failed to create postgres driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("Postgres Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, cluster.PgCfg, "secretpass"); err != nil {
			t.Fatalf("Postgres connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("Postgres ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, cluster.PgCfg.HealthQuery); err != nil {
			t.Errorf("Postgres health check failed: %v", err)
		}
	})

	t.Run("MySQL_Container", func(t *testing.T) {
		t.Parallel()
		db, err := database.New("mysql")
		if err != nil {
			t.Fatalf("Failed to create mysql driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MySQL Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, cluster.MysqlCfg, "secretpass"); err != nil {
			t.Fatalf("MySQL connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MySQL ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, cluster.MysqlCfg.HealthQuery); err != nil {
			t.Errorf("MySQL health check failed: %v", err)
		}
	})

	t.Run("MongoDB_Container", func(t *testing.T) {
		t.Parallel()
		db, err := database.New("mongodb")
		if err != nil {
			t.Fatalf("Failed to create mongodb driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MongoDB Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, cluster.MongoCfg, "secretpass"); err != nil {
			t.Fatalf("MongoDB connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MongoDB ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, cluster.MongoCfg.HealthQuery); err != nil {
			t.Errorf("MongoDB health check failed: %v", err)
		}
	})

	t.Run("MSSQL_Container", func(t *testing.T) {
		t.Parallel()
		db, err := database.New("sqlserver")
		if err != nil {
			t.Fatalf("Failed to create sqlserver driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MSSQL Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, cluster.MssqlCfg, "SecretPass2026!"); err != nil {
			t.Fatalf("MSSQL connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MSSQL ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, cluster.MssqlCfg.HealthQuery); err != nil {
			t.Errorf("MSSQL health check failed: %v", err)
		}
	})

	t.Run("Oracle_Container", func(t *testing.T) {
		t.Parallel()
		db, err := database.New("oracle")
		if err != nil {
			t.Fatalf("Failed to create oracle driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("Oracle Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, cluster.OracleCfg, "SecretPass2026!"); err != nil {
			t.Fatalf("Oracle connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("Oracle ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, cluster.OracleCfg.HealthQuery); err != nil {
			t.Errorf("Oracle health check failed: %v", err)
		}
	})

	t.Run("Full_CLI_Batch_Scan", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "docker_live_config.yaml")

		t.Setenv("DB_SECRET_KEY", cluster.MasterKeyHex)

		var encOut, encErr bytes.Buffer
		exitCode := dbchecker.RunAppCLI([]string{"-encrypt", "secretpass"}, &encOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI encryption failed: %s", encErr.String())
		}
		encPass := strings.TrimSpace(encOut.String())

		var encMsOut bytes.Buffer
		exitCode = dbchecker.RunAppCLI([]string{"-encrypt", "SecretPass2026!"}, &encMsOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI ms encryption failed: %s", encErr.String())
		}
		encMsPass := strings.TrimSpace(encMsOut.String())

		yamlData := fmt.Sprintf(`
databases:
  live_postgres:
    type: postgres
    host: %s
    port: %d
    user: testuser
    name: testdb
    password: %s
    health_query: "SELECT 1;"
  live_mysql:
    type: mysql
    host: %s
    port: %d
    user: root
    name: testdb
    password: %s
    health_query: "SELECT 1;"
  live_mongo:
    type: mongodb
    host: %s
    port: %d
    user: testuser
    name: testdb
    password: %s
    health_query: '{"dbStats": 1}'
  live_mssql:
    type: sqlserver
    host: %s
    port: %d
    user: sa
    name: master
    password: %s
    tls_mode: disable
    health_query: "SELECT 1;"
  live_oracle:
    type: oracle
    host: %s
    port: %d
    user: system
    name: XEPDB1
    password: %s
    health_query: "SELECT 1 FROM DUAL"
`, cluster.DockerHost, cluster.PgPort, encPass, cluster.DockerHost, cluster.MysqlPort, encPass, cluster.DockerHost, cluster.MongoPort, encPass, cluster.DockerHost, cluster.MssqlPort, encMsPass, cluster.DockerHost, cluster.OraclePort, encMsPass)

		if err := os.WriteFile(configPath, []byte(yamlData), 0o600); err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		var scanOut, scanErr bytes.Buffer
		exitCode = dbchecker.RunAppCLI([]string{"-config", configPath, "-json"}, &scanOut, &scanErr)
		if exitCode != 0 {
			t.Fatalf("CLI scan failed with exit code %d. Stderr: %s", exitCode, scanErr.String())
		}

		outStr := scanOut.String()
		for _, dbName := range []string{"live_postgres", "live_mysql", "live_mongo", "live_mssql", "live_oracle"} {
			if !strings.Contains(outStr, dbName) {
				t.Errorf("Expected CLI scan output to contain %s, got: %s", dbName, outStr)
			}
		}
	})

	t.Run("Negative_Auth_Rejection", func(t *testing.T) {
		t.Parallel()
		wrongPass := "WrongPassword123!"

		pgDriver, _ := database.New("postgres")
		if err := pgDriver.Connect(ctx, cluster.PgCfg, wrongPass); err == nil {
			if pingErr := pgDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Postgres ping to fail with wrong password, but it succeeded")
			}
			_ = pgDriver.Close()
		}

		mysqlDriver, _ := database.New("mysql")
		if err := mysqlDriver.Connect(ctx, cluster.MysqlCfg, wrongPass); err == nil {
			if pingErr := mysqlDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected MySQL ping to fail with wrong password, but it succeeded")
			}
			_ = mysqlDriver.Close()
		}

		mongoDriver, _ := database.New("mongodb")
		if err := mongoDriver.Connect(ctx, cluster.MongoCfg, wrongPass); err == nil {
			if pingErr := mongoDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Mongo ping to fail with wrong password, but it succeeded")
			}
			_ = mongoDriver.Close()
		}

		mssqlDriver, _ := database.New("sqlserver")
		if err := mssqlDriver.Connect(ctx, cluster.MssqlCfg, wrongPass); err == nil {
			if pingErr := mssqlDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected MSSQL ping to fail with wrong password, but it succeeded")
			}
			_ = mssqlDriver.Close()
		}

		oracleDriver, _ := database.New("oracle")
		if err := oracleDriver.Connect(ctx, cluster.OracleCfg, wrongPass); err == nil {
			if pingErr := oracleDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Oracle ping to fail with wrong password, but it succeeded")
			}
			_ = oracleDriver.Close()
		}
	})
}
