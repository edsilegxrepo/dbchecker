package main

import (
	"bytes"
	"context"
	"criticalsys/secretprotector/pkg/libsecsecrets"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"criticalsys.net/dbchecker/config"
	"criticalsys.net/dbchecker/database"
)

// getDockerPrefix returns ["wsl", "env", "PATH=...", "docker"] on Windows and ["docker"] on Linux/other OS.
func getDockerPrefix() []string {
	if runtime.GOOS == "windows" {
		return []string{"wsl", "env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "docker"}
	}
	return []string{"docker"}
}

// isDockerAvailable verifies if Docker engine is running and responsive.
func isDockerAvailable() bool {
	prefix := getDockerPrefix()
	args := append(prefix[1:], "info")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, prefix[0], args...)
	return cmd.Run() == nil
}

// runEphemeralContainer starts a container and registers a t.Cleanup callback for automatic force removal.
func runEphemeralContainer(t *testing.T, image string, containerPort int, envVars []string) (hostPort int) {
	t.Helper()
	prefix := getDockerPrefix()
	cleanImage := strings.NewReplacer("/", "-", ":", "-", ".", "-").Replace(image)
	containerName := fmt.Sprintf("dbchecker-test-%s-%d-%d", cleanImage, time.Now().UnixNano(), time.Now().Nanosecond())

	// Force-remove any container with this name prior to starting
	_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()

	args := append(prefix[1:], "run", "-d", "--name", containerName, "-p", fmt.Sprintf("0:%d", containerPort))
	for _, env := range envVars {
		args = append(args, "-e", env)
	}
	args = append(args, image)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run docker container %s (%s): %v. Output: %s", containerName, image, err, string(out))
	}

	// Register unconditional force-cleanup for both container AND image upon test completion
	t.Cleanup(func() {
		rmArgs := append(prefix[1:], "rm", "-f", containerName)
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		_ = exec.CommandContext(cleanCtx, prefix[0], rmArgs...).Run()

		if os.Getenv("PRESERVE_DOCKER_IMAGES") != "1" {
			rmiArgs := append(prefix[1:], "rmi", "-f", image)
			rmiCtx, rmiCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer rmiCancel()
			_ = exec.CommandContext(rmiCtx, prefix[0], rmiArgs...).Run()
		}
	})

	// Inspect mapped dynamic host port
	portArgs := append(prefix[1:], "port", containerName, fmt.Sprintf("%d/tcp", containerPort))
	portCtx, portCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer portCancel()

	portCmd := exec.CommandContext(portCtx, prefix[0], portArgs...)
	portOut, err := portCmd.CombinedOutput()
	if err != nil {
		// Fallback: try port without /tcp suffix
		portArgs = append(prefix[1:], "port", containerName, fmt.Sprintf("%d", containerPort))
		portCmd = exec.CommandContext(portCtx, prefix[0], portArgs...)
		portOut, err = portCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to inspect mapped port for %s: %v. Output: %s", containerName, err, string(portOut))
		}
	}

	// Output format is e.g. "0.0.0.0:49153\n" or "127.0.0.1:49153\n"
	rawPortStr := strings.TrimSpace(string(portOut))
	idx := strings.LastIndex(rawPortStr, ":")
	if idx == -1 || idx == len(rawPortStr)-1 {
		t.Fatalf("Unexpected docker port output string for %s: %q", containerName, rawPortStr)
	}

	portNum, err := strconv.Atoi(rawPortStr[idx+1:])
	if err != nil {
		t.Fatalf("Failed to parse host port from %q: %v", rawPortStr, err)
	}

	return portNum
}

// waitForDatabase retries connecting and pinging the database engine until it is ready or times out.
func waitForDatabase(ctx context.Context, driverType string, cfg config.DatabaseConfig, password string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		db, err := database.New(driverType)
		if err == nil {
			connCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			if err := db.Connect(connCtx, cfg, password); err == nil {
				if pingErr := db.Ping(connCtx); pingErr == nil {
					_ = db.Close()
					cancel()
					return nil
				} else {
					lastErr = pingErr
				}
				_ = db.Close()
			} else {
				lastErr = err
			}
			cancel()
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("database %s at %s:%d did not become ready within %v: %v", driverType, cfg.Host, cfg.Port, timeout, lastErr)
}

// pruneDbcheckerContainers force removes any leftover running or stopped test containers from previous interrupted runs.
func pruneDbcheckerContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmdStr := "docker rm -f $(docker ps -a -q --filter name=dbchecker) 2>/dev/null || true"
	if runtime.GOOS == "windows" {
		_ = exec.CommandContext(ctx, "wsl", "bash", "-c", cmdStr).Run()
	} else {
		_ = exec.CommandContext(ctx, "bash", "-c", cmdStr).Run()
	}
}

// TestLiveDockerContainers spins up ephemeral Postgres, MySQL, MongoDB, MSSQL, and Oracle containers
// (via WSL on Windows or native Docker on Linux) and tests end-to-end connections.
func TestLiveDockerContainers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live container tests in -short mode.")
	}
	if !isDockerAvailable() {
		t.Skip("Skipping live container integration tests: Docker daemon is not available or WSL docker is not running.")
	}

	pruneDbcheckerContainers()
	ctx := context.Background()

	var (
		pgPort, mysqlPort, mongoPort, mssqlPort, oraclePort int
		wgLaunch                                            sync.WaitGroup
	)

	wgLaunch.Add(5)
	t.Log("Launching all 5 database engine containers concurrently in parallel goroutines...")

	go func() {
		defer wgLaunch.Done()
		pgPort = runEphemeralContainer(t, "postgres:18-alpine", 5432, []string{
			"POSTGRES_USER=testuser",
			"POSTGRES_PASSWORD=secretpass",
			"POSTGRES_DB=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		mysqlPort = runEphemeralContainer(t, "mysql:8.4", 3306, []string{
			"MYSQL_ROOT_PASSWORD=secretpass",
			"MYSQL_DATABASE=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		mongoPort = runEphemeralContainer(t, "mongo:8.0", 27017, []string{
			"MONGO_INITDB_ROOT_USERNAME=testuser",
			"MONGO_INITDB_ROOT_PASSWORD=secretpass",
			"MONGO_INITDB_DATABASE=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		mssqlPort = runEphemeralContainer(t, "mcr.microsoft.com/azure-sql-edge", 1433, []string{
			"ACCEPT_EULA=Y",
			"MSSQL_SA_PASSWORD=SecretPass2026!",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		oraclePort = runEphemeralContainer(t, "gvenzl/oracle-xe:21-slim", 1521, []string{
			"ORACLE_PASSWORD=SecretPass2026!",
		})
	}()

	wgLaunch.Wait()

	pgCfg := config.DatabaseConfig{
		Type:        "postgres",
		Host:        "127.0.0.1",
		Port:        pgPort,
		User:        "testuser",
		Name:        "testdb",
		HealthQuery: "SELECT 1;",
	}

	mysqlCfg := config.DatabaseConfig{
		Type:        "mysql",
		Host:        "127.0.0.1",
		Port:        mysqlPort,
		User:        "root",
		Name:        "testdb",
		HealthQuery: "SELECT 1;",
	}

	mongoCfg := config.DatabaseConfig{
		Type:        "mongodb",
		Host:        "127.0.0.1",
		Port:        mongoPort,
		User:        "testuser",
		Name:        "testdb",
		HealthQuery: `{"dbStats": 1}`,
	}

	mssqlCfg := config.DatabaseConfig{
		Type:        "sqlserver",
		Host:        "127.0.0.1",
		Port:        mssqlPort,
		User:        "sa",
		Name:        "master",
		TLSMode:     "disable",
		HealthQuery: "SELECT 1;",
	}

	oracleCfg := config.DatabaseConfig{
		Type:        "oracle",
		Host:        "127.0.0.1",
		Port:        oraclePort,
		User:        "system",
		Name:        "XEPDB1",
		HealthQuery: "SELECT 1 FROM DUAL",
	}

	// Wait for all 5 database containers to report ready status concurrently in parallel
	t.Log("Waiting for all 5 database containers to report ready status concurrently...")
	var wg sync.WaitGroup
	bootErrs := make(chan error, 5)

	checkReady := func(name, driverType string, cfg config.DatabaseConfig, pass string, timeout time.Duration) {
		defer wg.Done()
		if err := waitForDatabase(ctx, driverType, cfg, pass, timeout); err != nil {
			bootErrs <- fmt.Errorf("%s boot failure: %w", name, err)
		}
	}

	wg.Add(5)
	go checkReady("PostgreSQL", "postgres", pgCfg, "secretpass", 30*time.Second)
	go checkReady("MySQL", "mysql", mysqlCfg, "secretpass", 45*time.Second)
	go checkReady("MongoDB", "mongodb", mongoCfg, "secretpass", 30*time.Second)
	go checkReady("MSSQL", "sqlserver", mssqlCfg, "SecretPass2026!", 45*time.Second)
	go checkReady("Oracle 21c", "oracle", oracleCfg, "SecretPass2026!", 90*time.Second)

	wg.Wait()
	close(bootErrs)

	for err := range bootErrs {
		t.Fatalf("Container ready check failed: %v", err)
	}

	// 6. Test low-level DB driver interfaces (Connect, Ping, HealthCheck)
	t.Run("PostgreSQL_Container", func(t *testing.T) {
		db, err := database.New("postgres")
		if err != nil {
			t.Fatalf("Failed to create postgres driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("Postgres Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, pgCfg, "secretpass"); err != nil {
			t.Fatalf("Postgres connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("Postgres ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, pgCfg.HealthQuery); err != nil {
			t.Errorf("Postgres health check failed: %v", err)
		}
	})

	t.Run("MySQL_Container", func(t *testing.T) {
		db, err := database.New("mysql")
		if err != nil {
			t.Fatalf("Failed to create mysql driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MySQL Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, mysqlCfg, "secretpass"); err != nil {
			t.Fatalf("MySQL connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MySQL ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, mysqlCfg.HealthQuery); err != nil {
			t.Errorf("MySQL health check failed: %v", err)
		}
	})

	t.Run("MongoDB_Container", func(t *testing.T) {
		db, err := database.New("mongodb")
		if err != nil {
			t.Fatalf("Failed to create mongodb driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MongoDB Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, mongoCfg, "secretpass"); err != nil {
			t.Fatalf("MongoDB connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MongoDB ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, mongoCfg.HealthQuery); err != nil {
			t.Errorf("MongoDB health check failed: %v", err)
		}
	})

	t.Run("MSSQL_Container", func(t *testing.T) {
		db, err := database.New("sqlserver")
		if err != nil {
			t.Fatalf("Failed to create sqlserver driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MSSQL Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, mssqlCfg, "SecretPass2026!"); err != nil {
			t.Fatalf("MSSQL connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MSSQL ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, mssqlCfg.HealthQuery); err != nil {
			t.Errorf("MSSQL health check failed: %v", err)
		}
	})

	t.Run("Oracle_Container", func(t *testing.T) {
		db, err := database.New("oracle")
		if err != nil {
			t.Fatalf("Failed to create oracle driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("Oracle Close failed: %v", closeErr)
			}
		}()
		if err := db.Connect(ctx, oracleCfg, "SecretPass2026!"); err != nil {
			t.Fatalf("Oracle connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("Oracle ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, oracleCfg.HealthQuery); err != nil {
			t.Errorf("Oracle health check failed: %v", err)
		}
	})

	// 7. Test Full End-to-End CLI Scan against all 5 live containers
	t.Run("Full_CLI_Batch_Scan", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "docker_live_config.yaml")

		masterKey, err := libsecsecrets.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}
		t.Setenv("DB_SECRET_KEY", masterKey)

		// Encrypt password via CLI
		var encOut, encErr bytes.Buffer
		exitCode := runApp([]string{"-encrypt", "secretpass"}, &encOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI encryption failed: %s", encErr.String())
		}
		encPass := strings.TrimSpace(encOut.String())

		var encMsOut bytes.Buffer
		exitCode = runApp([]string{"-encrypt", "SecretPass2026!"}, &encMsOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI ms encryption failed: %s", encErr.String())
		}
		encMsPass := strings.TrimSpace(encMsOut.String())

		yamlData := fmt.Sprintf(`
databases:
  live_postgres:
    type: postgres
    host: 127.0.0.1
    port: %d
    user: testuser
    name: testdb
    password: %s
    health_query: "SELECT 1;"
  live_mysql:
    type: mysql
    host: 127.0.0.1
    port: %d
    user: root
    name: testdb
    password: %s
    health_query: "SELECT 1;"
  live_mongo:
    type: mongodb
    host: 127.0.0.1
    port: %d
    user: testuser
    name: testdb
    password: %s
    health_query: '{"dbStats": 1}'
  live_mssql:
    type: sqlserver
    host: 127.0.0.1
    port: %d
    user: sa
    name: master
    password: %s
    tls_mode: disable
    health_query: "SELECT 1;"
  live_oracle:
    type: oracle
    host: 127.0.0.1
    port: %d
    user: system
    name: XEPDB1
    password: %s
    health_query: "SELECT 1 FROM DUAL"
`, pgPort, encPass, mysqlPort, encPass, mongoPort, encPass, mssqlPort, encMsPass, oraclePort, encMsPass)

		if err := os.WriteFile(configPath, []byte(yamlData), 0o600); err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		var scanOut, scanErr bytes.Buffer
		exitCode = runApp([]string{"-config", configPath, "-json"}, &scanOut, &scanErr)
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

	// 8. Test Negative Error Path (Auth Rejection on Live Containers)
	t.Run("Negative_Auth_Rejection", func(t *testing.T) {
		wrongPass := "WrongPassword123!"

		// PostgreSQL wrong password rejection
		pgDriver, _ := database.New("postgres")
		if err := pgDriver.Connect(ctx, pgCfg, wrongPass); err == nil {
			if pingErr := pgDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Postgres ping to fail with wrong password, but it succeeded")
			}
			_ = pgDriver.Close()
		}

		// MySQL wrong password rejection
		mysqlDriver, _ := database.New("mysql")
		if err := mysqlDriver.Connect(ctx, mysqlCfg, wrongPass); err == nil {
			if pingErr := mysqlDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected MySQL ping to fail with wrong password, but it succeeded")
			}
			_ = mysqlDriver.Close()
		}

		// MongoDB wrong password rejection
		mongoDriver, _ := database.New("mongodb")
		if err := mongoDriver.Connect(ctx, mongoCfg, wrongPass); err == nil {
			if pingErr := mongoDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Mongo ping to fail with wrong password, but it succeeded")
			}
			_ = mongoDriver.Close()
		}

		// MSSQL wrong password rejection
		mssqlDriver, _ := database.New("sqlserver")
		if err := mssqlDriver.Connect(ctx, mssqlCfg, wrongPass); err == nil {
			if pingErr := mssqlDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected MSSQL ping to fail with wrong password, but it succeeded")
			}
			_ = mssqlDriver.Close()
		}

		// Oracle wrong password rejection
		oracleDriver, _ := database.New("oracle")
		if err := oracleDriver.Connect(ctx, oracleCfg, wrongPass); err == nil {
			if pingErr := oracleDriver.Ping(ctx); pingErr == nil {
				t.Errorf("Expected Oracle ping to fail with wrong password, but it succeeded")
			}
			_ = oracleDriver.Close()
		}
	})
}

// unused import check helper
var _ = net.IPv4
