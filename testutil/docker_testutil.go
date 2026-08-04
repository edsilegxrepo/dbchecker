/*
Package testutil provides Docker container lifecycle management for integration tests.

Core Functions:
  - GetDockerHost(): Returns container-accessible IP (handles WSL2 networking on Windows)
  - RunEphemeralContainer(): Starts a container with dynamic port mapping, auto-cleanup
  - WaitForDatabase(): Polls until database accepts connections or timeout
  - StartLiveDatabaseCluster(): Orchestrates 5-engine cluster (Postgres, MySQL, Mongo, MSSQL, Oracle)

WSL2 Considerations:
  - Containers bind to WSL's IP, not localhost (requires GetDockerHost())
  - Network latency requires extended timeouts (30s for commands, 30-45s for DB ready)
  - Docker commands prefixed with "wsl" on Windows

Security:
  - Fresh AES-256 key generated per test run via libsecsecrets.GenerateKey()
  - Passwords encrypted before storage in test configs
*/
package testutil

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/database"
	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// lastAllocatedPort tracks port allocation to avoid conflicts across concurrent tests.
var lastAllocatedPort atomic.Int32

func init() {
	lastAllocatedPort.Store(35000)
}

// GetFreePorts allocates 'count' thread-safe, monotonically increasing free local TCP ports.
func GetFreePorts(count int) ([]int, error) {
	ports := make([]int, 0, count)
	for len(ports) < count {
		candidate := int(lastAllocatedPort.Add(1))
		if candidate > 60000 {
			lastAllocatedPort.Store(35000)
			candidate = 35001
		}

		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", candidate))
		if err == nil {
			_ = ln.Close()
			ports = append(ports, candidate)
		}
	}
	return ports, nil
}

// GetDockerPrefix returns ["wsl", "docker"] on Windows and ["docker"] on Linux/macOS.
func GetDockerPrefix() []string {
	if runtime.GOOS == "windows" {
		return []string{"wsl", "docker"}
	}
	return []string{"docker"}
}

// GetDockerHost returns the IP address where Docker containers are accessible.
// On Windows with WSL2, containers bind to WSL's network, so we need the WSL IP.
// On Linux or Docker Desktop with host networking, 127.0.0.1 works.
func GetDockerHost() string {
	if runtime.GOOS != "windows" {
		return "127.0.0.1"
	}

	// On Windows, get WSL IP address
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// #nosec G204 -- Test helper gets WSL IP for Docker connectivity
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, "wsl", "hostname", "-I")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to localhost if WSL command fails
		return "127.0.0.1"
	}

	// hostname -I returns space-separated IPs, first one is the main interface
	ips := strings.Fields(strings.TrimSpace(string(out)))
	if len(ips) > 0 {
		return ips[0]
	}

	return "127.0.0.1"
}

// IsDockerAvailable verifies if Docker engine is running and responsive.
func IsDockerAvailable() bool {
	prefix := GetDockerPrefix()
	args := append(prefix[1:], "info")

	// WSL networking can be slow on Windows, allow up to 30 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// #nosec G204 -- Test helper checks docker availability via system CLI
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, prefix[0], args...)
	return cmd.Run() == nil
}

// PruneContainers force removes any leftover running or stopped test containers matching the name filter.
func PruneContainers(nameFilter string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmdStr := fmt.Sprintf("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; docker ps -a -q --filter name=%s | xargs -r docker rm -f 2>/dev/null || true", nameFilter)
	if runtime.GOOS == "windows" {
		// #nosec G204 -- Test helper executes container cleanup via wsl bash
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		_ = exec.CommandContext(ctx, "wsl", "bash", "-c", cmdStr).Run()
	} else {
		// #nosec G204 -- Test helper executes container cleanup via bash
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		_ = exec.CommandContext(ctx, "bash", "-c", cmdStr).Run()
	}
}

// RunEphemeralContainer starts a live Docker DB container with dynamic host port mapping.
func RunEphemeralContainer(t *testing.T, image string, containerPort int, envVars []string) (hostPort int) {
	t.Helper()
	prefix := GetDockerPrefix()
	cleanImage := strings.NewReplacer("/", "-", ":", "-", ".", "-").Replace(image)
	containerName := fmt.Sprintf("dbchecker-test-%s-%d", cleanImage, time.Now().UnixNano())

	// #nosec G204 -- Test helper removes existing container by name before startup
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()

	args := append(prefix[1:], "run", "-d", "--name", containerName, "-p", fmt.Sprintf("0:%d", containerPort))
	for _, env := range envVars {
		args = append(args, "-e", env)
	}
	args = append(args, image)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// #nosec G204 -- Test helper launches test container with controlled parameters
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run docker container %s (%s): %v. Output: %s", containerName, image, err, string(out))
	}

	t.Cleanup(func() {
		rmArgs := append(prefix[1:], "rm", "-f", containerName)
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		// #nosec G204 -- Test helper cleanup callback removes container on test completion
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		_ = exec.CommandContext(cleanCtx, prefix[0], rmArgs...).Run()
	})

	portArgs := append(prefix[1:], "port", containerName, fmt.Sprintf("%d/tcp", containerPort))
	// WSL networking can be slow, allow 30 seconds
	portCtx, portCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer portCancel()

	// #nosec G204 -- Test helper queries docker port for container host mapping
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	portCmd := exec.CommandContext(portCtx, prefix[0], portArgs...)
	portOut, err := portCmd.CombinedOutput()
	if err != nil {
		portArgs = append(prefix[1:], "port", containerName, fmt.Sprintf("%d", containerPort))
		// #nosec G204 -- Test helper fallback attempt to query docker port for container host mapping
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		portCmd = exec.CommandContext(portCtx, prefix[0], portArgs...)
		portOut, err = portCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to inspect mapped port for %s: %v. Output: %s", containerName, err, string(portOut))
		}
	}

	rawPortStr := strings.TrimSpace(string(portOut))
	idx := strings.LastIndex(rawPortStr, ":")
	if idx == -1 || idx == len(rawPortStr)-1 {
		t.Fatalf("Unexpected docker port output for %s: %q", containerName, rawPortStr)
	}

	portNum, err := strconv.Atoi(rawPortStr[idx+1:])
	if err != nil {
		t.Fatalf("Failed to parse host port from %q: %v", rawPortStr, err)
	}

	return portNum
}

// WaitForDatabase retries connecting and pinging the database engine until it is ready or times out.
func WaitForDatabase(ctx context.Context, driverType string, cfg config.DatabaseConfig, password string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		db, err := database.New(driverType)
		if err == nil {
			// WSL networking can take 10+ seconds on Windows
			connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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

// LiveCluster encapsulates all 5 database containers, their connection configs,
// and encrypted credentials. Used by integration tests to run full-stack checks.
type LiveCluster struct {
	DockerHost          string
	MasterKeyHex        string
	KeyBytes            []byte
	EncryptedSecretPass string
	EncryptedMsPass     string

	PgPort     int
	MysqlPort  int
	MongoPort  int
	MssqlPort  int
	OraclePort int

	PgCfg     config.DatabaseConfig
	MysqlCfg  config.DatabaseConfig
	MongoCfg  config.DatabaseConfig
	MssqlCfg  config.DatabaseConfig
	OracleCfg config.DatabaseConfig

	PgDSN     string
	MysqlDSN  string
	MongoDSN  string
	MssqlDSN  string
	OracleDSN string
}

// StartLiveDatabaseCluster spins up all 5 database engine containers concurrently and waits for readiness.
func StartLiveDatabaseCluster(t *testing.T, filterPrefix string) *LiveCluster {
	t.Helper()
	if !IsDockerAvailable() {
		t.Skip("Skipping live container test: Docker engine is unavailable.")
	}

	PruneContainers(filterPrefix)

	// Generate a fresh cryptographic key for each test run
	masterKeyHex, err := libsecsecrets.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	cluster := &LiveCluster{
		DockerHost:   GetDockerHost(),
		MasterKeyHex: masterKeyHex,
	}

	keyBytes, err := hex.DecodeString(cluster.MasterKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode master key hex: %v", err)
	}
	cluster.KeyBytes = keyBytes

	_ = os.Setenv("DB_SECRET_KEY", cluster.MasterKeyHex)

	encSecretPass, err := libsecsecrets.Encrypt(context.Background(), "secretpass", keyBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt secretpass: %v", err)
	}
	cluster.EncryptedSecretPass = encSecretPass

	encMsPass, err := libsecsecrets.Encrypt(context.Background(), "SecretPass2026!", keyBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt SecretPass2026!: %v", err)
	}
	cluster.EncryptedMsPass = encMsPass

	var wgLaunch sync.WaitGroup
	wgLaunch.Add(5)

	go func() {
		defer wgLaunch.Done()
		cluster.PgPort = RunEphemeralContainer(t, "postgres:18-alpine", 5432, []string{
			"POSTGRES_USER=testuser",
			"POSTGRES_PASSWORD=secretpass",
			"POSTGRES_DB=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		cluster.MysqlPort = RunEphemeralContainer(t, "mysql:8.4", 3306, []string{
			"MYSQL_ROOT_PASSWORD=secretpass",
			"MYSQL_DATABASE=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		cluster.MongoPort = RunEphemeralContainer(t, "mongo:8.0", 27017, []string{
			"MONGO_INITDB_ROOT_USERNAME=testuser",
			"MONGO_INITDB_ROOT_PASSWORD=secretpass",
			"MONGO_INITDB_DATABASE=testdb",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		cluster.MssqlPort = RunEphemeralContainer(t, "mcr.microsoft.com/azure-sql-edge", 1433, []string{
			"ACCEPT_EULA=Y",
			"MSSQL_SA_PASSWORD=SecretPass2026!",
		})
	}()

	go func() {
		defer wgLaunch.Done()
		cluster.OraclePort = RunEphemeralContainer(t, "gvenzl/oracle-xe:21-slim", 1521, []string{
			"ORACLE_PASSWORD=SecretPass2026!",
		})
	}()

	wgLaunch.Wait()

	cluster.PgCfg = config.DatabaseConfig{
		Type:        "postgres",
		Host:        cluster.DockerHost,
		Port:        cluster.PgPort,
		User:        "testuser",
		Name:        "testdb",
		HealthQuery: "SELECT 1;",
	}

	cluster.MysqlCfg = config.DatabaseConfig{
		Type:        "mysql",
		Host:        cluster.DockerHost,
		Port:        cluster.MysqlPort,
		User:        "root",
		Name:        "testdb",
		HealthQuery: "SELECT 1;",
	}

	cluster.MongoCfg = config.DatabaseConfig{
		Type:        "mongodb",
		Host:        cluster.DockerHost,
		Port:        cluster.MongoPort,
		User:        "testuser",
		Name:        "testdb",
		HealthQuery: `{"dbStats": 1}`,
	}

	cluster.MssqlCfg = config.DatabaseConfig{
		Type:        "sqlserver",
		Host:        cluster.DockerHost,
		Port:        cluster.MssqlPort,
		User:        "sa",
		Name:        "master",
		TLSMode:     "disable",
		HealthQuery: "SELECT 1;",
	}

	cluster.OracleCfg = config.DatabaseConfig{
		Type:        "oracle",
		Host:        cluster.DockerHost,
		Port:        cluster.OraclePort,
		User:        "system",
		Name:        "XEPDB1",
		HealthQuery: "SELECT 1 FROM DUAL",
	}

	cluster.PgDSN = fmt.Sprintf("postgres://testuser:%s@%s:%d/testdb?sslmode=disable", url.PathEscape(encSecretPass), cluster.DockerHost, cluster.PgPort)
	cluster.MysqlDSN = fmt.Sprintf("root:%s@tcp(%s:%d)/testdb", url.PathEscape(encSecretPass), cluster.DockerHost, cluster.MysqlPort)
	cluster.MongoDSN = fmt.Sprintf("mongodb://testuser:%s@%s:%d/testdb?authSource=admin", url.PathEscape(encSecretPass), cluster.DockerHost, cluster.MongoPort)
	cluster.MssqlDSN = fmt.Sprintf("sqlserver://sa:%s@%s:%d?database=master&encrypt=disable", url.PathEscape(encMsPass), cluster.DockerHost, cluster.MssqlPort)
	cluster.OracleDSN = fmt.Sprintf("oracle://system:%s@%s:%d/XEPDB1", url.PathEscape(encMsPass), cluster.DockerHost, cluster.OraclePort)

	t.Log("Waiting for all 5 database containers to report ready status concurrently...")
	var wgReady sync.WaitGroup
	bootErrs := make(chan error, 5)

	checkReady := func(name, driverType string, cfg config.DatabaseConfig, pass string, timeout time.Duration) {
		defer wgReady.Done()
		if err := WaitForDatabase(context.Background(), driverType, cfg, pass, timeout); err != nil {
			bootErrs <- fmt.Errorf("%s boot failure: %w", name, err)
		}
	}

	wgReady.Add(5)
	go checkReady("PostgreSQL", "postgres", cluster.PgCfg, "secretpass", 30*time.Second)
	go checkReady("MySQL", "mysql", cluster.MysqlCfg, "secretpass", 45*time.Second)
	go checkReady("MongoDB", "mongodb", cluster.MongoCfg, "secretpass", 30*time.Second)
	go checkReady("MSSQL", "sqlserver", cluster.MssqlCfg, "SecretPass2026!", 45*time.Second)
	go checkReady("Oracle 21c", "oracle", cluster.OracleCfg, "SecretPass2026!", 180*time.Second)

	wgReady.Wait()
	close(bootErrs)

	for err := range bootErrs {
		t.Fatalf("Container ready check failed: %v", err)
	}

	return cluster
}
