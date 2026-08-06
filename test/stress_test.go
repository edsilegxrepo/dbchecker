//go:build stress
// +build stress

/*
Stress tests for dbchecker database operations.

Test Strategy:
  - SQLite stress: High concurrency Check() calls against embedded SQLite (no Docker)
  - Docker stress: Concurrent connections against all 5 database containers
  - Connection pool: Validates driver handles rapid connect/disconnect cycles

Requirements:
  - Docker daemon for full stress tests (SQLite tests run without Docker)
  - Build tag "stress" required: go test -tags stress ./test/...
*/
package test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/database"
	"github.com/edsilegxrepo/dbchecker/testutil"
)

var (
	skipWSL = flag.Bool("skip-wsl", false, "Skip WSL stress tests (Windows only)")
)

// stressConfig holds environment-specific thresholds
type stressConfig struct {
	name            string
	concurrency     int
	iterations      int
	maxErrorRate    float64
	maxP99Duration  time.Duration
}

func getStressConfig() stressConfig {
	if runtime.GOOS == "linux" {
		return stressConfig{
			name:            "Linux",
			concurrency:     100,
			iterations:      500,
			maxErrorRate:    0.01, // 1%
			maxP99Duration:  150 * time.Millisecond,
		}
	}
	return stressConfig{
		name:            "Windows",
		concurrency:     50,
		iterations:      200,
		maxErrorRate:    0.05, // 5%
		maxP99Duration:  200 * time.Millisecond,
	}
}

// TestStressSQLite tests SQLite under high concurrency (no Docker required)
func TestStressSQLite(t *testing.T) {
	cfg := getStressConfig()
	t.Logf("Running SQLite stress test with %s config (concurrency=%d, iterations=%d)",
		cfg.name, cfg.concurrency, cfg.iterations)

	dbPath := filepath.Join(t.TempDir(), "stress_test.db")
	ctx := context.Background()

	// Create initial connection to set up database
	db, err := database.New("sqlite")
	if err != nil {
		t.Fatalf("Failed to create sqlite driver: %v", err)
	}

	sqliteCfg := config.DatabaseConfig{
		Type:        "sqlite",
		Host:        dbPath,
		HealthQuery: "SELECT 1;",
	}

	if err := db.Connect(ctx, sqliteCfg, ""); err != nil {
		t.Fatalf("Failed to connect to SQLite: %v", err)
	}
	_ = db.Close()

	var (
		successCount int64
		errorCount   int64
		durations    []time.Duration
		mu           sync.Mutex
		wg           sync.WaitGroup
	)

	semaphore := make(chan struct{}, cfg.concurrency)
	startTime := time.Now()

	for i := 0; i < cfg.iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			iterStart := time.Now()

			db, err := database.New("sqlite")
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if err := db.Connect(ctx, sqliteCfg, ""); err != nil {
				atomic.AddInt64(&errorCount, 1)
				_ = db.Close()
				return
			}

			if err := db.Ping(ctx); err != nil {
				atomic.AddInt64(&errorCount, 1)
				_ = db.Close()
				return
			}

			if err := db.HealthCheck(ctx, sqliteCfg.HealthQuery); err != nil {
				atomic.AddInt64(&errorCount, 1)
				_ = db.Close()
				return
			}

			_ = db.Close()
			atomic.AddInt64(&successCount, 1)

			mu.Lock()
			durations = append(durations, time.Since(iterStart))
			mu.Unlock()
		}()
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	// Calculate P99
	if len(durations) > 0 {
		// Simple P99: sort and take 99th percentile
		sortDurations(durations)
		p99Index := int(float64(len(durations)) * 0.99)
		if p99Index >= len(durations) {
			p99Index = len(durations) - 1
		}
		p99 := durations[p99Index]

		errorRate := float64(errorCount) / float64(cfg.iterations)
		throughput := float64(successCount) / totalDuration.Seconds()

		t.Logf("SQLite Stress Results:")
		t.Logf("  Total iterations: %d", cfg.iterations)
		t.Logf("  Success:          %d (%.2f%%)", successCount, float64(successCount)/float64(cfg.iterations)*100)
		t.Logf("  Errors:           %d (%.2f%%)", errorCount, errorRate*100)
		t.Logf("  Throughput:       %.2f ops/s", throughput)
		t.Logf("  P99 latency:      %s", p99)
		t.Logf("  Total duration:   %s", totalDuration)

		if errorRate > cfg.maxErrorRate {
			t.Errorf("Error rate %.2f%% exceeds threshold %.2f%%", errorRate*100, cfg.maxErrorRate*100)
		}
		if p99 > cfg.maxP99Duration {
			t.Errorf("P99 latency %s exceeds threshold %s", p99, cfg.maxP99Duration)
		}
	}
}

// TestStressDockerContainers tests all database containers under concurrent load
func TestStressDockerContainers(t *testing.T) {
	if !testutil.IsDockerAvailable() {
		t.Skip("Docker not available")
	}

	cfg := getStressConfig()
	// Reduce iterations for Docker tests (slower)
	dockerIterations := cfg.iterations / 5
	if dockerIterations < 20 {
		dockerIterations = 20
	}

	t.Logf("Running Docker stress test with %s config (concurrency=%d, iterations=%d per DB)",
		cfg.name, cfg.concurrency/5, dockerIterations)

	cluster := testutil.StartLiveDatabaseCluster(t, "dbchecker-stress")
	ctx := context.Background()

	// SQLite config for embedded test
	sqlitePath := filepath.Join(t.TempDir(), "stress_docker.db")
	sqliteCfg := config.DatabaseConfig{
		Type:        "sqlite",
		Host:        sqlitePath,
		HealthQuery: "SELECT 1;",
	}

	databases := []struct {
		name     string
		dbType   string
		config   config.DatabaseConfig
		password string
	}{
		{"SQLite", "sqlite", sqliteCfg, ""},
		{"PostgreSQL", "postgres", cluster.PgCfg, "secretpass"},
		{"MySQL", "mysql", cluster.MysqlCfg, "secretpass"},
		{"MongoDB", "mongodb", cluster.MongoCfg, "secretpass"},
		{"MSSQL", "sqlserver", cluster.MssqlCfg, "SecretPass2026!"},
		{"Oracle", "oracle", cluster.OracleCfg, "SecretPass2026!"},
	}

	for _, dbInfo := range databases {
		dbInfo := dbInfo // capture
		t.Run(dbInfo.name+"_Stress", func(t *testing.T) {
			var (
				successCount int64
				errorCount   int64
				wg           sync.WaitGroup
			)

			concurrency := cfg.concurrency / 5 // Lower concurrency per DB
			if concurrency < 5 {
				concurrency = 5
			}
			semaphore := make(chan struct{}, concurrency)
			startTime := time.Now()

			for i := 0; i < dockerIterations; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					db, err := database.New(dbInfo.dbType)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						return
					}

					if err := db.Connect(ctx, dbInfo.config, dbInfo.password); err != nil {
						atomic.AddInt64(&errorCount, 1)
						_ = db.Close()
						return
					}

					if err := db.Ping(ctx); err != nil {
						atomic.AddInt64(&errorCount, 1)
						_ = db.Close()
						return
					}

					_ = db.Close()
					atomic.AddInt64(&successCount, 1)
				}()
			}

			wg.Wait()
			totalDuration := time.Since(startTime)

			errorRate := float64(errorCount) / float64(dockerIterations)
			throughput := float64(successCount) / totalDuration.Seconds()

			t.Logf("%s Stress Results:", dbInfo.name)
			t.Logf("  Success: %d/%d (%.2f%%)", successCount, dockerIterations,
				float64(successCount)/float64(dockerIterations)*100)
			t.Logf("  Throughput: %.2f ops/s", throughput)
			t.Logf("  Duration: %s", totalDuration)

			// More lenient threshold for Docker tests
			if errorRate > 0.10 { // 10% max error rate
				t.Errorf("Error rate %.2f%% exceeds threshold 10%%", errorRate*100)
			}
		})
	}
}

// TestStressConnectionChurn tests rapid connect/disconnect cycles
func TestStressConnectionChurn(t *testing.T) {
	cfg := getStressConfig()
	t.Logf("Running connection churn stress test with %s config", cfg.name)

	dbPath := filepath.Join(t.TempDir(), "churn_test.db")
	ctx := context.Background()

	sqliteCfg := config.DatabaseConfig{
		Type:        "sqlite",
		Host:        dbPath,
		HealthQuery: "SELECT 1;",
	}

	// Rapid connect/disconnect cycles
	iterations := cfg.iterations * 2
	var successCount int64
	var errorCount int64

	startTime := time.Now()

	for i := 0; i < iterations; i++ {
		db, err := database.New("sqlite")
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
			continue
		}

		if err := db.Connect(ctx, sqliteCfg, ""); err != nil {
			atomic.AddInt64(&errorCount, 1)
			_ = db.Close()
			continue
		}

		if err := db.Close(); err != nil {
			atomic.AddInt64(&errorCount, 1)
			continue
		}

		atomic.AddInt64(&successCount, 1)
	}

	totalDuration := time.Since(startTime)
	throughput := float64(successCount) / totalDuration.Seconds()

	t.Logf("Connection Churn Results:")
	t.Logf("  Iterations: %d", iterations)
	t.Logf("  Success:    %d (%.2f%%)", successCount, float64(successCount)/float64(iterations)*100)
	t.Logf("  Throughput: %.2f connects/s", throughput)
	t.Logf("  Duration:   %s", totalDuration)

	errorRate := float64(errorCount) / float64(iterations)
	if errorRate > cfg.maxErrorRate {
		t.Errorf("Error rate %.2f%% exceeds threshold %.2f%%", errorRate*100, cfg.maxErrorRate*100)
	}
}

// TestStressWSL runs stress tests inside WSL (Windows only)
func TestStressWSL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL tests only run on Windows")
	}
	if *skipWSL {
		t.Skip("WSL tests disabled via -skip-wsl flag")
	}

	if _, err := exec.LookPath("wsl"); err != nil {
		t.Skip("WSL not available")
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	projectDir := filepath.Dir(cwd)
	projectPath := windowsToWSLPath(projectDir)

	t.Logf("Running stress tests in WSL from %s", projectPath)

	// Run SQLite stress test in WSL (skip Docker to avoid complexity)
	cmd := exec.Command("wsl", "bash", "-c", fmt.Sprintf(
		"cd %s && go test ./test/... -tags=stress -v -run 'TestStressSQLite|TestStressConnectionChurn' -timeout 120s 2>&1",
		projectPath,
	))

	output, err := cmd.CombinedOutput()
	t.Logf("WSL stress test output:\n%s", string(output))

	if err != nil {
		if strings.Contains(string(output), "FAIL") {
			t.Errorf("WSL stress tests failed: %v", err)
		} else {
			t.Fatalf("Failed to run WSL stress tests: %v", err)
		}
	}

	if strings.Contains(string(output), "PASS") {
		t.Log("WSL stress tests passed")
	}
}

// Helper functions

func sortDurations(d []time.Duration) {
	for i := 0; i < len(d)-1; i++ {
		for j := i + 1; j < len(d); j++ {
			if d[i] > d[j] {
				d[i], d[j] = d[j], d[i]
			}
		}
	}
}

func windowsToWSLPath(winPath string) string {
	path := strings.ReplaceAll(winPath, "\\", "/")
	if len(path) >= 2 && path[1] == ':' {
		drive := strings.ToLower(string(path[0]))
		path = "/mnt/" + drive + path[2:]
	}
	return path
}
