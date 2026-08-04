/*
Package dbchecker checker implements the core database connectivity verification logic.

Objectives:
  - Perform secure credential decryption with memory hygiene
  - Execute multi-step health checks (connect → ping → query)
  - Support concurrent batch checking with configurable parallelism
  - Provide deterministic, sorted result ordering for reproducibility

Check Lifecycle (per database):
 1. Decrypt password using DecryptBytes (zeroable []byte)
 2. Initialize driver from registry
 3. Establish connection with timeout context
 4. Verify connectivity via Ping
 5. Execute optional health query
 6. Zero password buffer on completion (defer)

Security Model:
  - Passwords decrypted to []byte, zeroed after use via defer
  - Context timeout propagated through all network operations
  - Early exit on any failure with granular step identification
*/
package dbchecker

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/crypto"
	"github.com/edsilegxrepo/dbchecker/database"
)

// finalizeResult populates computed fields for JSON serialization before returning.
// Converts Duration to milliseconds and Err to string for proper JSON output.
func finalizeResult(res *Result) {
	res.DurationMs = res.Duration.Milliseconds()
	if res.Err != nil {
		res.ErrorMsg = res.Err.Error()
	}
}

// Check performs a single connectivity and health check lifecycle for a DatabaseConfig.
// It returns a strongly-typed Result struct with duration metrics, granular exit codes, and step error categorization.
func Check(parentCtx context.Context, id string, dbConfig config.DatabaseConfig, secretKey []byte, timeout time.Duration) Result {
	startTime := time.Now()
	res := Result{
		ID:       id,
		Type:     dbConfig.Type,
		ExitCode: ExitSuccess,
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	// 1. Decrypt password (use DecryptBytes so we can zero the buffer after use)
	decryptedPasswordBytes, err := crypto.DecryptBytes(ctx, dbConfig.Password, secretKey)
	if err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepDecryption
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = fmt.Errorf("password decryption failed for %s: %w", id, err)
		finalizeResult(&res)
		return res
	}
	defer crypto.ZeroBuffer(decryptedPasswordBytes)
	decryptedPassword := string(decryptedPasswordBytes)

	// 2. Initialize database driver
	db, err := database.New(dbConfig.Type)
	if err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepDriverInit
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = err
		finalizeResult(&res)
		return res
	}

	// 3. Connect to database
	if err := db.Connect(ctx, dbConfig, decryptedPassword); err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepConnect
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = fmt.Errorf("connection failed for %s: %w", id, err)
		finalizeResult(&res)
		return res
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil && res.Err == nil {
			res.Err = fmt.Errorf("close failed for %s: %w", id, closeErr)
		}
	}()

	// 4. Ping database
	if err := db.Ping(ctx); err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepPing
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = fmt.Errorf("ping failed for %s: %w", id, err)
		finalizeResult(&res)
		return res
	}

	// 5. Run health check query if provided
	if dbConfig.HealthQuery != "" {
		if err := db.HealthCheck(ctx, dbConfig.HealthQuery); err != nil {
			res.Duration = time.Since(startTime)
			res.FailedStep = StepHealthCheck
			res.ExitCode = MapStepToExitCode(res.FailedStep)
			res.Err = fmt.Errorf("health check failed for %s: %w", id, err)
			finalizeResult(&res)
			return res
		}
	}

	res.Success = true
	res.ExitCode = ExitSuccess
	res.Duration = time.Since(startTime)
	finalizeResult(&res)
	return res
}

// CheckAll executes batch connectivity and health checks concurrently across all databases in cfg.
// Results are returned in deterministic alphabetical order by database ID for reproducible output.
// Concurrency is controlled via semaphore; default 10 parallel workers.
func CheckAll(ctx context.Context, cfg *config.Config, secretKey []byte, opts ...Option) []Result {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	if cfg == nil || len(cfg.Databases) == 0 {
		return nil
	}

	// Sort database IDs for deterministic result ordering (Go map iteration is random)
	ids := make([]string, 0, len(cfg.Databases))
	for id := range cfg.Databases {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	results := make([]Result, len(ids))
	var wg sync.WaitGroup
	var mu sync.Mutex

	sem := make(chan struct{}, options.Concurrency)

	for idx, id := range ids {
		dbConfig := cfg.Databases[id]
		wg.Add(1)
		sem <- struct{}{}
		go func(currentIndex int, targetID string, targetConfig config.DatabaseConfig) {
			defer wg.Done()
			defer func() { <-sem }()

			res := Check(ctx, targetID, targetConfig, secretKey, options.Timeout)

			mu.Lock()
			results[currentIndex] = res
			mu.Unlock()
		}(idx, id, dbConfig)
	}

	wg.Wait()
	return results
}
