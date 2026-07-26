package dbchecker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"criticalsys.net/dbchecker/config"
	"criticalsys.net/dbchecker/crypto"
	"criticalsys.net/dbchecker/database"
)

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

	// 1. Decrypt password
	decryptedPassword, err := crypto.Decrypt(ctx, dbConfig.Password, secretKey)
	if err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepDecryption
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = fmt.Errorf("password decryption failed for %s: %w", id, err)
		return res
	}

	// 2. Initialize database driver
	db, err := database.New(dbConfig.Type)
	if err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepDriverInit
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = err
		return res
	}

	// 3. Connect to database
	if err := db.Connect(ctx, dbConfig, decryptedPassword); err != nil {
		res.Duration = time.Since(startTime)
		res.FailedStep = StepConnect
		res.ExitCode = MapStepToExitCode(res.FailedStep)
		res.Err = fmt.Errorf("connection failed for %s: %w", id, err)
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
		return res
	}

	// 5. Run health check query if provided
	if dbConfig.HealthQuery != "" {
		if err := db.HealthCheck(ctx, dbConfig.HealthQuery); err != nil {
			res.Duration = time.Since(startTime)
			res.FailedStep = StepHealthCheck
			res.ExitCode = MapStepToExitCode(res.FailedStep)
			res.Err = fmt.Errorf("health check failed for %s: %w", id, err)
			return res
		}
	}

	res.Success = true
	res.ExitCode = ExitSuccess
	res.Duration = time.Since(startTime)
	return res
}

// CheckAll executes batch connectivity and health checks concurrently across all databases in cfg.
// It accepts functional options to configure timeout and worker concurrency.
func CheckAll(ctx context.Context, cfg *config.Config, secretKey []byte, opts ...Option) []Result {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	if cfg == nil || len(cfg.Databases) == 0 {
		return nil
	}

	results := make([]Result, len(cfg.Databases))
	var wg sync.WaitGroup
	var mu sync.Mutex
	idx := 0

	sem := make(chan struct{}, options.Concurrency)

	for id, dbConfig := range cfg.Databases {
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
		idx++
	}

	wg.Wait()
	return results
}
