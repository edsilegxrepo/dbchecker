/*
Package dbchecker result types define structured diagnostic output for database health checks.

Design Objectives:
  - Provide granular exit codes for shell scripting and CI/CD integration
  - Enable step-by-step failure identification for troubleshooting
  - Support both human-readable CLI output and machine-parseable JSON

JSON Serialization:
  - DurationMs: Milliseconds as int64 (not Duration's nanoseconds)
  - ErrorMsg: String message (not Go's error interface which serializes as {})
  - Duration/Err: Internal fields excluded from JSON (json:"-")
*/
package dbchecker

import (
	"time"
)

// Granular diagnostic exit codes for CLI and orchestration scripts.
const (
	ExitSuccess         = 0 // All database checks passed successfully
	ExitConfigError     = 1 // Configuration, CLI flag, or driver lookup error
	ExitKeyError        = 2 // Master secret key resolution or permission error
	ExitDecryptionError = 3 // Password decryption failure
	ExitConnectionError = 4 // Socket connection drop or network timeout
	ExitHealthError     = 5 // Ping failure or healthcheck query failure
)

// StepError represents the specific phase of execution where a check failed.
type StepError string

const (
	StepNone        StepError = ""
	StepDecryption  StepError = "decryption"
	StepDriverInit  StepError = "driver_init"
	StepConnect     StepError = "connect"
	StepPing        StepError = "ping"
	StepHealthCheck StepError = "health_check"
)

// Result holds structured diagnostic details, latency metrics, and granular exit codes.
// Fields are designed for both programmatic access and JSON serialization:
//   - DurationMs: Computed from Duration for JSON (milliseconds, not nanoseconds)
//   - ErrorMsg: Computed from Err for JSON (string, not empty object)
//   - Duration/Err: Internal use only, excluded from JSON output
type Result struct {
	ID         string        `json:"id"`                    // Database identifier from config
	Type       string        `json:"type"`                  // Driver type (postgres, mysql, etc.)
	Success    bool          `json:"success"`               // True if all steps passed
	ExitCode   int           `json:"exit_code"`             // Granular exit code for scripting
	DurationMs int64         `json:"duration_ms"`           // Check duration in milliseconds
	Duration   time.Duration `json:"-"`                     // Internal: raw duration value
	FailedStep StepError     `json:"failed_step,omitempty"` // Which step failed (if any)
	Err        error         `json:"-"`                     // Internal: raw error value
	ErrorMsg   string        `json:"error,omitempty"`       // Serializable error message
}

// MapStepToExitCode maps a failed execution step to a granular diagnostic exit code.
func MapStepToExitCode(step StepError) int {
	switch step {
	case StepNone:
		return ExitSuccess
	case StepDecryption:
		return ExitDecryptionError
	case StepDriverInit:
		return ExitConfigError
	case StepConnect:
		return ExitConnectionError
	case StepPing, StepHealthCheck:
		return ExitHealthError
	default:
		return ExitConfigError
	}
}
