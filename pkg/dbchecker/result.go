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
type Result struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Success    bool          `json:"success"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration_ms"`
	FailedStep StepError     `json:"failed_step,omitempty"`
	Err        error         `json:"error,omitempty"`
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
