package dbchecker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dbchecker/crypto"
)

func TestRunAppCLIInPkg(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. Test -version flag
	code := RunAppCLI([]string{"-version"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for -version, got %d", code)
	}

	// 2. Test missing secret key error -> ExitKeyError (2)
	t.Setenv("DB_SECRET_KEY", "")
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-config", "non_existent.yaml"}, &stdout, &stderr)
	if code != ExitKeyError {
		t.Errorf("Expected exit code ExitKeyError (%d) when secret key is missing, got %d", ExitKeyError, code)
	}

	// 3. Test -encrypt flag with valid secret key in env
	secretKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars = 32 bytes
	t.Setenv("DB_SECRET_KEY", secretKeyHex)
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-encrypt", "mypassword"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for -encrypt, got %d", code)
	}

	// 4. Test execution with YAML config file and single DB check + -json flag
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "app_config.yaml")

	secretKeyBytes, err := crypto.ResolveKey(context.Background(), secretKeyHex, "", "")
	if err != nil {
		t.Fatalf("Failed to resolve test key: %v", err)
	}

	encryptedPass, _ := crypto.Encrypt(context.Background(), "pass123", secretKeyBytes)
	yamlData := `
databases:
  db1:
    type: sqlite
    name: ":memory:"
    password: ` + encryptedPass + `
`
	_ = os.WriteFile(configPath, []byte(yamlData), 0o600)

	// Test single valid DB execution with -json flag
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-config", configPath, "-db", "db1", "-json"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for single valid DB check with -json, got %d. Stderr: %s", code, stderr.String())
	}

	// Test single valid DB execution with text formatting
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-config", configPath, "-db", "db1"}, &stdout, &stderr)
	if code != ExitSuccess {
		t.Errorf("Expected exit code ExitSuccess (0) for text output, got %d", code)
	}

	// Test missing DB ID in config -> ExitConfigError (1)
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-config", configPath, "-db", "missing_db"}, &stdout, &stderr)
	if code != ExitConfigError {
		t.Errorf("Expected exit code ExitConfigError (%d) for missing DB ID, got %d", ExitConfigError, code)
	}

	// Test missing config file -> ExitConfigError (1)
	stdout.Reset()
	stderr.Reset()
	code = RunAppCLI([]string{"-config", "non_existent_cfg.yaml"}, &stdout, &stderr)
	if code != ExitConfigError {
		t.Errorf("Expected exit code ExitConfigError (%d) for missing config file, got %d", ExitConfigError, code)
	}
}

func TestMapStepToExitCodeDefault(t *testing.T) {
	if code := MapStepToExitCode(StepError("unknown_step")); code != ExitConfigError {
		t.Errorf("Expected ExitConfigError (%d) for unknown step, got %d", ExitConfigError, code)
	}
}
