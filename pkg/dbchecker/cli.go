/*
CLI implementation for dbchecker database connectivity diagnostics.

Usage Modes:
  - Version: dbchecker -version
  - Encrypt: dbchecker -encrypt "password" (outputs Base64 ciphertext)
  - Single:  dbchecker -config config.yaml -db mydb
  - Batch:   dbchecker -config config.yaml [-concurrency 10] [-json]

Error Message Format: "[component] action failed: error"

	Components: key, encrypt, config, output

Exit Code Strategy:

	Returns the highest exit code among all checked databases.
	This enables shell scripts to detect the most severe failure type.
*/
package dbchecker

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/crypto"
	"github.com/edsilegxrepo/dbchecker/database"
)

// Version is set at build time via -ldflags "-X ...Version=v1.0.0".
// Defaults to "dev" for local builds without ldflags.
var Version = "dev"

// RunAppCLI executes CLI lifecycle logic and returns integer exit code.
// Exit codes:
// 0 = ExitSuccess (All checks passed)
// 1 = ExitConfigError (Configuration or CLI flag error)
// 2 = ExitKeyError (Secret key resolution failure)
// 3 = ExitDecryptionError (Password decryption failure)
// 4 = ExitConnectionError (Socket connection or network timeout)
// 5 = ExitHealthError (Ping failure or healthcheck query error)
func RunAppCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbchecker", flag.ContinueOnError)
	flags.SetOutput(stderr)

	configFile := flags.String("config", "config.yaml", "Path to the configuration file")
	dbID := flags.String("db", "", "Identifier of the database to check")
	versionFlag := flags.Bool("version", false, "Display version information")
	encryptFlag := flags.String("encrypt", "", "Encrypt a password and exit")
	keyFileFlag := flags.String("key-file", "", "Path to the secret key file (overrides DB_SECRET_KEY)")
	timeoutFlag := flags.Duration("timeout", 10*time.Second, "Timeout for each database connection and check operation")
	concurrencyFlag := flags.Int("concurrency", 10, "Maximum concurrent database checks")
	jsonFlag := flags.Bool("json", false, "Output diagnostic results in JSON format")

	if err := flags.Parse(args); err != nil {
		return ExitConfigError
	}

	if *versionFlag {
		_, _ = fmt.Fprintf(stdout, "DB Connection Diags - Version: %s\n", Version)
		return ExitSuccess
	}

	ctx := context.Background()

	// Resolve the master secret key using secretprotector key resolution strategy.
	var envVar string
	var keyFile string
	if *keyFileFlag != "" {
		keyFile = *keyFileFlag
	} else {
		envVar = "DB_SECRET_KEY"
	}

	secretKeyBytes, err := crypto.ResolveKey(ctx, "", envVar, keyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[key] resolution failed: %v\n", err)
		return ExitKeyError
	}
	defer crypto.ZeroBuffer(secretKeyBytes)

	if *encryptFlag != "" {
		encryptedPassword, err := crypto.Encrypt(ctx, *encryptFlag, secretKeyBytes)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "[encrypt] encryption failed: %v\n", err)
			return ExitDecryptionError
		}
		_, _ = fmt.Fprintln(stdout, encryptedPassword)
		return ExitSuccess
	}

	cfg, err := config.LoadConfig(*configFile, database.IsSupported)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[config] load failed: %v\n", err)
		return ExitConfigError
	}

	var results []Result

	if *dbID != "" {
		dbConfig, ok := cfg.Databases[*dbID]
		if !ok {
			_, _ = fmt.Fprintf(stderr, "[config] database ID '%s' not found\n", *dbID)
			return ExitConfigError
		}
		res := Check(ctx, *dbID, dbConfig, secretKeyBytes, *timeoutFlag)
		results = []Result{res}
	} else {
		results = CheckAll(ctx, cfg, secretKeyBytes,
			WithTimeout(*timeoutFlag),
			WithConcurrency(*concurrencyFlag),
		)
	}

	if *jsonFlag {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(results); err != nil {
			_, _ = fmt.Fprintf(stderr, "[output] JSON encoding failed: %v\n", err)
			return ExitConfigError
		}
	} else {
		for _, res := range results {
			if res.Success {
				_, _ = fmt.Fprintf(stdout, "Successfully connected and checked %s (%s) [%v]\n", res.ID, res.Type, res.Duration)
			} else {
				_, _ = fmt.Fprintf(stderr, "Check failed for %s (%s) at step '%s' [%v]: %v\n", res.ID, res.Type, res.FailedStep, res.Duration, res.Err)
			}
		}
	}

	highestExitCode := ExitSuccess
	for _, res := range results {
		if !res.Success && res.ExitCode > highestExitCode {
			highestExitCode = res.ExitCode
		}
	}

	return highestExitCode
}
