/*
Package main provides the CLI entrypoint for DB Connection Diags.
It delegates command-line execution directly to pkg/dbchecker.RunAppCLI for 100% DRY compliance.
*/
package main

import (
	"context"
	"io"
	"os"
	"time"

	"criticalsys.net/dbchecker/config"
	"criticalsys.net/dbchecker/pkg/dbchecker"
)

func main() {
	os.Exit(runApp(os.Args[1:], os.Stdout, os.Stderr))
}

func runApp(args []string, stdout, stderr io.Writer) int {
	return dbchecker.RunAppCLI(args, stdout, stderr)
}

// checkDatabase is preserved for root package test backwards compatibility.
func checkDatabase(parentCtx context.Context, dbConfig config.DatabaseConfig, dbID string, secretKey []byte, timeout time.Duration, stdout, stderr io.Writer) error {
	res := dbchecker.Check(parentCtx, dbID, dbConfig, secretKey, timeout)
	if !res.Success {
		return res.Err
	}
	return nil
}
