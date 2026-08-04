/*
Package main provides the CLI entrypoint for DB Connection Diags.
It delegates command-line execution directly to pkg/dbchecker.RunAppCLI for 100% DRY compliance.
*/
package main

import (
	"io"
	"os"

	"github.com/edsilegxrepo/dbchecker/pkg/dbchecker"
)

func main() {
	os.Exit(runApp(os.Args[1:], os.Stdout, os.Stderr))
}

func runApp(args []string, stdout, stderr io.Writer) int {
	return dbchecker.RunAppCLI(args, stdout, stderr)
}
