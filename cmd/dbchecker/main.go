/*
Package main provides the standalone CLI binary for DB Connection Diags.
It calls pkg/dbchecker.RunAppCLI to execute CLI diagnostic workflows.
*/
package main

import (
	"io"
	"os"

	"criticalsys.net/dbchecker/pkg/dbchecker"
)

func main() {
	os.Exit(runApp(os.Args[1:], os.Stdout, os.Stderr))
}

func runApp(args []string, stdout, stderr io.Writer) int {
	return dbchecker.RunAppCLI(args, stdout, stderr)
}
