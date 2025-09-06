// Package main is the entry point of the SweetByte application.
package main

import (
	"os"

	"github.com/hambosto/sweetbyte/cmd/cli"
	"github.com/hambosto/sweetbyte/cmd/interactive"
)

// main is the entry point of the application.
func main() {
	// If there are command-line arguments, run the CLI application.
	if len(os.Args) > 1 {
		cliApp := cli.NewCLI()
		if err := cliApp.Execute(); err != nil {
			os.Exit(1)
		}
	} else {
		// Otherwise, run the interactive application.
		interactiveApp := interactive.NewInteractive()
		interactiveApp.Run()
	}
}
