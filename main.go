// Package main is the entry point of the SweetByte application.
// It determines whether to run the application in CLI mode or interactive mode based on the command-line arguments.
package main

import (
	"os"

	"github.com/hambosto/sweetbyte/cmd/cli"
	"github.com/hambosto/sweetbyte/cmd/interactive"
)

// main is the entry point of the application.
// It checks for command-line arguments to decide which mode to run.
func main() {
	// If there are more than one argument, it means the user wants to run the CLI mode.
	if len(os.Args) > 1 {
		// Create a new CLI application instance.
		cliApp := cli.NewCLI()
		// Execute the CLI application and exit with an error code if something goes wrong.
		if err := cliApp.Execute(); err != nil {
			os.Exit(1)
		}
	} else {
		// If there are no arguments, run the application in interactiveApp mode.
		interactiveApp := interactive.NewInteractive()
		// Run the interactiveApp application.
		interactiveApp.Run()
	}
}
