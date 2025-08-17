// Package main is the entry point for the SweetByte application.
// It orchestrates the startup of either the command-line interface (CLI) or the interactive mode,
// based on the arguments provided at runtime.
package main

import (
	"os"

	"github.com/hambosto/sweetbyte/cmd/cli"
	"github.com/hambosto/sweetbyte/cmd/interactive"
)

// main is the primary function where the application execution begins.
// It checks for command-line arguments to decide whether to launch the CLI or the interactive application.
func main() {
	if len(os.Args) > 1 { // Check if any command-line arguments are provided.
		cliApp := cli.NewCLI()                   // Initialize a new CLI application instance.
		if err := cliApp.Execute(); err != nil { // Execute the CLI command and check for errors.
			os.Exit(1) // If an error occurs during CLI execution, exit with a non-zero status code.
		}
	} else { // If no command-line arguments are provided, default to interactive mode.
		interactiveApp := interactive.NewInteractiveApp() // Initialize a new interactive application instance.
		interactiveApp.Run()                              // Run the interactive application.
	}
}
