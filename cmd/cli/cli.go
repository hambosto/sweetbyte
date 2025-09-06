// Package cli provides the entry point for the command-line interface.
package cli

import (
	"github.com/hambosto/sweetbyte/internal/cli"
)

// NewCLI creates a new CLI command runner.
func NewCLI() *cli.Commands {
	// It returns a new command runner from the internal cli package.
	return cli.NewCommands()
}
