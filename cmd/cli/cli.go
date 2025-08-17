// Package cli provides the command-line interface entry point for the SweetByte application.
// It acts as a wrapper, delegating the actual CLI logic to the internal/cli package.
package cli

import (
	"github.com/hambosto/sweetbyte/internal/cli"
)

// NewCLI creates and returns a new instance of the CLI application.
// This function serves as the public interface for initializing the CLI.
func NewCLI() *cli.CLI {
	return cli.NewCLI() // Delegates the creation of the CLI to the internal/cli package.
}
