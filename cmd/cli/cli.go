// Package cli provides the command-line interface for the SweetByte application.
package cli

import (
	"github.com/hambosto/sweetbyte/internal/cli"
)

// NewCLI creates a new CLI application instance.
func NewCLI() *cli.CLI {
	return cli.NewCLI()
}
