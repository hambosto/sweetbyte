// Package cli provides the command-line interface for the SweetByte application.
package cli

import (
	"github.com/hambosto/sweetbyte/internal/cli"
)

// NewCLI creates a new Commands application instance.
func NewCLI() *cli.Commands {
	return cli.NewCommands()
}
