// Package interactive provides the entry point for the interactive mode.
package interactive

import (
	"github.com/hambosto/sweetbyte/internal/interactive"
)

// NewInteractive creates a new interactive mode runner.
func NewInteractive() *interactive.Interactive {
	// It returns a new interactive mode runner from the internal interactive package.
	return interactive.NewInteractive()
}
