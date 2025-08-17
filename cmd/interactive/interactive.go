// Package interactive provides the entry point for the SweetByte interactive application mode.
// It serves as a simple wrapper, forwarding the creation of the interactive application
// to the internal/interactive package.
package interactive

import (
	"github.com/hambosto/sweetbyte/internal/interactive"
)

// NewInteractiveApp creates and returns a new instance of the interactive application.
// This function is the public interface for initializing the interactive mode.
func NewInteractiveApp() *interactive.InteractiveApp {
	return interactive.NewInteractiveApp() // Delegates the creation of the interactive app to the internal/interactive package.
}
