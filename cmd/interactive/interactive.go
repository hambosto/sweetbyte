// Package interactive provides the interactive mode for the SweetByte application.
package interactive

import (
	"github.com/hambosto/sweetbyte/internal/interactive"
)

// NewInteractiveApp creates a new interactive application instance.
func NewInteractive() *interactive.Interactive {
	return interactive.NewInteractive()
}
