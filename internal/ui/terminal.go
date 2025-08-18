// Package ui provides components for the user interface of the SweetByte application.
package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

// Terminal provides functions for interacting with the terminal.
type Terminal struct{}

// NewTerminal creates a new Terminal instance.
func NewTerminal() *Terminal {
	return &Terminal{}
}

// Clear clears the terminal screen.
func (t *Terminal) Clear() {
	screen.Clear()
}

// MoveTopLeft moves the cursor to the top-left corner of the terminal.
func (t *Terminal) MoveTopLeft() {
	screen.MoveTopLeft()
}

// PrintBanner prints the application's banner to the terminal.
func (t *Terminal) PrintBanner() {
	banner := `
███████╗██╗    ██╗███████╗███████╗████████╗██████╗ ██╗   ██╗████████╗███████╗
██╔════╝██║    ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
███████╗██║ █╗ ██║█████╗  █████╗     ██║   ██████╔╝ ╚████╔╝    ██║   █████╗  
╚════██║██║███╗██║██╔══╝  ██╔══╝     ██║   ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  
███████║╚███╔███╔╝███████╗███████╗   ██║   ██████╔╝   ██║      ██║   ███████╗
╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝   ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
`
	fmt.Println(banner)
}

// Cleanup performs any necessary cleanup tasks for the terminal.
func (t *Terminal) Cleanup() {
	fmt.Println()
}
