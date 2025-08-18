// Package ui provides user interface components and utilities for the SweetByte application.
// This includes terminal manipulation, interactive prompts, and progress bar displays,
// enhancing the user experience in both CLI and interactive modes.
package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

// Terminal provides methods for interacting with the console screen.
// It wraps functionality like clearing the screen, moving the cursor, and printing specific UI elements.
type Terminal struct{}

// NewTerminal creates and returns a new Terminal instance.
// It is an empty struct as its methods directly use screen manipulation functions.
func NewTerminal() *Terminal {
	return &Terminal{}
}

// Clear clears the entire terminal screen.
func (t *Terminal) Clear() {
	screen.Clear()
}

// MoveTopLeft moves the terminal cursor to the top-left corner (0,0 position).
func (t *Terminal) MoveTopLeft() {
	screen.MoveTopLeft()
}

// PrintBanner displays the SweetByte ASCII art banner to the console.
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

// Cleanup performs any necessary terminal cleanup, such as adding a final newline.
func (t *Terminal) Cleanup() {
	fmt.Println() // Print a newline to ensure the cursor is on a fresh line after operations.
}
