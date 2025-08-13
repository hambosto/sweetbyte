package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

// Terminal provides terminal control functionality
type Terminal struct{}

// NewTerminal creates a new Terminal instance
func NewTerminal() *Terminal {
	return &Terminal{}
}

// Clear clears the terminal screen
func (t *Terminal) Clear() {
	screen.Clear()
}

// MoveTopLeft moves the cursor to the top-left corner
func (t *Terminal) MoveTopLeft() {
	screen.MoveTopLeft()
}

// PrintBanner prints the application banner
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

// PrintError prints an error message with formatting
func (t *Terminal) PrintError(message string) {
	fmt.Printf("❌ %s\n", message)
}

// Cleanup performs terminal cleanup operations
func (t *Terminal) Cleanup() {
	fmt.Println() // Add a newline for clean exit
}
