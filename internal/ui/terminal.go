// Package ui provides user interface functionalities.
package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

// Clear clears the terminal screen.
func Clear() {
	screen.Clear()
}

// MoveTopLeft moves the cursor to the top-left corner of the terminal.
func MoveTopLeft() {
	screen.MoveTopLeft()
}

// PrintBanner prints the application banner to the terminal.
func PrintBanner() {
	banner := `
   _____                   __  __          __     
  / ___/      _____  ___  / /_/ /_  __  __/ /____ 
  \__ \ | /| / / _ \/ _ \/ __/ __ \/ / / / __/ _ \
 ___/ / |/ |/ /  __/  __/ /_/ /_/ / /_/ / /_/  __/
/____/|__/|__/\___/\___/\__/_.___/\__, /\__/\___/ 
                                 /____/           
`
	fmt.Print(banner)
}
