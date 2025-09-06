// Package ui provides components for the user interface of the SweetByte application.
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

// PrintBanner prints the application's banner to the terminal.
func PrintBanner() {
	banner := `
   _____                   __  ____        __     
  / ___/      _____  ___  / /_/ __ )__  __/ /____ 
  \__ \ | /| / / _ \/ _ \/ __/ __  / / / / __/ _ \
 ___/ / |/ |/ /  __/  __/ /_/ /_/ / /_/ / /_/  __/
/____/|__/|__/\___/\___/\__/_____/\__, /\__/\___/ 
                                 /____/           
`
	fmt.Print(banner)
}
