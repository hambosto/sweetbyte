// Package ui provides user interface functionalities.
package ui

import (
	"github.com/alperdrsnn/clime"
)

// Clear clears the terminal screen.
func Clear() {
	clime.Clear()
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
	clime.BoldColor.Print(banner)
}
