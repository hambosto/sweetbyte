// Package ui provides user interface functionalities.
package ui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/charmbracelet/lipgloss"
)

// Clear clears the terminal screen.
func Clear() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run() //nolint:errcheck
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
	fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2")).Render(banner))
}
