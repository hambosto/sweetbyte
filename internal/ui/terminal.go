package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

type Terminal struct{}

func NewTerminal() *Terminal {
	return &Terminal{}
}

func (t *Terminal) Clear() {
	screen.Clear()
}

func (t *Terminal) MoveTopLeft() {
	screen.MoveTopLeft()
}

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

func (t *Terminal) PrintError(message string) {
	fmt.Printf("❌ %s\n", message)
}

func (t *Terminal) Cleanup() {
	fmt.Println()
}
