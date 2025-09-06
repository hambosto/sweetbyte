package ui

import (
	"fmt"

	"github.com/inancgumus/screen"
)

func Clear() {
	screen.Clear()
}

func MoveTopLeft() {
	screen.MoveTopLeft()
}

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
