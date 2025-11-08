package main

import (
	"os"

	"sweetbyte/cmd/cli"
	"sweetbyte/cmd/interactive"
)

func main() {
	if len(os.Args) > 1 {
		cliApp := cli.NewCommands()
		if err := cliApp.Execute(); err != nil {
			os.Exit(1)
		}
	} else {
		interactiveApp := interactive.NewInteractive()
		interactiveApp.Run()
	}
}
