package main

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/cmd/cli"
	"github.com/hambosto/sweetbyte/cmd/interactive"
)

func main() {
	if len(os.Args) > 1 {
		cliApp := cli.NewCLI()
		if err := cliApp.Execute(); err != nil {
			os.Exit(1)
		}
	} else {
		if err := interactive.Run(); err != nil {
			fmt.Print(err)
		}
	}
}
