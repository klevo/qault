package main

import (
	"fmt"
	"os"

	"qault/internal/cli"
	"qault/internal/tui"
)

func main() {
	if len(os.Args) <= 1 {
		if err := tui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	c := cli.NewDefault()
	os.Exit(c.Run(os.Args[1:]))
}
