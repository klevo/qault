package main

import (
	"os"

	"qault/internal/cli"
)

func main() {
	c := cli.NewDefault()
	os.Exit(c.Run(os.Args[1:]))
}
