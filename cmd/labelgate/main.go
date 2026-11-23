package main

import (
	"os"

	"github.com/momirov/labelgate/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}))
}
