package main

import (
	"os"

	"github.com/momirov/scopedmail/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}))
}
