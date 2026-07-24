// Package main is the entry point for the sesam binary.
//
// If you want to import sesam as library, then you should use the high-level API in repo/
// Some types from core/ will be required too.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/muesli/termenv"
	"opensesam.org/sesam/cli"
	"opensesam.org/sesam/cli/commands"
)

func printError(msg string) {
	output := termenv.NewOutput(os.Stderr)
	prefix := output.String("✘").Foreground(output.Color("#800000")).String()

	// NOTE: errors must go to stderr.
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
}

func main() {
	if err := cli.Main(os.Args); err != nil {
		exitErr := new(commands.ExitCodeErr)
		if errors.As(err, &exitErr) {
			if exitErr.Print() {
				printError(err.Error())
			}

			os.Exit(exitErr.Code())
			return
		}

		// generic case:
		printError(err.Error())
		os.Exit(1)
	}
}
