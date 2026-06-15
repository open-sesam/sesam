package main

import (
	"fmt"
	"os"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/cli"
)

func printError(msg string) {
	output := termenv.NewOutput(os.Stdout)
	prefix := output.String("⨯").Foreground(output.Color("#800000")).String()
	fmt.Printf("%s %s\n", prefix, msg)
}

func main() {
	if err := cli.Main(os.Args); err != nil {
		printError(err.Error())
		os.Exit(1)
	}
}
