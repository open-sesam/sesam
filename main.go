package main

import (
	"log/slog"
	"os"

	"github.com/open-sesam/sesam/cli"
)

func main() {
	if err := cli.Main(os.Args); err != nil {
		slog.Error("exit", slog.Any("error", err))
		os.Exit(1)
	}
}
