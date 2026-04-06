package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

func HandleRoot(_ context.Context, _ *cli.Command) error {
	fmt.Println("sesam started. use --help to inspect available commands")
	return nil
}

func HandleVerify(_ context.Context, _ *cli.Command) error {
	return handleStub("verify")
}

func HandleID(_ context.Context, _ *cli.Command) error {
	return handleStub("id")
}

func HandleServer(_ context.Context, _ *cli.Command) error {
	return handleStub("server")
}

func HandleLog(_ context.Context, _ *cli.Command) error {
	return handleStub("log")
}

func HandleUndo(_ context.Context, _ *cli.Command) error {
	return handleStub("undo")
}

func HandleTell(_ context.Context, _ *cli.Command) error {
	return handleStub("tell")
}

func HandleKill(_ context.Context, _ *cli.Command) error {
	return handleStub("kill")
}

func HandleList(_ context.Context, _ *cli.Command) error {
	return handleStub("list")
}
