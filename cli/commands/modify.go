package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

func HandleModify(_ context.Context, _ *cli.Command) error {
	return handleStub("modify")
}

func HandleModifyAdd(_ context.Context, _ *cli.Command) error {
	return handleStub("modify add")
}

func HandleModifyRemove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify rm")
}

func HandleModifyMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

func HandleModifyList(_ context.Context, _ *cli.Command) error {
	return handleStub("modify ls")
}
