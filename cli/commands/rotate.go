package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

func HandleRotate(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate")
}

func HandleRotatePlan(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate plan")
}

func HandleRotateExec(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate exec")
}

func HandleRotateTodo(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate todo")
}
