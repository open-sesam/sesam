package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

// HandleRotate is the parent command for key/secret rotation workflows.
func HandleRotate(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate")
}

// HandleRotatePlan computes and prints the intended rotation plan.
func HandleRotatePlan(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate plan")
}

// HandleRotateExec executes a previously prepared rotation plan.
func HandleRotateExec(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate exec")
}

// HandleRotateTodo lists pending post-rotation tasks.
func HandleRotateTodo(_ context.Context, _ *cli.Command) error {
	return handleStub("rotate todo")
}
