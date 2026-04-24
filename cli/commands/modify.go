package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)


// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, _ *cli.Command) error {
	return handleStub("modify add")
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify rm")
}

// HandleMove renames or relocates a tracked secret path.
func HandleMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

// HandleList prints tracked secret metadata.
func HandleList(_ context.Context, _ *cli.Command) error {
	return handleStub("modify ls")
}
