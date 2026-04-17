package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

// HandleModify is the parent command for secret metadata/file mutations.
func HandleModify(_ context.Context, _ *cli.Command) error {
	return handleStub("modify")
}

// HandleModifyAdd adds a secret path to sesam metadata.
func HandleModifyAdd(_ context.Context, _ *cli.Command) error {
	return handleStub("modify add")
}

// HandleModifyRemove removes a secret path from sesam metadata.
func HandleModifyRemove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify rm")
}

// HandleModifyMove renames or relocates a tracked secret path.
func HandleModifyMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

// HandleModifyList prints tracked secret metadata.
func HandleModifyList(_ context.Context, _ *cli.Command) error {
	return handleStub("modify ls")
}
