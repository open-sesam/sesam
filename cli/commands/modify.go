package commands

import (
	"context"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleAddSecret adds a secret path to sesam metadata.
func HandleAddSecret(ctx context.Context, cmd *cli.Command) error {
	return clirepo.AddSecret(
		cmd.String("config"),
		cmd.String("path"),
		cmd.String("name"),
		cmd.String("type"),
		cmd.String("description"),
		cmd.StringSlice("access"),
	)
}

// HandleRemoveSecret removes a secret path from sesam metadata.
func HandleRemoveSecret(_ context.Context, _ *cli.Command) error {
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

func HandleRead(_ context.Context, _ *cli.Command) error {
	return handleStub("modify read")
}
