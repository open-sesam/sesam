package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

func HandleHookPreCommit(_ context.Context, cmd *cli.Command) error {
	// Run seal (only if needed, depending on audit log and if .sesam exists) and verify. If very fails we should abort the commit.
	return nil
}

func HandleHookPostCheckout(_ context.Context, cmd *cli.Command) error {
	// Run clean and open (only if .sesam exists) - is also run on git clone.
	return nil
}

func HandleHookInstall(_ context.Context, cmd *cli.Command) error {
	// Make sure hooks are all configured (or only specific ones)
	return nil
}

func HandleHookUninstall(_ context.Context, cmd *cli.Command) error {
	// Make sure hooks are all configured (or only specific ones)
	return nil
}
