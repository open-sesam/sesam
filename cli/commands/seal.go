package commands

import (
	"context"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleSeal encrypts and signs tracked secrets via Repo.SealAll.
func HandleSeal(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if err := r.SealAll(); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		return r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
		})
	}

	return nil
}
