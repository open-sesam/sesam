package commands

import (
	"context"

	"github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleSeal encrypts and signs tracked secrets via Repo.SealAll.
func HandleSeal(ctx context.Context, cmd *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
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
