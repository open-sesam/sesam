package commands

import (
	"context"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleSeal encrypts and signs tracked secrets via a staged seal commit.
func HandleSeal(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if err := r.Update(func(s *repo.Stage) error { return s.SealAll() }); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		return r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
		})
	}

	return nil
}
