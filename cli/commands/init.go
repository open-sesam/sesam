package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// TODO: Show ascii logo on init

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) (err error) {
	initialUser := cmd.String("user")
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	r, err := repo.Init(
		ctx,
		cmd.String("sesam-dir"),
		initialUser,
		cmd.StringSlice("identity"),
		repo.RepoOpts{
			Interactive: true,
			LockTimeout: cmd.Duration("lock-timeout"),
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := r.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("close repo: %w", closeErr)
			return
		}
		slog.Warn("close repo failed", slog.Any("error", closeErr))
	}()

	return nil
}
