package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// RepoAction is the signature every handler that needs a live sesam Repo
// uses. The Repo is loaded (lock + managers) by WithRepo before the handler
// runs and is closed afterwards.
type RepoAction func(ctx context.Context, cmd *cli.Command, r *repo.Repo, config *config.ConfigRepository) error

// WithRepo adapts a RepoAction to cli/v3's ActionFunc. It loads the repo
// from the shared --sesam-dir / --identity / --lock-timeout flags, defers
// Close, and surfaces Close errors:
//   - if the handler succeeded, a Close error becomes the action's error
//   - if the handler already failed, a Close error is logged at warn
func WithRepo(action RepoAction) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) (err error) {
		r, err := repo.Load(
			cmd.String("sesam-dir"),
			cmd.StringSlice("identity"),
			repo.RepoOpts{
				Interactive: true,
				LockTimeout: cmd.Duration("lock-timeout"),
			},
		)
		if err != nil {
			return err
		}

		configRepo := config.NewConfigRepository()
		if err := configRepo.Load(cmd.String("config")); err != nil {
			return err
		}

		defer func() {
			if err := configRepo.Save(); err != nil {
				return
			}

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
		return action(ctx, cmd, r, configRepo)
	}
}

func printJSON(value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json output: %w", err)
	}

	fmt.Println(string(payload))
	return nil
}
