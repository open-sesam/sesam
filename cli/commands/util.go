package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	json "github.com/neilotoole/jsoncolor"

	"github.com/mattn/go-colorable"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// RepoAction is the signature every handler that needs a live sesam Repo
// uses. The Repo is loaded (lock + managers) by WithRepo before the handler
// runs and is closed afterwards.
type RepoAction func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error

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
		return action(ctx, cmd, r)
	}
}

func printJSON(value any) error {
	out := colorable.NewColorable(os.Stdout) // needed for Windows
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	// IsColorTerminal checks NO_COLOR env variable
	if json.IsColorTerminal(os.Stdout) {
		colors := json.DefaultColors()
		enc.SetColors(colors)
	}

	return enc.Encode(value)
}

func printInfo(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}
