package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

func cleanCheck(path string, quiet, dryRun bool) (bool, error) {
	if !quiet {
		fmt.Println(path)
	}
	return !dryRun, nil
}

// HandleClean removes every file under the sesam directory that git does not
// track. Stale revealed plaintext from earlier checkouts disappears, leaving
// the worktree ready for a fresh smudge pass.
//
// Clean does not load the audit log or take the repo lock — it must work
// even when the audit state is partially broken.
//
// With --aggressive, untracked files inside `.sesam/` are removed too
// (similar to `git clean -fdx`). Without it, `.sesam/` is left alone.
func HandleClean(ctx context.Context, cmd *cli.Command) error {
	dryRun := cmd.Bool("dry-run")
	quiet := cmd.Bool("quiet")

	opts := repo.CleanOpts{
		CheckFunc: func(path string) (bool, error) {
			return cleanCheck(path, quiet, dryRun)
		},
	}

	if cmd.Bool("aggressive") {
		return repo.CleanAggressive(
			ctx,
			cmd.String("sesam-dir"),
			cmd.StringSlice("identity"),
			opts,
		)
	}

	return WithRepo(HandleCleanWithRepo)(ctx, cmd)
}

func HandleCleanWithRepo(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	dryRun := cmd.Bool("dry-run")
	quiet := cmd.Bool("quiet")

	return r.Clean(ctx, repo.CleanOpts{
		Aggressive: false,
		CheckFunc: func(path string) (bool, error) {
			return cleanCheck(path, quiet, dryRun)
		},
	})
}
