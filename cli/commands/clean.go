package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleClean removes every file under the sesam directory that git does not
// track. Stale revealed plaintext from earlier checkouts disappears, leaving
// the worktree ready for a fresh smudge pass.
//
// Clean does not load the audit log or take the repo lock — it must work
// even when the audit state is partially broken.
func HandleClean(ctx context.Context, cmd *cli.Command) error {
	dryRun := cmd.Bool("dry-run")
	quiet := cmd.Bool("quiet")

	return repo.CleanAggressive(
		ctx,
		cmd.String("sesam-dir"),
		cmd.StringSlice("identity"),
		repo.CleanOpts{
			Aggressive: cmd.Bool("aggressive"),
			CheckFunc: func(path string) (bool, error) {
				if !quiet {
					fmt.Println(path)
				}
				return !dryRun, nil
			},
		},
	)
}
