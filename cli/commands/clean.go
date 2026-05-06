package commands

import (
	"context"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleClean removes every file under the sesam directory that git does not
// track. Stale revealed plaintext from earlier checkouts disappears, leaving
// the worktree ready for a fresh smudge pass.
func HandleClean(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	repo, err := clirepo.OpenGitRepo(sesamDir)
	if err != nil {
		return err
	}

	return clirepo.Cleanup(repo, sesamDir)
}
