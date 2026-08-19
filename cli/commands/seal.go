package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleSeal encrypts and signs tracked secrets via a staged seal commit.
//
// Conflict markers are warned about, not refused: seal is what you reach for to
// get out of a half-finished merge, so refusing would be the bigger trap.
func HandleSeal(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	conflicted, err := r.ConflictedSecrets()
	if err != nil {
		return err
	}

	if len(conflicted) > 0 {
		fmt.Fprintf(
			os.Stderr,
			"sesam: WARNING: sealing %d %s with unresolved conflicts - the markers are being encrypted as-is:\n%s\n",
			len(conflicted),
			pluralize("secret", len(conflicted)),
			strings.Join(conflictedSecretHints(conflicted), "\n"),
		)
	}

	if err := r.Update(func(s *repo.Stage) error {
		return s.Seal(cmd.Bool("seal-all"))
	}); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		return r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
		})
	}

	return nil
}
