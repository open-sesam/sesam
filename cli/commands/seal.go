package commands

import (
	"context"
	"errors"
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
		return sealStage(cmd, r, s)
	}); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		res, err := r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
			Sync:       syncOpts(r.SesamDir()),
		})
		if err != nil {
			return err
		}

		printKeptClean(res)
	}

	return nil
}

// sealStage is the seal every mutating command ends with. Stale plaintext is
// left out and named; a secret changed on both sides stops the command and
// names both ways out.
func sealStage(cmd *cli.Command, r *repo.Repo, s *repo.Stage) error {
	res, err := s.Seal(repo.SealOpts{
		All:  cmd.Bool("seal-all"),
		Sync: syncOpts(r.SesamDir()),
	})
	if err != nil {
		var diverged *repo.DivergedError
		if errors.As(err, &diverged) {
			return fmt.Errorf("%w\n"+waysOut, err)
		}

		return err
	}

	printSkippedStale(res)
	return nil
}

// printSkippedStale names the objects seal left alone because they are newer
// than the plaintext beside them - after a pull or checkout without hooks,
// typically. Sealing would have written the old plaintext back over them.
func printSkippedStale(res *repo.SealResult) {
	if len(res.Stale) == 0 {
		return
	}

	printNote(
		fmt.Sprintf(
			"%d stale %s not sealed - the object is newer than the plaintext:",
			len(res.Stale), pluralize("secret", len(res.Stale)),
		),
		res.Stale,
		"`sesam reveal` refreshes the plaintext, `sesam seal --all` seals your version anyway.",
	)
}

// printKeptClean names the plaintext clean left alone: edited since it was last
// sealed, or never sealed - deleting it would lose the only copy.
func printKeptClean(res *repo.CleanResult) {
	if len(res.Kept) == 0 {
		return
	}

	printNote(
		fmt.Sprintf("kept %d edited or unsealed %s:", len(res.Kept), pluralize("secret", len(res.Kept))),
		res.Kept,
		"`sesam seal` writes them into their objects, `sesam clean --unsealed` deletes them.",
	)
}
