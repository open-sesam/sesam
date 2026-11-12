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
	if cmd.Bool("seal-all") && cmd.Args().Present() {
		return errors.New("--all seals every secret, it takes no paths")
	}

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

	paths, err := toRepoPaths(r.SesamDir(), cmd.Args().Slice())
	if err != nil {
		return err
	}

	opts := repo.SealOpts{
		All:           cmd.Bool("seal-all"),
		Sync:          syncOpts(ctx, r.SesamDir()),
		Paths:         paths,
		ForceStale:    cmd.Bool("force-stale"),
		ForceDiverged: cmd.Bool("force-diverged"),
	}

	if err := r.Update(func(s *repo.Stage) error {
		return sealWith(ctx, s, opts)
	}); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		res, err := r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
			Sync:       syncOpts(ctx, r.SesamDir()),
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
func sealStage(ctx context.Context, cmd *cli.Command, r *repo.Repo, s *repo.Stage) error {
	return sealWith(ctx, s, repo.SealOpts{
		All:  cmd.Bool("seal-all"),
		Sync: syncOpts(ctx, r.SesamDir()),
	})
}

func sealWith(ctx context.Context, s *repo.Stage, opts repo.SealOpts) error {
	res, err := s.Seal(ctx, opts)
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

	pluralizedSecret := pluralize("secret", len(res.Stale))
	verb, pronoun := "were", "they are"
	if len(res.Stale) == 1 {
		verb, pronoun = "was", "it is"
	}

	printNote(
		fmt.Sprintf(
			"%d stale %s %s not sealed because %s newer than what is revealed:",
			len(res.Stale), pluralizedSecret, verb, pronoun,
		),
		res.Stale,
		fmt.Sprintf(
			"This happens when git brought in a newer version but nothing revealed it, e.g. a `git pull` without sesam's hooks installed.\n"+
				"sesam: Please decide: `sesam reveal` takes the newer %s, `sesam seal <path>` (or `--force-stale` for all) seals your %s anyway.",
			pluralizedSecret,
			pluralizedSecret,
		),
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
