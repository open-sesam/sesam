package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
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

	return clirepo.Cleanup(repo, sesamDir, cmd.StringSlice("identity")...)
}

// TODO: Figure out where this is used?
func deleteRevealedSecrets(sesamDir string, secrets []core.VerifiedSecret) error {
	for _, secret := range secrets {
		revealedPath := filepath.Join(sesamDir, secret.RevealedPath)
		if err := os.Remove(revealedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to delete %s: %w", secret.RevealedPath, err)
		}
	}

	return nil
}
