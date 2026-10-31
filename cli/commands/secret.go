package commands

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if !cmd.Args().Present() {
		return fmt.Errorf("need at least one path")
	}

	groups, additive, err := resolveGroups(cmd, false)
	if err != nil {
		return err
	}
	if len(groups) == 0 && !additive {
		printInfo("no groups specified, assuming `--group admin` - only admins can decrypt!")
	}

	paths, err := toRepoPaths(r.SesamDir(), cmd.Args().Slice())
	if err != nil {
		return err
	}

	noSeal := cmd.Bool("no-seal")
	nested := cmd.Bool("nested")
	return r.Update(func(s *repo.Stage) error {
		if err := s.SecretAdd(paths, groups, additive, nested); err != nil {
			return err
		}
		if noSeal {
			return nil
		}

		return sealStage(cmd, r, s)
	})
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	paths, err := toRepoPaths(r.SesamDir(), cmd.Args().Slice())
	if err != nil {
		return err
	}

	force := cmd.Bool("force")
	noSeal := cmd.Bool("no-seal")

	// Only the plaintext of the removed secrets: the argument may be a
	// directory that also holds files sesam does not manage.
	root, err := os.OpenRoot(r.SesamDir())
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	secrets, err := r.ListSecrets(paths)
	if err != nil {
		return err
	}

	// Checked before anything is committed, so a refusal changes nothing.
	removed := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if err := core.NoSymlinks(root, secret.RevealedPath); err != nil {
			return fmt.Errorf("refusing to remove plaintext: %w", err)
		}
		removed = append(removed, secret.RevealedPath)
	}

	if !force && len(removed) > 0 {
		// Edited or never sealed plaintext is the only copy of its content.
		opts := syncOpts(r.SesamDir())
		opts.Paths = removed
		states, err := r.SyncStates(opts)
		if err != nil {
			return err
		}

		if unsealed := states.Paths(repo.SecretStateNotInSync, repo.SecretStateDiverged, repo.SecretStateNoSealedPath); len(unsealed) > 0 {
			printNote(
				fmt.Sprintf("refusing to remove %d unsealed %s:", len(unsealed), pluralize("secret", len(unsealed))),
				unsealed,
				"`sesam seal` keeps the edits in history, `sesam rm --force` deletes them.",
			)
			return fmt.Errorf("plaintext has unsealed changes")
		}
	}

	if err := r.Update(func(s *repo.Stage) error {
		if err := s.SecretRemove(paths); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return sealStage(cmd, r, s)
	}); err != nil {
		return err
	}

	for _, p := range removed {
		if err := root.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove plaintext %s: %w", p, err)
		}
	}

	return nil
}

func HandleMove(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	oldRevealedPath := cmd.StringArg("oldpath")
	newRevealedPath := cmd.StringArg("newpath")

	if oldRevealedPath == "" || newRevealedPath == "" {
		return fmt.Errorf("need <old> and <new>")
	}

	paths, err := toRepoPaths(r.SesamDir(), []string{oldRevealedPath, newRevealedPath})
	if err != nil {
		return err
	}

	nested := cmd.Bool("nested")

	// move always needs a seal, otherwise state is pretty broken
	return r.Update(func(s *repo.Stage) error {
		if err := s.SecretMove(paths[0], paths[1], nested); err != nil {
			return err
		}
		return sealStage(cmd, r, s)
	})
}
