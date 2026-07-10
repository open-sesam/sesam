package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
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
		printInfo("no groups specified, assuming `--group admin` only - only admins can decrypt")
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

		return s.Seal(cmd.Bool("seal-all"))
	})
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	paths, err := toRepoPaths(r.SesamDir(), []string{revealedPath})
	if err != nil {
		return err
	}

	if err := r.Update(func(s *repo.Stage) error {
		if err := s.SecretRemove(paths); err != nil {
			return err
		}
		return s.Seal(cmd.Bool("seal-all"))
	}); err != nil {
		return err
	}

	if !cmd.Bool("force") {
		return nil
	}

	return os.RemoveAll(revealedPath)
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
		return s.Seal(cmd.Bool("seal-all"))
	})
}
