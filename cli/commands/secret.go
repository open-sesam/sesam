package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if !cmd.Args().Present() {
		return fmt.Errorf("need at least one path")
	}

	groups := cmd.StringSlice("group")
	if len(groups) == 0 {
		printInfo("no groups specified, assuming `--group admin` only - only admins can decrypt")
	}

	paths, err := toRepoPaths(r.SesamDir(), cmd.Args().Slice())
	if err != nil {
		return err
	}

	if err := r.SecretAdd(paths, groups, cmd.Bool("nested")); err != nil {
		return err
	}

	if cmd.Bool("no-seal") {
		return nil
	}

	return r.SealAll()
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

	if err := r.SecretRemove(paths); err != nil {
		return err
	}

	return r.SealAll()
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

	if err := r.SecretMove(paths[0], paths[1]); err != nil {
		return err
	}

	// move always needs an seal, otherwise state is pretty broken
	return r.SealAll()
}
