package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

func HandleEditSecret(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	paths, err := toRepoPaths(r.SesamDir(), []string{revealedPath})
	if err != nil {
		return err
	}

	editor := cmd.String("editor")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		return fmt.Errorf("neither VISUAL nor EDITOR is set")
	}
	editorPath, err := exec.LookPath(editor)
	if err != nil {
		return fmt.Errorf("find editor %q: %w", editor, err)
	}

	return r.EditSecret(paths[0], func(path string) error {
		// #nosec G204,G702 -- editorPath was explicitly configured and resolved with LookPath.
		editorCmd := exec.CommandContext(ctx, editorPath, path)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		return editorCmd.Run()
	}, cmd.Bool("seal-all"))
}
