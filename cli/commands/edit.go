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
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		return fmt.Errorf("EDITOR is not set")
	}
	// TODO: ADD SUPPORT FOR $VISUAL
	// TODO: look up that the path of the $EDITOR
	return r.EditSecret(paths[0], func(path string) error {
		editorCmd := exec.CommandContext(ctx, "exec $EDITOR \"$1\"", "sesam-editor", path)
		editorCmd.Env = append(os.Environ(), "EDITOR="+editor)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		return editorCmd.Run()
	}, cmd.Bool("seal-all"))
}
