package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	shellquote "github.com/kballard/go-shellquote"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

func HandleEditSecret(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Args().Len() != 1 {
		return fmt.Errorf("edit takes exactly one secret path, got %d", cmd.Args().Len())
	}
	revealedPath := cmd.Args().First()

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
	// Editors are commonly configured with arguments, e.g. "code --wait".
	editorArgs, err := shellquote.Split(editor)
	if err != nil {
		return fmt.Errorf("parse editor %q: %w", editor, err)
	}
	if len(editorArgs) == 0 {
		return fmt.Errorf("editor %q holds no command", editor)
	}
	editorPath, err := exec.LookPath(editorArgs[0])
	if err != nil {
		return fmt.Errorf("find editor %q: %w", editor, err)
	}

	return r.EditSecret(paths[0], func(path string) error {
		// #nosec G204,G702 -- editorPath was explicitly configured and resolved with LookPath.
		editorCmd := exec.CommandContext(ctx, editorPath, append(editorArgs[1:], path)...)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		return editorCmd.Run()
	}, repo.SealOpts{All: cmd.Bool("seal-all"), Sync: syncOpts(r.SesamDir())})
}
