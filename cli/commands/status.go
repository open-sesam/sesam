package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func printDirectoryDiff(ctx context.Context, status *repo.Status) error {
	// TODO: Check for git and print a nicer message if not present.
	// defer os.RemoveAll(status.DiffDir)
	os.Chdir(status.DiffDir)
	cmd := exec.CommandContext(
		ctx,
		"git",
		"diff",
		"--no-index",
		"--color=auto",
		"--",
		"sealed",
		"revealed",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return err
		}

		if exitErr.ProcessState.ExitCode() == 1 {
			// if there's a diff it will exit with 1
			return nil
		}

		return err
	}

	return nil
}

func HandleStatus(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	status, err := r.Status(repo.StatusOpts{
		WriteDiffDirs: cmd.Bool("diff"),
	})
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(status)
	}

	if cmd.Bool("diff") {
		return printDirectoryDiff(ctx, status)
	}

	output := termenv.NewOutput(os.Stdout)

	header := "DIFF REVEALED vs. SEALED"
	t := newTable(header, "Path", "State")
	s := t.Style()
	s.Size.WidthMin = len(header) + 5

	for _, file := range status.Files {
		var desc string
		switch file.State {
		case repo.SecretStateNoSealedPath:
			desc = output.String("unsealed").Foreground(output.Color("#FFFF00")).String()
		case repo.SecretStateNoRevealedPath:
			desc = output.String("unrevealed").Foreground(output.Color("#00FFFF")).String()
		case repo.SecretStateUserHasNoAccess:
			desc = output.String("no access").Foreground(output.Color("#FF00FF")).String()
		case repo.SecretStateSameContent:
			desc = output.String("same").Foreground(output.Color("#00FF00")).String()
		case repo.SecretStateDifferentContent:
			desc = output.String("diff").Foreground(output.Color("#FF0000")).String()
		default:
			desc = output.String("undefined").Foreground(output.Color("#800000")).String()
		}

		t.AppendRow([]any{file.RevealedPath, desc})
	}

	t.AppendFooter([]any{
		"",
		fmt.Sprintf(
			"%d %s",
			len(status.Files),
			pluralize("secret", len(status.Files)),
		),
	})
	t.Render()

	return nil
}
