package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func printDirectoryDiff(ctx context.Context, status *repo.Status) error {
	defer func() {
		if err := os.RemoveAll(status.DiffDir); err != nil {
			slog.Error("failed to remove diff dir", slog.Any("err", err))
		}
	}()

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("failed to find git in PATH - required for this command")
	}

	// We have to call git directly here, as the user might have configured git tooling of his liking.
	cmd := exec.CommandContext(
		ctx,
		"git",
		"diff",
		"--no-index",
		"--color=auto",
		"--",
		"sealed/",
		"revealed/",
	)
	cmd.Dir = status.DiffDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 {
				// if there's a diff it will exit with 1
				return nil
			}
		}

		return err
	}

	return nil
}

func HandleStatus(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	status, err := r.Status(repo.StatusOpts{
		WriteDiffDirs:   cmd.Bool("diff"),
		SortByState:     cmd.Bool("sort-by-state"),
		IgnoreUnmanaged: cmd.Bool("ignore-unmanaged"),
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

	// NOTE: Maybe we want rather a "git status" like output here...
	for _, file := range status.Files {
		var color string
		switch file.State {
		case repo.SecretStateNoSealedPath:
			color = "#FFF000"
		case repo.SecretStateNoRevealedPath:
			color = "#00FFFF"
		case repo.SecretStateUserHasNoAccess:
			color = "#FF00FF"
		case repo.SecretStateSameContent:
			color = "#00FF00"
		case repo.SecretStateDifferentContent:
			color = "#FF0000"
		case repo.SecretStateNoSesamSecret:
			color = "#FF8800"
		default:
			color = "#800000"
		}

		desc := output.String(file.State.String()).Foreground(output.Color(color)).String()
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
