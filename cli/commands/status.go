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

	if err := os.Chdir(status.DiffDir); err != nil {
		return err
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
		WriteDiffDirs:    cmd.Bool("diff"),
		SortByState:      cmd.Bool("sort-by-state"),
		IgnoreUnamanaged: cmd.Bool("ignore-unmanaged"),
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
		case repo.SecretStateNoSesamSecret:
			desc = output.String("no sesam file").Foreground(output.Color("#FF8800")).String()
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
