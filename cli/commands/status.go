package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func HandleStatus(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Bool("diff") {
		return fmt.Errorf("not yet implemented")
	}

	status, err := r.Status()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(status)
	}

	output := termenv.NewOutput(os.Stdout)

	t := newTable("Difference between revealed and sealed", "State", "Path")
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
