package commands

import (
	"context"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

func HandleOpen(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.Reveal(cmd.Bool("all"))
}
