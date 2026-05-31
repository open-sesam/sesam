package commands

import (
	"context"
	"os"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleShow decrypts a secret and writes it to stdout.
func HandleShow(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	// TODO: Options to either force resolution as audit, user, secret, ...
	return r.Show(cmd.StringArg("object"), os.Stdout)
}
