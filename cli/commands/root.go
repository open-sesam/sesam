package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	whoami, err := r.Whoami()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		users, err := r.ListUsers()
		if err != nil {
			return err
		}

		for _, user := range users {
			if user.Name == whoami {
				return printJSON(user)
			}
		}

		return fmt.Errorf("%s not in user list?", whoami)
	}

	fmt.Println(whoami)
	return nil
}

func HandleKeyringClearCache(_ context.Context, _ *cli.Command) error {
	return core.DeleteAllCachedPassphrases()
}
