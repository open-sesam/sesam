package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func guessUserNameFromForgeID(recps []string) (string, error) {
	for _, recp := range recps {
		for _, prefix := range core.SupportedForges {
			if strings.HasPrefix(recp, prefix+":") {
				_, user, _ := strings.Cut(recp, ":")
				fmt.Printf("guessed '--user %s' from %s\n", user, recp)
				return user, nil
			}
		}
	}

	return "", fmt.Errorf("failed to guess user name - please pass --user")
}

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	recipients := cmd.StringSlice("recipient")
	groups := cmd.StringSlice("group")
	user := cmd.String("user")
	if user == "" {
		var err error
		user, err = guessUserNameFromForgeID(recipients)
		if err != nil {
			return err
		}
	}

	if err := r.UserTell(ctx, user, recipients, groups); err != nil {
		return err
	}

	if cmd.Bool("no-seal") {
		return nil
	}

	return r.SealAll()
}

func HandleKill(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if err := r.UserKill(cmd.String("user")); err != nil {
		return err
	}

	if cmd.Bool("no-seal") {
		return nil
	}

	return r.SealAll()
}

func HandleUserChangeGroups(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	err := r.UserChangeGroups(cmd.String("user"), cmd.StringSlice("group"))
	if err != nil {
		return err
	}

	if cmd.Bool("no-seal") {
		return nil
	}

	return r.SealAll()
}

func HandleRenameUser(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	oldName := cmd.StringArg("old")
	newName := cmd.StringArg("new")
	if oldName == "" || newName == "" {
		return fmt.Errorf("need <old> and <new>")
	}

	return r.RenameUser(oldName, newName)
}
