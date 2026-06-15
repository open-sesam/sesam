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

	return r.UserTell(ctx, user, recipients, groups)
}

// HandleKill removes a user/group relation.
func HandleKill(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.UserKill(cmd.String("user"))
}
