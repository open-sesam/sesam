package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
	user := cmd.String("user")

	recipients := cmd.StringSlice("recipient")
	if len(recipients) == 0 {
		return fmt.Errorf("missing recipient: pass --recipient")
	}

	groups := cmd.StringSlice("group")
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	if err := configRepo.Tell(user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user to config: %w", err)
	}

	return nil
	// return r.UserTell(ctx, user, recipients, groups)
}

// HandleKill removes a user/group relation.
func HandleKill(_ context.Context, cmd *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
	return r.UserKill(cmd.String("user"))
}
