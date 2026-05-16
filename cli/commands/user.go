package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	user := cmd.String("user")

	recipients := cmd.StringSlice("recipient")
	if len(recipients) == 0 {
		return fmt.Errorf("missing recipient: pass --recipient")
	}

	groups := cmd.StringSlice("group")
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), func(mgr *runtimeManagers) error {
		if err := mgr.User.TellUser(ctx, user, recipients, groups); err != nil {
			return fmt.Errorf("failed to add user: %w", err)
		}

		return mgr.Secret.SealAll()
	})
}

// HandleKill removes a user/group relation.
func HandleKill(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	user := strings.TrimSpace(cmd.String("user"))

	return withManagers(sesamDir, cmd.StringSlice("identity"), func(mgr *runtimeManagers) error {
		if err := mgr.User.KillUsers(user); err != nil {
			return fmt.Errorf("failed to remove user: %w", err)
		}

		return mgr.Secret.SealAll()
	})
}
