package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	user := cmd.String("user")
	if user == "" {
		return fmt.Errorf("missing user: pass --user")
	}

	recipients := cmd.StringSlice("recipient")
	if len(recipients) == 0 {
		return fmt.Errorf("missing recipient: pass --recipient")
	}

	groups := cmd.StringSlice("group")
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		identityPaths := cmd.StringSlice("identity")
		// TODO: close audit log
		_, usrMgr, err := buildManagers(sesamDir, identityPaths, core.NewInteractivePluginUI())
		if err != nil {
			return fmt.Errorf(" failed to load secret manager: %w", err)
		}

		if err := usrMgr.TellUser(ctx, user, recipients, groups); err != nil {
			return fmt.Errorf("failed to add user: %w", err)
		}

		return nil
	})
}

// HandleKill removes a user/group relation.
func HandleKill(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	user := strings.TrimSpace(cmd.String("user"))
	if user == "" {
		return fmt.Errorf("missing user: pass --user")
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		_, usrMgr, err := buildManagers(sesamDir, cmd.StringSlice("identity"), core.NewInteractivePluginUI())
		if err != nil {
			return err
		}

		if err := usrMgr.KillUsers(user); err != nil {
			return fmt.Errorf("failed to remove user: %w", err)
		}

		return nil
	})
}
