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

	user := strings.TrimSpace(cmd.String("user"))
	if user == "" {
		return fmt.Errorf("missing user: pass --user")
	}

	recipient := strings.TrimSpace(cmd.String("recipient"))
	if recipient == "" {
		return fmt.Errorf("missing recipient: pass --recipient")
	}

	groups := cmd.StringSlice("group")
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		mgr, auditLog, err := buildRegularUserManager(sesamDir, cmd.String("identity"))
		if err != nil {
			return err
		}
		defer func() {
			_ = auditLog.Close()
		}()

		if err := mgr.TellUser(ctx, user, recipient, groups); err != nil {
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
		mgr, auditLog, err := buildRegularUserManager(sesamDir, cmd.String("identity"))
		if err != nil {
			return err
		}
		defer func() {
			_ = auditLog.Close()
		}()

		if err := mgr.KillUsers(user); err != nil {
			return fmt.Errorf("failed to remove user: %w", err)
		}

		return nil
	})
}

func buildRegularUserManager(repoDir, identityPath string) (*core.UserManager, *core.AuditLog, error) {
	identities, err := loadIdentities(identityPath, "sesam.identity.runtime")
	if err != nil {
		return nil, nil, err
	}

	keyring := core.EmptyKeyring()
	auditLog, err := core.LoadAuditLog(repoDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		_ = auditLog.Close()
		return nil, nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	whoami, signIdentity, err := identityToUser(identities, keyring.ListUsers())
	if err != nil {
		_ = auditLog.Close()
		return nil, nil, fmt.Errorf("failed to map identity to user: %w", err)
	}

	signer, err := core.LoadSignKey(repoDir, whoami, signIdentity)
	if err != nil {
		_ = auditLog.Close()
		return nil, nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	mgr, err := core.BuildUserManager(repoDir, signer, auditLog, vstate)
	if err != nil {
		_ = auditLog.Close()
		return nil, nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	return mgr, auditLog, nil
}
