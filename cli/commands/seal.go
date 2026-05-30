package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleSeal encrypts and signs tracked secrets via SecretManager.SealAll.
func HandleSeal(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), cmd.Duration("lock-timeout"), core.NewInteractivePluginUI(), func(mgr *runtimeManagers) error {
		if err := mgr.Secret.SealAll(); err != nil {
			return fmt.Errorf("failed to seal secrets: %w", err)
		}

		if cmd.Bool("clean") {
			if err := deleteRevealedSecrets(sesamDir, mgr.Secret.State.Secrets); err != nil {
				return fmt.Errorf("failed to delete revealed secrets: %w", err)
			}
		}

		return nil
	})
}
