package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleReveal decrypts and verifies tracked secrets via SecretManager.RevealAll.
func HandleReveal(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), cmd.Duration("lock-timeout"), func(mgr *runtimeManagers) error {
		if err := mgr.Secret.RevealAll(); err != nil {
			return fmt.Errorf("failed to reveal secrets: %w", err)
		}

		return nil
	})
}
