package commands

import (
	"context"
	"fmt"
	"time"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleAddSecret adds a secret path to sesam metadata.
func HandleAddSecret(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	path := cmd.String("path")
	groups := cmd.StringSlice("access")
	// secret := config.Secret{
	// 	SecretType:  config.SecretType(cmd.String("type")),
	// 	Name:        cmd.String("name"),
	// 	Path:        path,
	// 	Access:      groups,
	// 	Description: cmd.String("description"),
	// }

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		identityPaths := cmd.StringSlice("identity")
		// TODO: close audit log
		secMgr, _, err := buildManagers(sesamDir, identityPaths)
		if err != nil {
			return fmt.Errorf(" failed to load secret manager: %w", err)
		}

		if err := secMgr.AddSecret(path, groups); err != nil {
			return fmt.Errorf(" failed to add secret: %w", err)
		}

		return secMgr.SealAll()
	})
}

// HandleRemoveSecret removes a secret path from sesam metadata.
func HandleRemoveSecret(_ context.Context, _ *cli.Command) error {
	return handleStub("modify rm")
}

// HandleMove renames or relocates a tracked secret path.
func HandleMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

// HandleList prints tracked secret metadata.
func HandleList(_ context.Context, _ *cli.Command) error {
	return handleStub("modify ls")
}

func HandleRead(_ context.Context, _ *cli.Command) error {
	return nil

	//return handleStub("modify read")
}
