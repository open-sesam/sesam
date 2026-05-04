package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

const keyringFingerprint = "sesam.identity.runtime"

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	if err := repo.IsInitialized(sesamDir); err != nil {
		return err
	}

	if err := repo.EnsureInitPathChoice(sesamDir, cmd.Bool("use-root")); err != nil {
		return err
	}

	initialUser := strings.TrimSpace(cmd.String("user"))
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	if err := core.ValidUserName(initialUser); err != nil {
		return fmt.Errorf("invalid initial user %q: %w", initialUser, err)
	}

	identities, err := loadIdentities(
		cmd.StringSlice("identity"),
		"sesam.id."+initialUser,
	)
	if err != nil {
		return err
	}

	if err := repo.EnsureSesamDirs(sesamDir); err != nil {
		return err
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		configPath := repo.ResolveConfigPath(sesamDir, cmd.String("config"), cmd.IsSet("config"))
		if err := repo.CreateInitialConfig(
			configPath,
			initialUser,
			identities.RecipientStrings(),
		); err != nil {
			return err
		}

		mgr, err := buildInitialSecretManager(
			ctx,
			sesamDir,
			initialUser,
			identities.RecipientStrings(),
			identities,
		)
		if err != nil {
			return err
		}
		defer func() {
			_ = mgr.AuditLog.Close()
		}()

		if err := repo.EnsureDefaultGitIgnore(sesamDir); err != nil {
			return err
		}

		if err := repo.EnsureDefaultGitAttributes(sesamDir); err != nil {
			return err
		}

		if err := repo.EnsureGitConfigAt(sesamDir); err != nil {
			return err
		}

		// TODO: Commented out until this actually works.
		// if err := repo.EnsureVerifyHook(sesamDir); err != nil {
		// 	return err
		// }

		if err := repo.EnsureGitSesamShim(sesamDir); err != nil {
			return err
		}

		if err := repo.EnsureSesamReadme(sesamDir); err != nil {
			return err
		}

		if err := repo.WithWorkingDir(sesamDir, func() error {
			return mgr.AddSecret("README.md", []string{"admin"})
		}); err != nil {
			return fmt.Errorf("failed to bootstrap readme secret: %w", err)
		}

		if err := repo.EnsureTmpKeepFile(sesamDir); err != nil {
			return err
		}

		if err := mgr.SealAll(); err != nil {
			return err
		}

		if err := repo.StageInitFiles(sesamDir, configPath); err != nil {
			return err
		}

		return nil
	})
}

// buildInitialSecretManager bootstraps audit/keyring state for init-time actions.
func buildInitialSecretManager(
	ctx context.Context,
	sesamDir string,
	initialUser string,
	pubKeySpecs []string,
	identities core.Identities,
) (*core.SecretManager, error) {
	signer, auditLog, err := core.InitAdminUser(
		ctx,
		sesamDir,
		initialUser,
		pubKeySpecs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize admin user: %w", err)
	}

	keyring := core.EmptyKeyring()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	mgr, err := core.BuildSecretManager(
		sesamDir,
		identities,
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	return mgr, nil
}
