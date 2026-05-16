package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// TODO: Show ascii logo on init

const keyringFingerprint = "sesam.identity.runtime"

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) (err error) {
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

	return withRepoLock(sesamDir, func() error {
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
			closeErr := mgr.Close()
			if closeErr == nil {
				return
			}

			if err != nil {
				err = fmt.Errorf("init: failed to close managers: %w", closeErr)
				return
			}

			slog.Warn("failed to close manager", slog.Any("error", closeErr))
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

		// TODO: fix pre-commit hook to verify and seal before commit.
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
			return mgr.Secret.AddSecret("README.md", []string{"admin"})
		}); err != nil {
			return fmt.Errorf("failed to bootstrap readme secret: %w", err)
		}

		if err := repo.EnsureTmpKeepFile(sesamDir); err != nil {
			return err
		}

		if err := mgr.Secret.SealAll(); err != nil {
			return err
		}

		if err := repo.StageInitFiles(sesamDir, configPath); err != nil {
			return err
		}

		return nil
	})
}

type initSecretManager struct {
	Secret *core.SecretManager

	auditLog *core.AuditLog
}

func (mgr *initSecretManager) Close() error {
	if mgr == nil || mgr.auditLog == nil {
		return nil
	}

	err := mgr.auditLog.Close()
	mgr.auditLog = nil
	return fmt.Errorf("failed to close audit log: %w", err)
}

// buildInitialSecretManager bootstraps audit/keyring state for init-time actions.
func buildInitialSecretManager(
	ctx context.Context,
	sesamDir string,
	initialUser string,
	pubKeySpecs []string,
	identities core.Identities,
) (*initSecretManager, error) {
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

	return &initSecretManager{
		Secret:   mgr,
		auditLog: auditLog,
	}, nil
}
