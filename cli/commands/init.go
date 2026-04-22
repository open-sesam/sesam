package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) error {
	repoRoot, err := clirepo.ResolveRepoRoot(cmd.String("repo"))
	if err != nil {
		return err
	}

	if err := clirepo.EnsureNotInitialized(repoRoot); err != nil {
		return err
	}

	if err := clirepo.EnsureInitPathChoice(repoRoot, cmd.Bool("use-root")); err != nil {
		return err
	}

	initialUser := strings.TrimSpace(cmd.String("user"))
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	if err := core.ValidUserName(initialUser); err != nil {
		return fmt.Errorf("invalid initial user %q: %w", initialUser, err)
	}

	identities, err := loadIdentities(cmd.String("identity"), "sesam.id."+initialUser)
	if err != nil {
		return err
	}

	_, recipientText, err := resolveInitialRecipient(ctx, cmd.String("recipient"), repoRoot, identities)
	if err != nil {
		return err
	}

	if err := clirepo.EnsureSesamDirs(repoRoot); err != nil {
		return err
	}

	return withRepoLock(repoRoot, 5*time.Second, func() error {
		configPath := clirepo.ResolveConfigPath(repoRoot, cmd.String("config"), cmd.IsSet("config"))
		if err := clirepo.CreateInitialConfig(configPath, initialUser, recipientText); err != nil {
			return err
		}

		mgr, err := buildInitialSecretManager(
			ctx,
			repoRoot,
			initialUser,
			recipientText,
			identities,
		)
		if err != nil {
			return err
		}
		defer func() {
			_ = mgr.AuditLog.Close()
		}()

		if err := clirepo.EnsureDefaultGitIgnore(repoRoot); err != nil {
			return err
		}

		if err := clirepo.EnsureDefaultGitAttributes(repoRoot); err != nil {
			return err
		}

		if err := clirepo.EnsureVerifyHook(repoRoot); err != nil {
			return err
		}

		if err := clirepo.EnsureGitSesamShim(repoRoot); err != nil {
			return err
		}

		if err := clirepo.EnsureExampleSecret(repoRoot); err != nil {
			return err
		}

		if err := clirepo.WithWorkingDir(repoRoot, func() error {
			return mgr.AddSecret("example.secret", []string{"admin"})
		}); err != nil {
			return fmt.Errorf("failed to bootstrap example secret: %w", err)
		}

		if err := clirepo.EnsureSesamReadme(repoRoot); err != nil {
			return err
		}

		if err := clirepo.EnsureTmpKeepFile(repoRoot); err != nil {
			return err
		}

		if err := clirepo.StageInitFiles(repoRoot, configPath); err != nil {
			return err
		}

		return nil
	})
}

// resolveInitialRecipient determines the initial admin recipient key.
func resolveInitialRecipient(ctx context.Context, recipientArg string, repoRoot string, identities core.Identities) (age.Recipient, string, error) {
	recipientArg = strings.TrimSpace(recipientArg)

	var resolved core.Recipients
	if recipientArg != "" {
		rawRecipient, err := core.ResolveRecipient(ctx, repoRoot, recipientArg, core.CacheModeReadWrite)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve recipient %q: %w", recipientArg, err)
		}

		resolved, err = core.ParseRecipients(rawRecipient)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse recipient %q: %w", recipientArg, err)
		}
	}

	if len(resolved) > 0 {
		for _, recipient := range resolved {
			for _, identity := range identities {
				if identityCanDecryptRecipient(identity, recipient.Recipient) {
					return recipient.Recipient, recipient.String(), nil
				}
			}
		}

		return nil, "", fmt.Errorf("none of the resolved recipients matches the selected identity")
	}

	recipient, err := core.ParseRecipient(identities[0].Public().String())
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive recipient from identity: %w", err)
	}

	return recipient.Recipient, identities[0].Public().String(), nil
}

// identityCanDecryptRecipient checks if identity corresponds to recipient.
func identityCanDecryptRecipient(identity *core.Identity, recipient age.Recipient) bool {
	const probe = "sesam-init-match"

	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return false
	}

	if _, err := w.Write([]byte(probe)); err != nil {
		return false
	}

	if err := w.Close(); err != nil {
		return false
	}

	r, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), identity)
	if err != nil {
		return false
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return false
	}

	return string(decrypted) == probe
}

// buildInitialSecretManager bootstraps audit/keyring state for init-time actions.
func buildInitialSecretManager(
	ctx context.Context,
	repoRoot string,
	initialUser string,
	recipientText string,
	identities core.Identities,
) (*core.SecretManager, error) {
	signer, auditLog, err := core.InitAdminUser(ctx, repoRoot, initialUser, recipientText)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize admin user: %w", err)
	}

	keyring := core.EmptyKeyring()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	mgr, err := core.BuildSecretManager(
		repoRoot,
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
