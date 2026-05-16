package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleSeal encrypts and signs tracked secrets via SecretManager.SealAll.
func HandleSeal(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		mgr, _, err := buildManagers(sesamDir, cmd.StringSlice("identity"), core.NewInteractivePluginUI())
		if err != nil {
			return err
		}

		if err := mgr.SealAll(); err != nil {
			return fmt.Errorf("failed to seal secrets: %w", err)
		}

		return nil
	})
}

// HandleReveal decrypts and verifies tracked secrets via SecretManager.RevealAll.
func HandleReveal(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		mgr, _, err := buildManagers(sesamDir, cmd.StringSlice("identity"), core.NewInteractivePluginUI())
		if err != nil {
			return err
		}

		if err := mgr.RevealAll(); err != nil {
			return fmt.Errorf("failed to reveal secrets: %w", err)
		}

		return nil
	})
}

// buildManagers initializes runtime state for non-init operations. pluginUI
// controls how age plugins prompt for user input (PIN, touch, etc.); pass
// core.NewInteractivePluginUI() for foreground commands and
// core.NewNonInteractivePluginUI() for git filter contexts.
func buildManagers(sesamDir string, identityPath []string, pluginUI *core.PluginUI) (*core.SecretManager, *core.UserManager, error) {
	identities, err := loadIdentities(
		identityPath,
		keyringFingerprint,
		pluginUI,
	)
	if err != nil {
		return nil, nil, err
	}

	keyring := core.EmptyKeyring()

	auditLog, err := core.LoadAuditLog(sesamDir, identities)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	verifyStart := time.Now()
	vstate, err := core.Verify(auditLog, keyring, pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	slog.Info("audit log verified", slog.Duration("duration", time.Since(verifyStart)))

	whoami, signIdentity, err := identityToUser(identities, keyring.ListUsers())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to map identity to user: %w", err)
	}

	slog.Info("resolved signer identity", slog.String("user", whoami))

	signer, err := core.LoadSignKey(sesamDir, whoami, signIdentity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	secMgr, err := core.BuildSecretManager(
		sesamDir,
		identities,
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	usrMgr, err := core.BuildUserManager(
		sesamDir,
		signer,
		auditLog,
		vstate,
		secMgr,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	// TODO: Find a better place to call this.
	// .git/config is not synced and needs to be constantly checked.
	if err := clirepo.EnsureGitConfigAt(sesamDir); err != nil {
		return nil, nil, err
	}

	return secMgr, usrMgr, nil
}

func identityToUser(identities core.Identities, users map[string]core.Recipients) (string, *core.Identity, error) {
	for _, identity := range identities {
		user, err := core.IdentityToUser(identity, users)
		if err == nil {
			return user, identity, nil
		}
	}

	return "", nil, fmt.Errorf("no loaded identity matches any known user")
}

// loadIdentities reads all given paths and parses all identities. Encrypted
// identities are unlocked via the system keyring, falling back to a stdin
// prompt when no entry exists. pluginUI is used when a path holds a plugin
// identity; pass core.NewInteractivePluginUI() for foreground commands.
func loadIdentities(identityPaths []string, keyFingerprint string, pluginUI *core.PluginUI) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, &core.KeyringPassphraseProvider{
		KeyFingerprint: keyFingerprint,
		Fallback:       &core.StdinPassphraseProvider{},
	}, pluginUI)
}

// loadIdentitiesKeyringOnly is like loadIdentities but never prompts on stdin.
// It is required for the long-running smudge filter, where stdin is owned by
// the git pkt-line protocol and a passphrase prompt would corrupt the stream.
// If the keyring has no entry for an encrypted identity, parsing fails.
// Plugin identities load successfully but will return ErrNoTTY on first use,
// which age.Decrypt skips so other identities still have a chance to work.
func loadIdentitiesKeyringOnly(identityPaths []string, keyFingerprint string) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, &core.KeyringPassphraseProvider{
		KeyFingerprint: keyFingerprint,
	}, core.NewNonInteractivePluginUI())
}

func loadIdentitiesWith(identityPaths []string, provider core.PassphraseProvider, pluginUI *core.PluginUI) (core.Identities, error) {
	if len(identityPaths) == 0 {
		return nil, fmt.Errorf("at least one --identity or SESAM_ID env var required")
	}

	identities := make(core.Identities, 0, len(identityPaths))
	for _, identityPath := range identityPaths {
		if strings.TrimSpace(identityPath) == "" {
			return nil, fmt.Errorf("missing identity path: pass --identity")
		}

		expandedPath, err := expandHomeDir(identityPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve identity path: %w", err)
		}

		const maxIdentityFileBytes = 1024 * 1024
		data, err := core.ReadFileLimited(expandedPath, maxIdentityFileBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity %s: %w", expandedPath, err)
		}

		identity, err := core.ParseIdentity(strings.TrimSpace(string(data)), provider, pluginUI)
		if err != nil {
			return nil, err
		}

		identities = append(identities, identity)
	}

	return identities, nil
}
