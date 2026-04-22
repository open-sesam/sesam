package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleSeal encrypts and signs tracked secrets via SecretManager.SealAll.
func HandleSeal(_ context.Context, cmd *cli.Command) error {
	repoRoot, err := resolveRepoRoot(cmd.String("repo"))
	if err != nil {
		return err
	}

	return withRepoLock(repoRoot, 5*time.Second, func() error {
		mgr, err := buildRegularSecretManager(repoRoot, cmd.String("identity"))
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
	repoRoot, err := resolveRepoRoot(cmd.String("repo"))
	if err != nil {
		return err
	}

	return withRepoLock(repoRoot, 5*time.Second, func() error {
		mgr, err := buildRegularSecretManager(repoRoot, cmd.String("identity"))
		if err != nil {
			return err
		}

		if err := mgr.RevealAll(); err != nil {
			return fmt.Errorf("failed to reveal secrets: %w", err)
		}

		return nil
	})
}

// buildRegularSecretManager initializes runtime state for non-init operations.
func buildRegularSecretManager(repoDir, identityPath string) (*core.SecretManager, error) {
	identity, identities, err := loadPrimaryIdentity(identityPath, "sesam.identity.runtime")
	if err != nil {
		return nil, err
	}

	keyring := core.EmptyKeyring()

	auditLog, err := core.LoadAuditLog(repoDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	verifyStart := time.Now()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	fmt.Println("verify took", time.Since(verifyStart))

	whoami, err := core.IdentityToUser(identity, keyring.ListUsers())
	if err != nil {
		return nil, fmt.Errorf("failed to map identity to user: %w", err)
	}

	fmt.Println("Who am I:", whoami)

	signer, err := core.LoadSignKey(repoDir, whoami, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	mgr, err := core.BuildSecretManager(
		repoDir,
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

// loadPrimaryIdentity parses identities from one key file and returns the first.
func loadPrimaryIdentity(identityPath, keyFingerprint string) (*core.Identity, core.Identities, error) {
	identities, err := loadIdentities(identityPath, keyFingerprint)
	if err != nil {
		return nil, nil, err
	}

	return identities[0], identities, nil
}

// loadIdentities reads one key file and parses all usable identity lines.
func loadIdentities(identityPath, keyFingerprint string) (core.Identities, error) {
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

	rawKey := strings.TrimSpace(string(data))
	if rawKey != "" {
		identity, err := core.ParseIdentity(rawKey, &core.KeyringPassphraseProvider{
			KeyFingerprint: keyFingerprint,
			Fallback:       &core.StdinPassphraseProvider{},
		})
		if err == nil {
			return core.Identities{identity}, nil
		}
	}

	// We allow multiple identities in one file because users may keep several
	// keys (for example key rotation or multiple devices) in age/ssh key files.
	// Command flows can then select the matching identity/recipient pair.
	var identities core.Identities
	for line := range strings.SplitSeq(string(data), "\n") {
		key := strings.TrimSpace(line)
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}

		identity, err := core.ParseIdentity(key, &core.KeyringPassphraseProvider{
			KeyFingerprint: keyFingerprint,
			Fallback:       &core.StdinPassphraseProvider{},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse identity %s: %w", expandedPath, err)
		}

		identities = append(identities, identity)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("identity %s does not contain any usable entries", expandedPath)
	}

	return identities, nil
}
