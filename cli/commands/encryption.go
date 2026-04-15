package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

func HandleSeal(ctx context.Context, cmd *cli.Command) error {
	secretPath := cmd.String("secret")
	repoDir := cmd.String("repo")
	user := cmd.String("user")

	secretFullPath := filepath.Join(repoDir, secretPath)
	if _, err := os.Stat(secretFullPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("secret file %q not found at %s", secretPath, secretFullPath)
		}

		return fmt.Errorf("failed to access secret file %s: %w", secretFullPath, err)
	}

	identities, err := loadIdentities(cmd.String("identity"), user)
	if err != nil {
		return err
	}

	rawRecipients, err := core.ResolveRecipient(ctx, repoDir, cmd.String("recipient"), core.CacheModeReadWrite)
	if err != nil {
		return fmt.Errorf("failed to resolve recipient: %w", err)
	}

	recipients, err := parseRecipients(rawRecipients)
	if err != nil {
		return fmt.Errorf("failed to parse recipient: %w", err)
	}

	signer, err := core.LoadSignKey(repoDir, user, identities[0])
	if err != nil {
		signRecipient, err := matchIdentityRecipient(identities, recipients)
		if err != nil {
			return fmt.Errorf("failed to find recipient matching provided identity: %w", err)
		}

		signer, err = core.GenerateSignKey(repoDir, user, signRecipient)
		if err != nil {
			return fmt.Errorf("failed to load or create signing key for %q: %w", user, err)
		}
	}

	secret := &core.Secret{
		Mgr: &core.SecretManager{
			RepoDir:    repoDir,
			Identities: identities,
			Signer:     signer,
		},
		RevealedPath: secretPath,
		Recipients:   recipients,
	}

	if _, err := secret.Seal(); err != nil {
		return err
	}

	fmt.Printf("SEAL %s\n", secretPath)
	return nil
}

func HandleReveal(_ context.Context, cmd *cli.Command) error {
	secretPath := cmd.String("secret")
	repoDir := cmd.String("repo")
	user := cmd.String("user")

	identities, err := loadIdentities(cmd.String("identity"), user)
	if err != nil {
		return err
	}

	signer, err := core.LoadSignKey(repoDir, user, identities[0])
	if err != nil {
		return fmt.Errorf("failed to load signing key for %q: %w", user, err)
	}

	secret := &core.Secret{
		Mgr: &core.SecretManager{
			RepoDir:    repoDir,
			Identities: identities,
			Signer:     signer,
		},
		RevealedPath: secretPath,
	}

	if err := secret.Reveal(); err != nil {
		return err
	}

	fmt.Printf("REVEAL %s\n", secretPath)
	return nil
}

func loadIdentities(identityPath, user string) (core.Identities, error) {
	expandedPath, err := expandHomeDir(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity path: %w", err)
	}

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity %s: %w", expandedPath, err)
	}

	var identities core.Identities
	for line := range strings.SplitSeq(string(data), "\n") {
		key := strings.TrimSpace(line)
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}

		identity, err := core.ParseIdentity(key, &core.KeyringPassphraseProvider{
			KeyFingerprint: "sesam.id." + user,
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

func parseRecipients(rawRecipients string) (core.Recipients, error) {
	var recipients core.Recipients
	for line := range strings.SplitSeq(rawRecipients, "\n") {
		key := strings.TrimSpace(line)
		if key == "" {
			continue
		}

		recipient, err := core.ParseRecipient(key)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, recipient)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipient key found")
	}

	return recipients, nil
}

func matchIdentityRecipient(identities core.Identities, recipients core.Recipients) (*core.Recipient, error) {
	const probeText = "sesam-signkey-probe"

	for _, recipient := range recipients {
		buf := &bytes.Buffer{}

		w, err := age.Encrypt(buf, recipient)
		if err != nil {
			return nil, err
		}

		if _, err := w.Write([]byte(probeText)); err != nil {
			return nil, err
		}

		if err := w.Close(); err != nil {
			return nil, err
		}

		for _, identity := range identities {
			r, err := age.Decrypt(bytes.NewReader(buf.Bytes()), identity)
			if err != nil {
				continue
			}

			decrypted, err := io.ReadAll(r)
			if err != nil {
				continue
			}

			if string(decrypted) == probeText {
				return recipient, nil
			}
		}
	}

	return nil, fmt.Errorf("no recipient matches provided identity")
}

func expandHomeDir(path string) (string, error) {
	switch {
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return homeDir, nil
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return filepath.Join(homeDir, strings.TrimPrefix(path, "~/")), nil
	default:
		return path, nil
	}
}
