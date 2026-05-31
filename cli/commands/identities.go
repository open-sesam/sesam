package commands

import (
	"fmt"
	"strings"

	"github.com/open-sesam/sesam/core"
)

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
// prompt when no entry exists.
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
func loadIdentitiesKeyringOnly(identityPaths []string, keyFingerprint string, pluginUI *core.PluginUI) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, &core.KeyringPassphraseProvider{
		KeyFingerprint: keyFingerprint,
	}, pluginUI)
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
