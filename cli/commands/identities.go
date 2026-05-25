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

// loadIdentities reads all given paths and parses all identities.
func loadIdentities(identityPaths []string, keyFingerprint string) (core.Identities, error) {
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

		identity, err := core.ParseIdentity(strings.TrimSpace(string(data)), &core.KeyringPassphraseProvider{
			KeyFingerprint: keyFingerprint,
			Fallback:       &core.StdinPassphraseProvider{},
		})
		if err != nil {
			return nil, err
		}

		identities = append(identities, identity)
	}

	return identities, nil
}
